"""Bounded discovery of OCF-advertised secure UDP ports.

Samsung appliances normally receive public CoAP discovery on UDP 5683, but
some firmware sends the response from a different source port. This module
therefore uses unconnected UDP sockets, validates the resolved target address
and CoAP token, then pins the first valid response endpoint for the remainder
of a bounded Block2 transfer.

Only NON ``GET /oic/res?rt=oic.r.doxm`` is sent. Retries keep the token and
use a fresh message ID. No ownership, credential, or other OCF security
resource is written.
"""

from __future__ import annotations

import io
import math
import secrets
import selectors
import socket
import time
import uuid
from dataclasses import dataclass
from urllib.parse import urlsplit

import cbor2

from ..errors import MalformedMessageError
from .coap import (
    ACCEPT,
    BLOCK2,
    CF_CBOR,
    CONTENT_FORMAT,
    METHOD_GET,
    SIZE2,
    TYPE_ACK,
    TYPE_CON,
    TYPE_NON,
    TYPE_RST,
    URI_PATH,
    URI_QUERY,
    block_value,
    build_coap,
    parse_coap,
)
from .endpoint import ResolvedUdpEndpoint, resolve_udp_endpoints

__all__ = [
    'OcfMulticastSecurePortDiscoveryResult',
    'OcfSecurePortDiscoveryResult',
    'discover_ocf_secure_ports',
    'discover_ocf_secure_ports_multicast',
]

_DISCOVERY_PORT = 5683
_IPV4_OCF_MULTICAST_GROUP = socket.inet_ntoa(bytes((224, 0, 1, 187)))
_MULTICAST_ROUNDS = 2
_MAX_MULTICAST_RESPONSES_PER_ROUND = 64
_MAX_ENDPOINTS = 8
_MAX_PORTS = 8
_MAX_BLOCKS = 32
_MAX_DATAGRAM_BYTES = 8192
_MAX_PAYLOAD_BYTES = 65536
_MAX_CONTAINERS = 64
_MAX_LINKS = 256
_MAX_ENDPOINT_URIS_PER_LINK = 32
_OCF_CBOR_CONTENT_FORMAT = 10000
_ETAG = 4
_CONTENT = 0x45
_UNSET = object()


@dataclass(frozen=True, slots=True, repr=False)
class OcfSecurePortDiscoveryResult:
    """Redacted outcome of one public OCF resource-directory lookup.

    ``attempts`` counts logical request attempts rather than destination
    addresses. The custom representation deliberately omits the discovered
    ports, target address, and wire data.
    """

    ports: tuple[int, ...]
    attempts: int
    response_received: bool
    error_code: str | None = None

    @property
    def found(self):
        """Return whether at least one validated secure port was advertised."""
        return bool(self.ports)

    def __repr__(self):
        return (
            'OcfSecurePortDiscoveryResult('
            f'found={self.found!r}, port_count={len(self.ports)}, '
            f'attempts={self.attempts}, '
            f'response_received={self.response_received!r}, '
            f'error_code={self.error_code!r})'
        )


@dataclass(frozen=True, slots=True, repr=False)
class OcfMulticastSecurePortDiscoveryResult:
    """Redacted result of identity-aware IPv4 multicast discovery.

    ``address`` and ``ports`` are available for the caller's next bounded
    probe, but the custom representation omits both. The target UUID is used
    only during discovery and is not retained in the result.
    """

    address: str | None
    ports: tuple[int, ...]
    rounds: int
    responses: int
    error_code: str | None = None

    @property
    def found(self):
        """Return whether one stable target advertisement was found."""
        return self.address is not None and bool(self.ports)

    def __repr__(self):
        return (
            'OcfMulticastSecurePortDiscoveryResult('
            f'found={self.found!r}, port_count={len(self.ports)}, '
            f'rounds={self.rounds}, responses={self.responses}, '
            f'error_code={self.error_code!r})'
        )


@dataclass(slots=True, repr=False)
class _Route:
    sock: socket.socket
    endpoint: ResolvedUdpEndpoint
    host_key: tuple[bytes, int]


@dataclass(frozen=True, slots=True, repr=False)
class _ResponseBlock:
    number: int
    more: bool
    szx: int | None
    payload: bytes
    etag: bytes | None
    content_format: int | None
    size2: int | None


def _validate_options(discovery_port, timeout, retries, family):
    if isinstance(discovery_port, bool) or not isinstance(discovery_port, int):
        raise TypeError('discovery_port must be an integer')
    if not 1 <= discovery_port <= 65535:
        raise ValueError('discovery_port must be between 1 and 65535')
    if isinstance(timeout, bool) or not isinstance(timeout, (int, float)):
        raise TypeError('timeout must be a number')
    if not math.isfinite(timeout) or not 0 < timeout <= 30:
        raise ValueError('timeout must be greater than zero and at most 30')
    if isinstance(retries, bool) or not isinstance(retries, int):
        raise TypeError('retries must be an integer')
    if not 0 <= retries <= 4:
        raise ValueError('retries must be between zero and four')
    if isinstance(family, bool) or not isinstance(family, int):
        raise TypeError('family must be an address-family integer')
    if family not in (socket.AF_UNSPEC, socket.AF_INET, socket.AF_INET6):
        raise ValueError('family must be AF_UNSPEC, AF_INET, or AF_INET6')


def _host_key(family, sockaddr):
    """Return canonical address bytes plus an IPv6 scope ID."""
    expected_length = 2 if family == socket.AF_INET else 4
    if not isinstance(sockaddr, tuple) or len(sockaddr) != expected_length:
        return None
    host = sockaddr[0]
    if not isinstance(host, str):
        return None
    if family == socket.AF_INET6:
        host = host.split('%', 1)[0]
    try:
        packed = socket.inet_pton(family, host)
    except OSError:
        return None
    scope_id = sockaddr[3] if family == socket.AF_INET6 else 0
    if isinstance(scope_id, bool) or not isinstance(scope_id, int):
        return None
    return packed, scope_id


def _peer_key(family, sockaddr):
    host_key = _host_key(family, sockaddr)
    if host_key is None:
        return None
    port = sockaddr[1]
    if isinstance(port, bool) or not isinstance(port, int):
        return None
    if not 1 <= port <= 65535:
        return None
    return family, host_key[0], port, host_key[1]


def _open_routes(endpoints, selector):
    routes = []
    for endpoint in endpoints[:_MAX_ENDPOINTS]:
        key = _host_key(endpoint.family, endpoint.sockaddr)
        if key is None:
            continue
        sock = None
        try:
            sock = socket.socket(
                endpoint.family, socket.SOCK_DGRAM, socket.IPPROTO_UDP)
            sock.bind(endpoint.bind_address(0))
            sock.setblocking(False)
            route = _Route(sock, endpoint, key)
            selector.register(sock, selectors.EVENT_READ, route)
            routes.append(route)
        except (OSError, ValueError):
            if sock is not None:
                try:
                    sock.close()
                except OSError:
                    pass
    return routes


def _option_values(options, number):
    return [value for option_number, value in options
            if option_number == number]


def _decode_uint_option(values, *, max_length):
    if len(values) > 1:
        return _UNSET
    if not values:
        return None
    value = values[0]
    if len(value) > max_length:
        return _UNSET
    return int.from_bytes(value, 'big')


def _decode_response_block(
        datagram, *, token, expected_number, expected_szx):
    """Classify one correlated CoAP response without retaining wire data."""
    try:
        mtype, code, mid, response_token, options, payload = \
            parse_coap(datagram)
    except MalformedMessageError:
        return 'malformed', None, None

    if mtype == TYPE_RST:
        return 'ignore', None, None

    if mtype == TYPE_ACK:
        return 'ignore', None, None

    if response_token != token or code != _CONTENT:
        return 'ignore', None, None
    if mtype not in (TYPE_CON, TYPE_NON):
        return 'ignore', None, None

    ack_mid = mid if mtype == TYPE_CON else None
    block_values = _option_values(options, BLOCK2)
    if len(block_values) > 1:
        return 'malformed', None, ack_mid

    if block_values:
        encoded = block_values[0]
        if len(encoded) > 3:
            return 'malformed', None, ack_mid
        value = int.from_bytes(encoded, 'big')
        number = value >> 4
        more = bool((value >> 3) & 1)
        szx = value & 0x07
        if szx > 6:
            return 'malformed', None, ack_mid
    else:
        number = 0
        more = False
        szx = None

    if number < expected_number:
        return 'duplicate', None, ack_mid
    if number != expected_number:
        return 'malformed', None, ack_mid
    if expected_number > 0 and szx is None:
        return 'malformed', None, ack_mid
    if expected_szx is not None and szx != expected_szx:
        return 'malformed', None, ack_mid
    if szx is not None:
        block_size = 1 << (szx + 4)
        if len(payload) > block_size or (more and len(payload) != block_size):
            return 'malformed', None, ack_mid

    etag_values = _option_values(options, _ETAG)
    if len(etag_values) > 1:
        return 'malformed', None, ack_mid
    etag = etag_values[0] if etag_values else None
    if etag is not None and not 1 <= len(etag) <= 8:
        return 'malformed', None, ack_mid

    content_format = _decode_uint_option(
        _option_values(options, CONTENT_FORMAT), max_length=2)
    if content_format is _UNSET or content_format not in (
            None, int.from_bytes(CF_CBOR, 'big'),
            _OCF_CBOR_CONTENT_FORMAT):
        return 'malformed', None, ack_mid

    size2 = _decode_uint_option(
        _option_values(options, SIZE2), max_length=4)
    if size2 is _UNSET or (
            size2 is not None and size2 > _MAX_PAYLOAD_BYTES):
        return 'malformed', None, ack_mid

    return 'block', _ResponseBlock(
        number=number,
        more=more,
        szx=szx,
        payload=payload,
        etag=etag,
        content_format=content_format,
        size2=size2,
    ), ack_mid


def _decode_cbor(payload):
    stream = io.BytesIO(payload)
    try:
        value = cbor2.CBORDecoder(stream).decode()
    except Exception:  # noqa: BLE001 - untrusted CBOR must fail closed
        return _UNSET
    if stream.tell() != len(payload):
        return _UNSET
    return value


def _normalize_uuid(value):
    """Return one canonical UUID value without rendering it."""
    try:
        if isinstance(value, uuid.UUID):
            return value
        if isinstance(value, bytes):
            if len(value) == 16:
                return uuid.UUID(bytes=value)
            value = value.decode('ascii')
        if not isinstance(value, str):
            return None
        folded = value.casefold()
        for prefix in ('urn:uuid:', 'uuid:'):
            if folded.startswith(prefix):
                value = value[len(prefix):]
                break
        return uuid.UUID(value)
    except (UnicodeDecodeError, ValueError, AttributeError):
        return None


def _resource_links(value):
    """Return a shallow, bounded OCF link sequence or ``None``."""
    containers = value if isinstance(value, list) else [value]
    if not all(isinstance(container, dict) for container in containers):
        return None

    links = []
    for container in containers:
        if 'links' in container:
            nested = container.get('links')
            if not isinstance(nested, list):
                return None
            candidates = nested
        elif 'href' in container:
            candidates = [container]
        else:
            candidates = []
        for link in candidates:
            if not isinstance(link, dict):
                return None
            links.append(link)
            if len(links) > _MAX_LINKS:
                return None
    return links


def _endpoint_uri_port(value):
    if not isinstance(value, str):
        return None
    try:
        parsed = urlsplit(value)
        port = parsed.port
    except ValueError:
        return None
    if (parsed.scheme != 'coaps' or not parsed.hostname
            or parsed.username is not None or parsed.password is not None
            or parsed.path or parsed.query or parsed.fragment):
        return None
    return 5684 if port is None else port


def _endpoint_uri_port_for_ipv4_source(value, source_key):
    """Return a secure URI port only when its host is the response source."""
    if not isinstance(value, str):
        return None
    try:
        parsed = urlsplit(value)
        port = parsed.port
        endpoint_key = socket.inet_pton(socket.AF_INET, parsed.hostname or '')
    except (OSError, ValueError):
        return None
    if (parsed.scheme != 'coaps'
            or endpoint_key != source_key
            or parsed.username is not None or parsed.password is not None
            or parsed.path or parsed.query or parsed.fragment):
        return None
    return 5684 if port is None else port


def _target_secure_ports_from_payload(payload, target_uuid, source_key):
    """Classify one bounded directory payload for an exact target UUID.

    The status is ``target`` (with zero or more ports), ``absent``, or
    ``malformed``. Only links nested inside the matching top-level container
    are considered. Legacy policy ports are implicitly bound to ``source_key``;
    modern endpoint URIs must explicitly name that same IPv4 address.
    """
    value = _decode_cbor(payload)
    if value is _UNSET:
        return 'malformed', ()
    containers = value if isinstance(value, list) else [value]
    if (not containers or len(containers) > _MAX_CONTAINERS
            or not all(isinstance(container, dict)
                       for container in containers)):
        return 'malformed', ()

    matches = [
        container for container in containers
        if _normalize_uuid(container.get('di')) == target_uuid
    ]
    if not matches:
        return 'absent', ()
    if len(matches) != 1:
        return 'malformed', ()

    links = matches[0].get('links')
    if (not isinstance(links, list) or len(links) > _MAX_LINKS
            or not all(isinstance(link, dict) for link in links)):
        return 'malformed', ()

    ports = []
    seen = set()

    def add_port(port):
        if (isinstance(port, bool) or not isinstance(port, int)
                or not 1 <= port <= 65535 or port in seen):
            return
        seen.add(port)
        ports.append(port)

    for link in links:
        if link.get('href') != '/oic/sec/doxm':
            continue
        resource_types = link.get('rt')
        if isinstance(resource_types, str):
            resource_types = [resource_types]
        if (not isinstance(resource_types, list)
                or 'oic.r.doxm' not in resource_types):
            continue

        policy = link.get('p')
        if isinstance(policy, dict) and policy.get('sec') is True:
            # A legacy policy has no host. Returning it with the datagram's
            # source address is the binding; it is never associated with a
            # different responder or a root-unicast identity.
            add_port(policy.get('port'))

        endpoints = link.get('eps')
        if isinstance(endpoints, list):
            for endpoint in endpoints[:_MAX_ENDPOINT_URIS_PER_LINK]:
                if not isinstance(endpoint, dict):
                    continue
                add_port(_endpoint_uri_port_for_ipv4_source(
                    endpoint.get('ep'), source_key))

        if len(ports) >= _MAX_PORTS:
            break
    return 'target', tuple(sorted(ports[:_MAX_PORTS]))


def _secure_ports_from_payload(payload):
    value = _decode_cbor(payload)
    if value is _UNSET:
        return None
    links = _resource_links(value)
    if links is None:
        return None

    ports = []
    seen = set()

    def add_port(port):
        if (isinstance(port, bool) or not isinstance(port, int)
                or not 1 <= port <= 65535 or port in seen):
            return
        seen.add(port)
        ports.append(port)

    for link in links:
        if link.get('href') != '/oic/sec/doxm':
            continue
        resource_types = link.get('rt')
        if isinstance(resource_types, str):
            resource_types = [resource_types]
        if (not isinstance(resource_types, list)
                or 'oic.r.doxm' not in resource_types):
            continue

        policy = link.get('p')
        if isinstance(policy, dict) and policy.get('sec') is True:
            add_port(policy.get('port'))

        endpoints = link.get('eps')
        if isinstance(endpoints, list):
            for endpoint in endpoints[:_MAX_ENDPOINT_URIS_PER_LINK]:
                if not isinstance(endpoint, dict):
                    continue
                add_port(_endpoint_uri_port(endpoint.get('ep')))

        if len(ports) >= _MAX_PORTS:
            break
    return tuple(ports[:_MAX_PORTS])


def _build_request(token, mid, expected_number, szx):
    options = [
        (URI_PATH, b'oic'),
        (URI_PATH, b'res'),
        (URI_QUERY, b'rt=oic.r.doxm'),
        (ACCEPT, CF_CBOR),
    ]
    if expected_number > 0:
        options.append((BLOCK2, block_value(expected_number, 0, szx)))
    return build_coap(TYPE_NON, METHOD_GET, mid, token, options)


def _validate_multicast_options(
        target_uuid, interface_address, discovery_port, round_timeout):
    if not isinstance(target_uuid, (str, bytes, uuid.UUID)):
        raise TypeError('target_uuid must be a UUID string or bytes value')
    normalized_uuid = _normalize_uuid(target_uuid)
    if normalized_uuid is None:
        raise ValueError('target_uuid must be a valid UUID')
    if not isinstance(interface_address, str):
        raise TypeError('interface_address must be an IPv4 string')
    try:
        interface_key = socket.inet_pton(socket.AF_INET, interface_address)
    except OSError as exc:
        raise ValueError(
            'interface_address must be a valid IPv4 address') from exc
    if (interface_key == b'\x00\x00\x00\x00'
            or interface_key == b'\xff\xff\xff\xff'
            or 224 <= interface_key[0] <= 239):
        raise ValueError('interface_address must be a unicast IPv4 address')
    _validate_options(
        discovery_port, round_timeout, 0, socket.AF_INET)
    return normalized_uuid, socket.inet_ntop(socket.AF_INET, interface_key), \
        interface_key


def _decode_multicast_response(datagram, token):
    """Return one token-correlated, single-block NON response payload."""
    try:
        mtype, code, _mid, response_token, _options, _payload = \
            parse_coap(datagram)
    except MalformedMessageError:
        return 'malformed', None
    if response_token != token or code != _CONTENT or mtype != TYPE_NON:
        return 'ignore', None

    status, block, _ack_mid = _decode_response_block(
        datagram,
        token=token,
        expected_number=0,
        expected_szx=None,
    )
    if status != 'block':
        return status, None
    if (block.more or block.number != 0
            or (block.size2 is not None
                and block.size2 != len(block.payload))):
        return 'malformed', None
    return 'payload', block.payload


def _multicast_result(
        address, ports, rounds, responses, error_code=None):
    return OcfMulticastSecurePortDiscoveryResult(
        address=address,
        ports=ports,
        rounds=rounds,
        responses=responses,
        error_code=error_code,
    )


def discover_ocf_secure_ports_multicast(
        target_uuid, *, interface_address, discovery_port=_DISCOVERY_PORT,
        round_timeout=6.0):
    """Find one exact OCF device identity on one IPv4 LAN interface.

    This is an explicit entry point and never invokes the known-host unicast
    discovery function.

    Exactly two NON multicast discovery rounds are sent. A successful result
    requires the same sole response source and the same non-empty secure-port
    set in both rounds. Only the matching top-level ``di`` container is read;
    legacy policy ports are bound to its response source, and ``eps`` hosts
    must equal that source. No OCF security resource is read or written.
    """
    normalized_uuid, interface_address, interface_key = \
        _validate_multicast_options(
            target_uuid, interface_address, discovery_port, round_timeout)

    selector = selectors.DefaultSelector()
    sock = None
    try:
        sock = socket.socket(
            socket.AF_INET, socket.SOCK_DGRAM, socket.IPPROTO_UDP)
        sock.setsockopt(
            socket.IPPROTO_IP, socket.IP_MULTICAST_IF, interface_key)
        sock.setsockopt(socket.IPPROTO_IP, socket.IP_MULTICAST_TTL, 1)
        sock.setsockopt(socket.IPPROTO_IP, socket.IP_MULTICAST_LOOP, 0)
        sock.bind((interface_address, 0))
        sock.setblocking(False)
        selector.register(sock, selectors.EVENT_READ)
    except (OSError, ValueError):
        if sock is not None:
            try:
                sock.close()
            except OSError:
                pass
        selector.close()
        return _multicast_result(
            None, (), 0, 0, 'interface_unavailable')

    used_tokens = set()
    used_mids = set()
    round_matches = []
    inconsistent_sources = set()
    rounds = 0
    responses = 0
    target_seen = False
    target_with_ports = False
    valid_directory_response = False
    saw_malformed = False

    try:
        for _round_number in range(_MULTICAST_ROUNDS):
            token = secrets.token_bytes(8)
            while token in used_tokens:
                token = (
                    (int.from_bytes(token, 'big') + 1) & ((1 << 64) - 1)
                ).to_bytes(8, 'big')
            used_tokens.add(token)
            mid = secrets.randbits(16)
            while mid in used_mids:
                mid = (mid + 1) & 0xFFFF
            used_mids.add(mid)
            request = _build_request(token, mid, 0, None)
            try:
                sent_length = sock.sendto(
                    request,
                    (_IPV4_OCF_MULTICAST_GROUP, discovery_port),
                )
            except OSError:
                break
            if sent_length != len(request):
                break
            rounds += 1

            matches = {}
            deadline = time.monotonic() + float(round_timeout)
            datagrams = 0
            while datagrams < _MAX_MULTICAST_RESPONSES_PER_ROUND:
                remaining = deadline - time.monotonic()
                if remaining <= 0:
                    break
                try:
                    events = selector.select(remaining)
                except (OSError, ValueError):
                    events = []
                if not events:
                    break
                try:
                    datagram, source = sock.recvfrom(
                        _MAX_DATAGRAM_BYTES + 1)
                except (BlockingIOError, OSError):
                    continue
                datagrams += 1
                source_host_key = _host_key(socket.AF_INET, source)
                if (_peer_key(socket.AF_INET, source) is None
                        or source_host_key is None
                        or source_host_key[0] == b'\x00\x00\x00\x00'
                        or source_host_key[0] == b'\xff\xff\xff\xff'
                        or 224 <= source_host_key[0][0] <= 239):
                    continue
                if len(datagram) > _MAX_DATAGRAM_BYTES:
                    saw_malformed = True
                    continue

                status, payload = _decode_multicast_response(
                    datagram, token)
                if status == 'ignore':
                    continue
                if status != 'payload':
                    saw_malformed = True
                    continue
                responses += 1
                target_status, ports = _target_secure_ports_from_payload(
                    payload, normalized_uuid, source_host_key[0])
                if target_status == 'malformed':
                    saw_malformed = True
                    continue
                valid_directory_response = True
                if target_status == 'absent':
                    continue

                target_seen = True
                target_with_ports = target_with_ports or bool(ports)
                source_key = source_host_key[0]
                address = socket.inet_ntop(socket.AF_INET, source_key)
                previous = matches.get(source_key)
                candidate = (address, ports)
                if previous is not None and previous != candidate:
                    inconsistent_sources.add(source_key)
                    continue
                matches[source_key] = candidate
            round_matches.append(matches)

        if rounds != _MULTICAST_ROUNDS:
            return _multicast_result(
                None, (), rounds, responses, 'interface_unavailable')

        sources = set().union(*(set(matches) for matches in round_matches))
        if inconsistent_sources or len(sources) > 1:
            return _multicast_result(
                None, (), rounds, responses, 'ambiguous_target')
        if len(sources) == 1 and all(len(matches) == 1
                                     for matches in round_matches):
            source_key = next(iter(sources))
            first = round_matches[0][source_key]
            second = round_matches[1][source_key]
            if first == second and first[1]:
                return _multicast_result(
                    first[0], first[1], rounds, responses)

        if not target_seen:
            if not responses:
                error_code = 'no_ocf_response'
            elif valid_directory_response:
                error_code = 'target_not_found'
            elif saw_malformed:
                error_code = 'malformed_ocf_response'
            else:
                error_code = 'target_not_found'
        elif not target_with_ports:
            error_code = 'no_secure_ports'
        else:
            error_code = 'target_not_stable'
        return _multicast_result(
            None, (), rounds, responses, error_code)
    finally:
        try:
            selector.unregister(sock)
        except (KeyError, OSError, ValueError):
            pass
        try:
            sock.close()
        except OSError:
            pass
        selector.close()


def _result(ports, attempts, response_received, error_code=None):
    return OcfSecurePortDiscoveryResult(
        ports=ports,
        attempts=attempts,
        response_received=response_received,
        error_code=error_code,
    )


def discover_ocf_secure_ports(
        host, *, discovery_port=_DISCOVERY_PORT, timeout=3.0, retries=1,
        family=socket.AF_UNSPEC):
    """Discover secure ports advertised by a target's public OCF directory.

    This is an explicit known-host entry point and never starts multicast as
    an automatic fallback.

    Name resolution happens synchronously first. ``timeout`` then bounds all
    socket I/O, including a token-stable Block2 transfer. A port advertisement
    is only a candidate; callers should prove it with
    :func:`smartthings_local.protocol.dtls_probe.probe_dtls_ports` before a
    DTLS handshake.
    """
    _validate_options(discovery_port, timeout, retries, family)
    try:
        endpoints = resolve_udp_endpoints(
            host, discovery_port, family=family)
    except OSError:
        return _result((), 0, False, 'endpoint_unavailable')

    selector = selectors.DefaultSelector()
    routes = _open_routes(endpoints, selector)
    if not routes:
        selector.close()
        return _result((), 0, False, 'endpoint_unavailable')

    token = secrets.token_bytes(8)
    started = time.monotonic()
    deadline = started + float(timeout)
    wait_slice = min(1.0, float(timeout) / (retries + 1))
    attempts = 0
    response_received = False
    saw_malformed = False
    pinned_route = None
    pinned_peer = None
    pinned_destination = None
    payload = bytearray()
    expected_number = 0
    expected_szx = None
    expected_etag = _UNSET
    expected_content_format = _UNSET
    expected_size2 = None
    used_mids = set()

    try:
        while expected_number < _MAX_BLOCKS:
            block = None
            sent_for_block = False
            for block_attempt in range(retries + 1):
                if time.monotonic() >= deadline:
                    break
                mid = secrets.randbits(16)
                while mid in used_mids:
                    mid = (mid + 1) & 0xFFFF
                used_mids.add(mid)
                request = _build_request(
                    token, mid, expected_number, expected_szx)
                send_routes = [pinned_route] if pinned_route else routes
                sent = False
                for route in send_routes:
                    try:
                        destination = (
                            pinned_destination
                            if route is pinned_route and pinned_destination
                            else route.endpoint.sockaddr
                        )
                        sent_length = route.sock.sendto(
                            request, destination)
                        sent = sent or sent_length == len(request)
                    except OSError:
                        continue
                attempts += 1
                if not sent:
                    continue
                sent_for_block = True

                now = time.monotonic()
                attempt_deadline = (
                    deadline if block_attempt == retries
                    else min(deadline, now + wait_slice)
                )
                while True:
                    remaining = attempt_deadline - time.monotonic()
                    if remaining <= 0:
                        break
                    try:
                        events = selector.select(remaining)
                    except (OSError, ValueError):
                        events = []
                    if not events:
                        break
                    for key, _mask in events:
                        route = key.data
                        try:
                            datagram, source = route.sock.recvfrom(
                                _MAX_DATAGRAM_BYTES + 1)
                        except (BlockingIOError, OSError):
                            continue
                        source_host_key = _host_key(
                            route.endpoint.family, source)
                        peer_key = _peer_key(route.endpoint.family, source)
                        if (source_host_key != route.host_key
                                or peer_key is None):
                            continue
                        if pinned_peer is not None and (
                                route is not pinned_route
                                or peer_key != pinned_peer):
                            continue
                        if len(datagram) > _MAX_DATAGRAM_BYTES:
                            saw_malformed = True
                            continue

                        status, candidate, ack_mid = _decode_response_block(
                            datagram,
                            token=token,
                            expected_number=expected_number,
                            expected_szx=expected_szx,
                        )
                        if ack_mid is not None:
                            ack = build_coap(
                                TYPE_ACK, 0, ack_mid, b'', [])
                            try:
                                route.sock.sendto(ack, source)
                            except OSError:
                                pass
                        if status in ('ignore', 'duplicate'):
                            continue
                        if status == 'malformed':
                            saw_malformed = True
                            continue

                        response_received = True
                        if pinned_peer is None:
                            pinned_route = route
                            pinned_peer = peer_key
                            pinned_destination = tuple(source)
                        block = candidate
                        break
                    if block is not None:
                        break
                if block is not None:
                    break

            if block is None:
                if not sent_for_block:
                    error_code = 'endpoint_unavailable'
                elif saw_malformed:
                    error_code = 'malformed_ocf_response'
                else:
                    error_code = 'no_ocf_response'
                return _result(
                    (), attempts, response_received, error_code)

            if expected_number == 0:
                expected_szx = block.szx
                expected_etag = block.etag
                expected_content_format = block.content_format
                expected_size2 = block.size2
            else:
                if (block.etag != expected_etag
                        or block.content_format != expected_content_format):
                    return _result(
                        (), attempts, True, 'malformed_ocf_response')
                if block.size2 is not None:
                    if (expected_size2 is not None
                            and block.size2 != expected_size2):
                        return _result(
                            (), attempts, True, 'malformed_ocf_response')
                    expected_size2 = block.size2

            if len(payload) + len(block.payload) > _MAX_PAYLOAD_BYTES:
                return _result(
                    (), attempts, True, 'malformed_ocf_response')
            payload.extend(block.payload)
            if not block.more:
                if (expected_size2 is not None
                        and len(payload) != expected_size2):
                    return _result(
                        (), attempts, True, 'malformed_ocf_response')
                ports = _secure_ports_from_payload(bytes(payload))
                if ports is None:
                    return _result(
                        (), attempts, True, 'malformed_ocf_response')
                if not ports:
                    return _result((), attempts, True, 'no_secure_ports')
                return _result(ports, attempts, True)

            expected_number += 1

        return _result((), attempts, response_received,
                       'malformed_ocf_response')
    finally:
        for route in routes:
            try:
                selector.unregister(route.sock)
            except (KeyError, OSError, ValueError):
                pass
            try:
                route.sock.close()
            except OSError:
                pass
        selector.close()
