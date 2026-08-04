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
    'OcfSecurePortDiscoveryResult',
    'discover_ocf_secure_ports',
]

_DISCOVERY_PORT = 5683
_MAX_ENDPOINTS = 8
_MAX_PORTS = 8
_MAX_BLOCKS = 32
_MAX_DATAGRAM_BYTES = 8192
_MAX_PAYLOAD_BYTES = 65536
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
