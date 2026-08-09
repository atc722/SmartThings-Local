"""Public OCF secure-port discovery stays bounded and source-correlated."""

import socket
import threading
import traceback
import uuid
from dataclasses import FrozenInstanceError
from types import SimpleNamespace

import cbor2
import pytest

from smartthings_local.errors import EndpointError
from smartthings_local.protocol import ocf_discovery as discovery
from smartthings_local.protocol.coap import (
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


def _doxm_link(port=49872):
    return {
        'href': '/oic/sec/doxm',
        'rt': ['oic.r.doxm'],
        'p': {'sec': True, 'port': port},
    }


def _payload(*links, padding=''):
    value = {'links': list(links)}
    if padding:
        value['padding'] = padding
    return cbor2.dumps(value)


def _identity_payload(device_id, *links):
    return cbor2.dumps({'di': device_id, 'links': list(links)})


class _FakeMulticastSocket:
    def __init__(self, response_factory):
        self.response_factory = response_factory
        self.responses = []
        self.requests = []
        self.socket_options = []
        self.bound = None
        self.recv_count = 0
        self.closed = False

    def setsockopt(self, level, option, value):
        self.socket_options.append((level, option, value))

    def bind(self, address):
        self.bound = address

    def setblocking(self, _blocking):
        pass

    def sendto(self, request, destination):
        self.requests.append((request, destination))
        self.responses.extend(
            self.response_factory(request, len(self.requests)))
        return len(request)

    def recvfrom(self, _size):
        if not self.responses:
            raise BlockingIOError
        self.recv_count += 1
        return self.responses.pop(0)

    def close(self):
        self.closed = True


class _FakeSelector:
    def __init__(self):
        self.sock = None

    def register(self, sock, _events):
        self.sock = sock

    def unregister(self, sock):
        assert sock is self.sock

    def select(self, _timeout):
        if self.sock.responses:
            return [(SimpleNamespace(data=None), 1)]
        return []

    def close(self):
        pass


def _option_map(options):
    result = {}
    for number, value in options:
        result.setdefault(number, []).append(value)
    return result


def _uint_bytes(value):
    length = max(1, (value.bit_length() + 7) // 8)
    return value.to_bytes(length, 'big')


def test_extracts_only_valid_legacy_and_modern_secure_doxm_ports():
    links = [
        _doxm_link(),
        {
            'href': '/oic/sec/doxm',
            'rt': 'oic.r.doxm',
            'p': {'sec': True, 'port': 49872},
            'eps': [
                {'ep': 'coaps://192.0.2.20:49873'},
                {'ep': 'coaps://[2001:db8::20]'},
                {'ep': 'coap://192.0.2.20:49874'},
                {'ep': 'coaps+tcp://192.0.2.20:49875'},
                {'ep': 'coaps://user:secret@192.0.2.20:49876'},
                {'ep': 'coaps://192.0.2.20:49877/path'},
            ],
        },
        {
            'href': '/oic/sec/doxm',
            'rt': ['oic.r.doxm'],
            'p': {'sec': False, 'port': 49901},
        },
        {
            'href': '/oic/sec/pstat',
            'rt': ['oic.r.pstat'],
            'p': {'sec': True, 'port': 49902},
        },
        _doxm_link(True),
        _doxm_link('49878'),
        _doxm_link(0),
        _doxm_link(65536),
    ]

    assert discovery._secure_ports_from_payload(_payload(*links)) == (
        49872, 49873, 5684)


def test_direct_link_array_is_supported_and_port_count_is_bounded():
    links = [_doxm_link(port) for port in range(49870, 49880)]

    ports = discovery._secure_ports_from_payload(cbor2.dumps(links))

    assert ports == tuple(range(49870, 49878))


@pytest.mark.parametrize(
    'payload',
    (
        b'not-cbor',
        cbor2.dumps({'links': 'not-a-list'}),
        cbor2.dumps([{'links': [None]}]),
        cbor2.dumps({'links': []}) + cbor2.dumps(1),
    ),
)
def test_malformed_or_trailing_cbor_is_rejected(payload):
    assert discovery._secure_ports_from_payload(payload) is None


def test_valid_directory_without_secure_doxm_has_no_ports():
    value = {'links': [{'href': '/oic/d', 'rt': ['oic.wk.d']}]}

    assert discovery._secure_ports_from_payload(cbor2.dumps(value)) == ()


def test_multicast_extraction_is_identity_and_response_source_scoped():
    target = uuid.UUID('11111111-2222-3333-4444-555555555555')
    other = uuid.UUID('00000000-0000-0000-0000-000000000000')
    source = socket.inet_pton(socket.AF_INET, '192.0.2.20')
    payload = cbor2.dumps([
        {
            'di': str(other),
            'links': [_doxm_link(49901)],
        },
        {
            'di': target.bytes,
            'links': [
                _doxm_link(49872),
                {
                    'href': '/oic/sec/doxm',
                    'rt': 'oic.r.doxm',
                    'eps': [
                        {'ep': 'coaps://192.0.2.20:49873'},
                        {'ep': 'coaps://192.0.2.21:49874'},
                        {'ep': 'coap://192.0.2.20:49875'},
                    ],
                },
            ],
        },
    ])

    status, ports = discovery._target_secure_ports_from_payload(
        payload, target, source)

    assert status == 'target'
    assert ports == (49872, 49873)


def test_multicast_target_uuid_is_normalized_but_never_fuzzy_matched():
    target = uuid.UUID('11111111-2222-3333-4444-555555555555')
    source = socket.inet_pton(socket.AF_INET, '192.0.2.20')

    assert discovery._normalize_uuid(
        f'URN:UUID:{str(target).upper()}') == target
    assert discovery._normalize_uuid(target.bytes) == target
    assert discovery._target_secure_ports_from_payload(
        _identity_payload(str(target) + '0', _doxm_link()),
        target,
        source,
    ) == ('absent', ())


def test_multicast_duplicate_target_containers_fail_closed():
    target = uuid.UUID('11111111-2222-3333-4444-555555555555')
    source = socket.inet_pton(socket.AF_INET, '192.0.2.20')
    payload = cbor2.dumps([
        {'di': str(target), 'links': [_doxm_link(49872)]},
        {'di': str(target), 'links': [_doxm_link(49873)]},
    ])

    assert discovery._target_secure_ports_from_payload(
        payload, target, source) == ('malformed', ())


def test_multicast_never_treats_the_identity_container_as_a_link():
    target = uuid.UUID('11111111-2222-3333-4444-555555555555')
    source = socket.inet_pton(socket.AF_INET, '192.0.2.20')
    payload = cbor2.dumps({
        'di': str(target),
        **_doxm_link(49872),
    })

    assert discovery._target_secure_ports_from_payload(
        payload, target, source) == ('malformed', ())


def test_response_type_and_token_matrix():
    token = b'12345678'
    request_mid = 0x1234
    payload = _payload(_doxm_link())

    non_response = build_coap(
        TYPE_NON, 0x45, 0x7000, token, [], payload)
    status, block, ack_mid = discovery._decode_response_block(
        non_response,
        token=token,
        expected_number=0,
        expected_szx=None,
    )
    assert status == 'block'
    assert block.payload == payload
    assert ack_mid is None

    con_response = build_coap(
        TYPE_CON, 0x45, 0x7001, token, [], payload)
    status, _block, ack_mid = discovery._decode_response_block(
        con_response,
        token=token,
        expected_number=0,
        expected_szx=None,
    )
    assert status == 'block'
    assert ack_mid == 0x7001

    ack_response = build_coap(
        TYPE_ACK, 0x45, request_mid, token, [], payload)
    assert discovery._decode_response_block(
        ack_response,
        token=token,
        expected_number=0,
        expected_szx=None,
    )[0] == 'ignore'

    wrong_token = build_coap(
        TYPE_NON, 0x45, 0x7002, b'87654321', [], payload)
    assert discovery._decode_response_block(
        wrong_token,
        token=token,
        expected_number=0,
        expected_szx=None,
    )[0] == 'ignore'

    empty_ack = build_coap(TYPE_ACK, 0, request_mid, b'', [])
    assert discovery._decode_response_block(
        empty_ack,
        token=token,
        expected_number=0,
        expected_szx=None,
    )[0] == 'ignore'

    reset = build_coap(TYPE_RST, 0, request_mid, b'', [])
    assert discovery._decode_response_block(
        reset,
        token=token,
        expected_number=0,
        expected_szx=None,
    )[0] == 'ignore'


@pytest.mark.parametrize(
    'options,payload,expected_number,expected_szx',
    (
        ([(BLOCK2, b'\x00'), (BLOCK2, b'\x00')], b'x', 0, None),
        ([(BLOCK2, b'\x07')], b'x', 0, None),
        ([(BLOCK2, block_value(1, 0, 0))], b'x', 0, None),
        ([(BLOCK2, block_value(0, 1, 0))], b'x' * 15, 0, None),
        ([(BLOCK2, block_value(1, 0, 1))], b'x', 1, 0),
        ([(CONTENT_FORMAT, b'\x00')], b'x', 0, None),
        ([(SIZE2, _uint_bytes(65537))], b'x', 0, None),
    ),
)
def test_malformed_blockwise_metadata_is_rejected(
        options, payload, expected_number, expected_szx):
    token = b'12345678'
    response = build_coap(
        TYPE_NON, 0x45, 0x7000, token, options, payload)

    status, _block, _ack_mid = discovery._decode_response_block(
        response,
        token=token,
        expected_number=expected_number,
        expected_szx=expected_szx,
    )

    assert status == 'malformed'


def test_dynamic_source_port_and_two_block_response_are_supported():
    listener = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    responder = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    listener.bind(('127.0.0.1', 0))
    responder.bind(('127.0.0.1', 0))
    listener.settimeout(2.0)
    responder.settimeout(2.0)
    assert listener.getsockname()[1] != responder.getsockname()[1]

    body = _payload(_doxm_link(), padding='x' * 300)
    block_size = 256
    assert block_size < len(body) <= block_size * 2
    etag = b'test'
    errors = []

    def respond():
        try:
            first_request, client = listener.recvfrom(8192)
            mtype, code, first_mid, token, options, request_payload = \
                parse_coap(first_request)
            option_map = _option_map(options)
            assert mtype == TYPE_NON
            assert code == METHOD_GET
            assert len(token) == 8
            assert request_payload == b''
            assert option_map[URI_PATH] == [b'oic', b'res']
            assert option_map[URI_QUERY] == [b'rt=oic.r.doxm']
            assert option_map[ACCEPT] == [CF_CBOR]
            assert BLOCK2 not in option_map

            common = [
                (CONTENT_FORMAT, CF_CBOR),
                (discovery._ETAG, etag),
                (SIZE2, _uint_bytes(len(body))),
            ]
            first_response = build_coap(
                TYPE_CON,
                0x45,
                0x7001,
                token,
                [*common, (BLOCK2, block_value(0, 1, 4))],
                body[:block_size],
            )
            responder.sendto(first_response, client)
            first_ack, ack_peer = responder.recvfrom(8192)
            ack_type, ack_code, ack_mid, ack_token, ack_options, ack_body = \
                parse_coap(first_ack)
            assert ack_peer == client
            assert (ack_type, ack_code, ack_mid) == (TYPE_ACK, 0, 0x7001)
            assert ack_token == b'' and ack_options == [] and ack_body == b''

            second_request, second_client = responder.recvfrom(8192)
            mtype, code, second_mid, second_token, options, request_payload = \
                parse_coap(second_request)
            option_map = _option_map(options)
            assert second_client == client
            assert (mtype, code) == (TYPE_NON, METHOD_GET)
            assert second_token == token
            assert second_mid != first_mid
            assert request_payload == b''
            assert option_map[BLOCK2] == [block_value(1, 0, 4)]

            second_response = build_coap(
                TYPE_CON,
                0x45,
                0x7002,
                token,
                [*common, (BLOCK2, block_value(1, 0, 4))],
                body[block_size:],
            )
            responder.sendto(second_response, client)
            second_ack, _ack_peer = responder.recvfrom(8192)
            assert parse_coap(second_ack)[:4] == (
                TYPE_ACK, 0, 0x7002, b'')
        except Exception as exc:  # pragma: no cover - asserted below
            errors.append(exc)

    thread = threading.Thread(target=respond)
    thread.start()
    try:
        result = discovery.discover_ocf_secure_ports(
            '127.0.0.1',
            discovery_port=listener.getsockname()[1],
            timeout=1.5,
            retries=1,
            family=socket.AF_INET,
        )
    finally:
        thread.join(timeout=3.0)
        listener.close()
        responder.close()

    assert not thread.is_alive()
    assert errors == []
    assert result.ports == (49872,)
    assert result.response_received
    assert result.error_code is None
    assert result.attempts == 2


def test_block_transfer_pins_first_valid_response_source_port():
    listener = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    first_responder = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    other_responder = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    listener.bind(('127.0.0.1', 0))
    first_responder.bind(('127.0.0.1', 0))
    other_responder.bind(('127.0.0.1', 0))
    listener.settimeout(1.0)
    first_responder.settimeout(1.0)
    body = _payload(_doxm_link(), padding='x' * 10)
    assert 64 < len(body) <= 128
    errors = []

    def respond():
        try:
            request, client = listener.recvfrom(8192)
            _mtype, _code, _mid, token, _options, _body = \
                parse_coap(request)
            first_responder.sendto(
                build_coap(
                    TYPE_NON, 0x45, 0x7101, token,
                    [(BLOCK2, block_value(0, 1, 2))], body[:64]),
                client,
            )
            request, second_client = first_responder.recvfrom(8192)
            assert second_client == client
            other_responder.sendto(
                build_coap(
                    TYPE_NON, 0x45, 0x7102, token,
                    [(BLOCK2, block_value(1, 0, 2))], body[64:]),
                client,
            )
        except Exception as exc:  # pragma: no cover - asserted below
            errors.append(exc)

    thread = threading.Thread(target=respond)
    thread.start()
    try:
        result = discovery.discover_ocf_secure_ports(
            '127.0.0.1',
            discovery_port=listener.getsockname()[1],
            timeout=0.4,
            retries=0,
            family=socket.AF_INET,
        )
    finally:
        thread.join(timeout=2.0)
        listener.close()
        first_responder.close()
        other_responder.close()

    assert not thread.is_alive()
    assert errors == []
    assert result.ports == ()
    assert result.response_received
    assert result.error_code == 'no_ocf_response'


def test_retry_keeps_token_and_changes_message_id():
    listener = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    listener.bind(('127.0.0.1', 0))
    listener.settimeout(2.0)
    errors = []

    def respond():
        try:
            first, client = listener.recvfrom(8192)
            second, second_client = listener.recvfrom(8192)
            first_parsed = parse_coap(first)
            second_parsed = parse_coap(second)
            assert second_client == client
            assert first_parsed[0] == second_parsed[0] == TYPE_NON
            assert first_parsed[3] == second_parsed[3]
            assert first_parsed[2] != second_parsed[2]
            listener.sendto(
                build_coap(
                    TYPE_NON,
                    0x45,
                    0x7201,
                    second_parsed[3],
                    [],
                    _payload(_doxm_link()),
                ),
                client,
            )
        except Exception as exc:  # pragma: no cover - asserted below
            errors.append(exc)

    thread = threading.Thread(target=respond)
    thread.start()
    try:
        result = discovery.discover_ocf_secure_ports(
            '127.0.0.1',
            discovery_port=listener.getsockname()[1],
            timeout=0.5,
            retries=1,
            family=socket.AF_INET,
        )
    finally:
        thread.join(timeout=2.0)
        listener.close()

    assert not thread.is_alive()
    assert errors == []
    assert result.ports == (49872,)
    assert result.attempts == 2


def test_ipv4_multicast_discovery_requires_two_stable_identity_rounds(
        monkeypatch):
    target = uuid.UUID('11111111-2222-3333-4444-555555555555')
    other = uuid.UUID('00000000-0000-0000-0000-000000000000')
    target_source = ('192.0.2.20', 41000)
    other_source = ('192.0.2.21', 42000)

    def response_factory(request, round_number):
        mtype, code, mid, token, options, payload = parse_coap(request)
        option_map = _option_map(options)
        assert (mtype, code) == (TYPE_NON, METHOD_GET)
        assert payload == b''
        assert option_map[URI_PATH] == [b'oic', b'res']
        assert option_map[URI_QUERY] == [b'rt=oic.r.doxm']
        assert option_map[ACCEPT] == [CF_CBOR]
        target_payload = _identity_payload(
            str(target),
            _doxm_link(49872),
            {
                'href': '/oic/sec/doxm',
                'rt': ['oic.r.doxm'],
                'eps': [
                    {'ep': 'coaps://192.0.2.20:49873'},
                    {'ep': 'coaps://192.0.2.21:49874'},
                ],
            },
        )
        unrelated_payload = _identity_payload(
            str(other), _doxm_link(49901))
        return [
            (
                build_coap(
                    TYPE_NON, 0x45, mid + 1, b'badtoken', [],
                    target_payload),
                target_source,
            ),
            (
                build_coap(
                    TYPE_CON, 0x45, mid + 2, token, [], target_payload),
                target_source,
            ),
            (
                build_coap(
                    TYPE_NON, 0x45, mid + 3, token, [],
                    unrelated_payload),
                other_source,
            ),
            (
                build_coap(
                    TYPE_NON, 0x45, mid + 4, token, [], target_payload),
                target_source,
            ),
        ]

    fake_socket = _FakeMulticastSocket(response_factory)
    socket_calls = []

    def open_socket(*args):
        socket_calls.append(args)
        return fake_socket

    def unexpected_unicast(*_args, **_kwargs):
        pytest.fail('explicit multicast discovery invoked unicast fallback')

    monkeypatch.setattr(discovery.socket, 'socket', open_socket)
    monkeypatch.setattr(
        discovery, 'discover_ocf_secure_ports', unexpected_unicast)
    monkeypatch.setattr(
        discovery.selectors, 'DefaultSelector', _FakeSelector)

    result = discovery.discover_ocf_secure_ports_multicast(
        f'urn:uuid:{target}',
        interface_address='192.0.2.10',
        round_timeout=0.1,
    )

    assert result.address == target_source[0]
    assert result.ports == (49872, 49873)
    assert result.rounds == 2
    assert result.responses == 4
    assert result.error_code is None
    assert result.found
    assert len(socket_calls) == 1
    assert len(fake_socket.requests) == 2
    assert fake_socket.requests[0][1] == (
        discovery._IPV4_OCF_MULTICAST_GROUP, 5683)
    first = parse_coap(fake_socket.requests[0][0])
    second = parse_coap(fake_socket.requests[1][0])
    assert first[2] != second[2]
    assert first[3] != second[3]
    assert fake_socket.bound == ('192.0.2.10', 0)
    assert (
        socket.IPPROTO_IP,
        socket.IP_MULTICAST_IF,
        socket.inet_pton(socket.AF_INET, '192.0.2.10'),
    ) in fake_socket.socket_options
    assert (
        socket.IPPROTO_IP, socket.IP_MULTICAST_TTL, 1,
    ) in fake_socket.socket_options
    assert (
        socket.IPPROTO_IP, socket.IP_MULTICAST_LOOP, 0,
    ) in fake_socket.socket_options
    assert fake_socket.closed
    rendered = repr(result)
    assert target_source[0] not in rendered
    assert str(target) not in rendered
    assert '49872' not in rendered


def test_ipv4_multicast_discovery_rejects_changing_target_source(
        monkeypatch):
    target = uuid.UUID('11111111-2222-3333-4444-555555555555')
    sources = [('192.0.2.20', 41000), ('192.0.2.21', 42000)]

    def response_factory(request, round_number):
        _mtype, _code, mid, token, _options, _payload = parse_coap(request)
        payload = _identity_payload(str(target), _doxm_link(49872))
        return [(
            build_coap(TYPE_NON, 0x45, mid + 1, token, [], payload),
            sources[round_number - 1],
        )]

    fake_socket = _FakeMulticastSocket(response_factory)
    monkeypatch.setattr(
        discovery.socket, 'socket', lambda *_args: fake_socket)
    monkeypatch.setattr(
        discovery.selectors, 'DefaultSelector', _FakeSelector)

    result = discovery.discover_ocf_secure_ports_multicast(
        target,
        interface_address='192.0.2.10',
        round_timeout=0.1,
    )

    assert not result.found
    assert result.address is None
    assert result.ports == ()
    assert result.error_code == 'ambiguous_target'


def test_ipv4_multicast_no_response_stops_without_unicast_fallback(
        monkeypatch):
    target = uuid.UUID('11111111-2222-3333-4444-555555555555')
    fake_socket = _FakeMulticastSocket(
        lambda _request, _round_number: [])

    def unexpected_unicast(*_args, **_kwargs):
        pytest.fail('explicit multicast discovery invoked unicast fallback')

    monkeypatch.setattr(
        discovery.socket, 'socket', lambda *_args: fake_socket)
    monkeypatch.setattr(
        discovery.selectors, 'DefaultSelector', _FakeSelector)
    monkeypatch.setattr(
        discovery, 'discover_ocf_secure_ports', unexpected_unicast)

    result = discovery.discover_ocf_secure_ports_multicast(
        target,
        interface_address='192.0.2.10',
        round_timeout=0.1,
    )

    assert not result.found
    assert result.rounds == 2
    assert result.responses == 0
    assert result.error_code == 'no_ocf_response'
    assert len(fake_socket.requests) == 2


def test_ipv4_multicast_rounds_are_time_and_datagram_bounded(monkeypatch):
    target = uuid.UUID('11111111-2222-3333-4444-555555555555')
    source = ('192.0.2.20', 41000)

    def response_factory(request, _round_number):
        _mtype, _code, mid, _token, _options, _payload = parse_coap(request)
        return [
            (
                build_coap(
                    TYPE_NON,
                    0x45,
                    (mid + offset + 1) & 0xFFFF,
                    b'wrong-token',
                    [],
                    _identity_payload(str(target), _doxm_link()),
                ),
                source,
            )
            for offset in range(
                discovery._MAX_MULTICAST_RESPONSES_PER_ROUND + 1)
        ]

    class RecordingSelector(_FakeSelector):
        def __init__(self):
            super().__init__()
            self.timeouts = []

        def select(self, timeout):
            self.timeouts.append(timeout)
            return super().select(timeout)

    fake_socket = _FakeMulticastSocket(response_factory)
    fake_selector = RecordingSelector()
    monkeypatch.setattr(
        discovery.socket, 'socket', lambda *_args: fake_socket)
    monkeypatch.setattr(
        discovery.selectors, 'DefaultSelector', lambda: fake_selector)

    round_timeout = 0.1
    result = discovery.discover_ocf_secure_ports_multicast(
        target,
        interface_address='192.0.2.10',
        round_timeout=round_timeout,
    )

    assert not result.found
    assert result.rounds == 2
    assert len(fake_socket.requests) == 2
    assert fake_socket.recv_count == (
        discovery._MAX_MULTICAST_RESPONSES_PER_ROUND * 2)
    assert len(fake_selector.timeouts) == fake_socket.recv_count
    assert all(
        0 < timeout <= round_timeout for timeout in fake_selector.timeouts)


@pytest.mark.parametrize(
    ('target_uuid', 'interface_address', 'round_timeout', 'error_type'),
    (
        ('not-a-uuid', '192.0.2.10', 1.0, ValueError),
        (object(), '192.0.2.10', 1.0, TypeError),
        ('11111111-2222-3333-4444-555555555555', 'not-an-ip', 1.0,
         ValueError),
        ('11111111-2222-3333-4444-555555555555', 1, 1.0, TypeError),
        ('11111111-2222-3333-4444-555555555555',
         discovery._IPV4_OCF_MULTICAST_GROUP, 1.0,
         ValueError),
        ('11111111-2222-3333-4444-555555555555', '192.0.2.10', 30.1,
         ValueError),
    ),
)
def test_invalid_multicast_options_fail_before_network(
        target_uuid, interface_address, round_timeout, error_type):
    with pytest.raises(error_type):
        discovery.discover_ocf_secure_ports_multicast(
            target_uuid,
            interface_address=interface_address,
            round_timeout=round_timeout,
        )


def test_resolution_failure_and_result_repr_are_redacted(monkeypatch):
    remote_host = 'private-appliance.invalid'

    def fail(host, port, *, family):
        assert host == remote_host
        assert port == 5683
        assert family == socket.AF_INET6
        raise EndpointError()

    def unexpected_multicast(*_args, **_kwargs):
        pytest.fail('known-host discovery invoked multicast fallback')

    monkeypatch.setattr(discovery, 'resolve_udp_endpoints', fail)
    monkeypatch.setattr(
        discovery,
        'discover_ocf_secure_ports_multicast',
        unexpected_multicast,
    )

    result = discovery.discover_ocf_secure_ports(
        remote_host, family=socket.AF_INET6)
    rendered = repr(result) + ''.join(
        traceback.format_exception(EndpointError()))

    assert result.error_code == 'endpoint_unavailable'
    assert result.attempts == 0
    assert remote_host not in rendered
    assert '49872' not in repr(
        discovery.OcfSecurePortDiscoveryResult((49872,), 1, True))


def test_result_is_immutable_and_ipv6_scope_is_part_of_source_identity():
    result = discovery.OcfSecurePortDiscoveryResult((49872,), 1, True)

    with pytest.raises(FrozenInstanceError):
        result.attempts = 2
    assert discovery._host_key(
        socket.AF_INET, ('192.0.2.20', 5683)) != discovery._host_key(
            socket.AF_INET, ('192.0.2.21', 5683))
    assert discovery._host_key(
        socket.AF_INET6, ('2001:db8::20', 5683, 0, 7)) != \
        discovery._host_key(
            socket.AF_INET6, ('2001:db8::20', 5683, 0, 8))


@pytest.mark.parametrize(
    ('keyword', 'value', 'error_type'),
    (
        ('discovery_port', 0, ValueError),
        ('discovery_port', True, TypeError),
        ('timeout', 0, ValueError),
        ('timeout', float('nan'), ValueError),
        ('timeout', True, TypeError),
        ('retries', 5, ValueError),
        ('retries', True, TypeError),
        ('family', 9999, ValueError),
        ('family', 'AF_INET', TypeError),
    ),
)
def test_invalid_options_fail_before_network(keyword, value, error_type):
    with pytest.raises(error_type):
        discovery.discover_ocf_secure_ports(
            '192.0.2.20', **{keyword: value})
