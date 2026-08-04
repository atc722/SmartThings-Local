import pytest

from smartthings_local.errors import MalformedMessageError
from smartthings_local.protocol.coap import (
    ACCEPT,
    CF_CBOR,
    METHOD_GET,
    TYPE_CON,
    URI_PATH,
    block_value,
    build_coap,
    encode_options,
    fmt_code,
    parse_coap,
)


def test_build_then_parse_roundtrip_no_payload():
    opts = [(URI_PATH, b'device'), (URI_PATH, b'0'), (ACCEPT, CF_CBOR)]
    datagram = build_coap(TYPE_CON, METHOD_GET, 0xABCD, b'\x01\x02', opts)
    mtype, code, mid, tok, parsed_opts, payload = parse_coap(datagram)
    assert mtype == TYPE_CON
    assert code == METHOD_GET
    assert mid == 0xABCD
    assert tok == b'\x01\x02'
    assert payload == b''
    assert sorted(parsed_opts) == sorted(opts)


def test_build_then_parse_roundtrip_with_payload():
    datagram = build_coap(TYPE_CON, 0x45, 1, b'\xff', [], payload=b'\xa1\x01\x02')
    _, code, _, _, _, payload = parse_coap(datagram)
    assert code == 0x45
    assert payload == b'\xa1\x01\x02'


def test_encode_options_orders_by_option_number():
    # ACCEPT (17) must be encoded after URI_PATH (11) regardless of input order
    encoded_in_order = encode_options([(URI_PATH, b'x'), (ACCEPT, CF_CBOR)])
    encoded_reversed = encode_options([(ACCEPT, CF_CBOR), (URI_PATH, b'x')])
    assert encoded_in_order == encoded_reversed


def test_block_value_encodes_num_more_szx():
    # num=2, more=1, szx=6 -> (2<<4)|(1<<3)|6 = 0x2E
    assert block_value(2, 1, 6) == bytes([0x2E])


def test_block_value_promotes_to_two_bytes_when_num_is_large():
    v = block_value(num=0xFFF, more=0, szx=0)
    assert len(v) == 2


def test_fmt_code_formats_class_dot_detail():
    assert fmt_code(0x45) == '2.05'
    assert fmt_code(0x84) == '4.04'


@pytest.mark.parametrize('option_header', (b'\xf0', b'\x0f'))
def test_reserved_option_nibbles_raise_classified_value_error(option_header):
    datagram = b'\x40\x01\x00\x01' + option_header

    with pytest.raises(MalformedMessageError) as exc:
        parse_coap(datagram)

    assert isinstance(exc.value, ValueError)


@pytest.mark.parametrize(
    'datagram',
    (
        b'',
        b'\x40\x01\x00',
        b'\x80\x01\x00\x01',       # unsupported CoAP version
        b'\x49\x01\x00\x01' + b'x' * 9,  # reserved token length
        b'\x44\x01\x00\x01abc',    # truncated token
        b'\x40\x01\x00\x01\xd0', # truncated extended delta
        b'\x40\x01\x00\x01\xe0\x00',
        b'\x40\x01\x00\x01\x0d', # truncated extended length
        b'\x40\x01\x00\x01\x0e\x00',
        b'\x40\x01\x00\x01\x03ab',  # truncated option value
        b'\x40\x01\x00\x01\xff', # empty payload marker
    ),
)
def test_truncated_or_structurally_invalid_datagrams_are_classified(datagram):
    with pytest.raises(MalformedMessageError):
        parse_coap(datagram)


def test_non_bytes_coap_input_is_classified():
    with pytest.raises(MalformedMessageError):
        parse_coap('not wire bytes')
