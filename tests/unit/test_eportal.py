import pytest

from campus_autoconnect.adapters.eportal import (
    EPortalConfig,
    EPortalContext,
    login_account,
    parse_jsonp,
    response_accepted,
)
from campus_autoconnect.core.errors import CampusError
from campus_autoconnect.core.models import ErrorCode

pytestmark = pytest.mark.mock


@pytest.fixture
def config_payload():
    return {
        "code": 1,
        "data": {
            "login_method": "1",
            "en_md5": "0",
            "password_cut": "0",
            "account_prefix": "0",
            "enable_alias": "0",
            "io_mode": "0",
            "ipv6_state": "0",
            "enable_hotelop_login": "0",
            "en_perceive": "0",
            "account_suffix": "@example",
            "enable_https": "0",
            "ep_http_port": "801",
            "ep_https_port": "802",
        },
    }


def test_jsonp_accepts_data_without_executing_javascript():
    assert parse_jsonp(b' dr1003({"result":1,"msg":"synthetic"}); ', "dr1003")["result"] == 1


@pytest.mark.parametrize(
    "body",
    [
        b'dr1002({"result":1})',
        b'dr1003({"result":1});alert(1)',
        b'dr1003({"result":0,"result":1})',
        b'dr1003({"result":NaN})',
        b'dr1003({"nested":{"result":0,"result":1}})',
        b"dr1003([])",
        b'dr1003({"result":1});dr1003({"result":1})',
        b'{"result":1}',
        b"dr1003(\xff)",
    ],
)
def test_jsonp_rejects_stale_malformed_or_executable_responses(body):
    with pytest.raises(CampusError) as error:
        parse_jsonp(body, "dr1003")
    assert error.value.code == ErrorCode.PROTOCOL_CHANGED
    assert body[:100].decode("utf-8", errors="ignore") not in error.value.message


def test_jsonp_response_size_is_bounded():
    with pytest.raises(CampusError):
        parse_jsonp(b"dr1003(" + b" " * 131073 + b")", "dr1003")


@pytest.mark.parametrize(
    "field,value",
    [
        ("login_method", "9"),
        ("password_cut", "1"),
        ("account_prefix", "1"),
        ("enable_alias", "1"),
        ("en_md5", True),
        ("ipv6_state", "1"),
        ("enable_https", "-1"),
        ("ep_http_port", "0"),
        ("ep_https_port", "65536"),
        ("account_suffix", "<untrusted>"),
        ("account_suffix", None),
    ],
)
def test_unverified_configuration_is_not_guessed(config_payload, field, value):
    config_payload["data"][field] = value
    with pytest.raises(CampusError):
        EPortalConfig.from_response(config_payload)


def test_supported_configuration_and_context_hide_network_values(config_payload):
    config = EPortalConfig.from_response(config_payload)
    context = EPortalContext.from_page(
        b"var v46ip='192.0.2.10';var ss4='02:00:00:00:00:07';var vlanid='12';",
        ("192.0.2.10",),
    )
    assert context.ipv4 == "192.0.2.10"
    assert context.mac == "020000000007"
    assert config.account_suffix == "@example"
    assert config.https_mode == 0
    assert "@example" not in repr(config)
    assert "192.0.2.10" not in repr(context)


@pytest.mark.parametrize(
    "page",
    [
        b"var v46ip='192.0.2.11';var ss4='020000000007';var vlanid='12';",
        b"var v46ip='192.0.2.10';var ss4='000000000000';var vlanid='12';",
        b"var v46ip='192.0.2.10';var ss4='020000000007';var vlanid='4095';",
        b"var v46ip='192.0.2.10';var v46ip='192.0.2.10';var ss4='020000000007';var vlanid='12';",
        b"var v46ip=untrusted();var ss4='020000000007';var vlanid='12';",
    ],
)
def test_page_context_requires_unambiguous_current_local_address(page):
    with pytest.raises(CampusError):
        EPortalContext.from_page(page, ("192.0.2.10",))


def test_zero_vlan_is_preserved_and_zero_mac_requires_explicit_permission():
    page = b"var v46ip='192.0.2.10';var ss4='000000000000';var vlanid='0';"
    with pytest.raises(CampusError) as error:
        EPortalContext.from_page(page, ("192.0.2.10",))
    assert error.value.code == ErrorCode.ZERO_MAC_PERMISSION_REQUIRED
    context = EPortalContext.from_page(page, ("192.0.2.10",), allow_zero_mac=True)
    assert context.mac == "000000000000" and context.vlan == "0"


@pytest.mark.parametrize(
    "page,code",
    [
        (b"var v46ip='192.0.2.10';var ss4='000000000000';", ErrorCode.SESSION_FIELDS_INVALID),
        (
            b"var v46ip='192.0.2.11';var ss4='000000000000';var vlanid='0';",
            ErrorCode.SESSION_IP_MISMATCH,
        ),
        (
            b"var v46ip='bad-address';var ss4='000000000000';var vlanid='0';",
            ErrorCode.SESSION_IP_MISMATCH,
        ),
        (
            b"var v46ip='192.0.2.10';var ss4='PRIVATE-MALFORMED';var vlanid='0';",
            ErrorCode.SESSION_MAC_INVALID,
        ),
        (
            b"var v46ip='192.0.2.10';var ss4='000000000000';var vlanid='4095';",
            ErrorCode.SESSION_VLAN_INVALID,
        ),
        (
            b"var v46ip='192.0.2.10';var ss4='000000000000';var vlanid='-1';",
            ErrorCode.SESSION_VLAN_INVALID,
        ),
    ],
)
def test_compatibility_retains_session_validation_and_specific_safe_errors(page, code):
    with pytest.raises(CampusError) as error:
        EPortalContext.from_page(page, ("192.0.2.10",), allow_zero_mac=True)
    assert error.value.code == code
    assert all(
        value not in error.value.message for value in ("PRIVATE", "192.0.2.10", "192.0.2.11")
    )


@pytest.mark.parametrize("result", [True, "1", "ok", None, 2])
def test_response_acceptance_does_not_coerce_or_guess_result_codes(result):
    with pytest.raises(CampusError):
        response_accepted({"result": result, "msg": "login success"})


def test_observed_result_zero_is_a_rejection_and_one_only_accepts_response():
    assert not response_accepted({"result": 0})
    assert response_accepted({"result": 1})


@pytest.mark.parametrize(
    "username,suffix,expected",
    [
        ("example", "@school", "example@school"),
        ("example@school", "@school", "example@school"),
        ("example@other", "", "example@other"),
        ("example", "", "example"),
        ("example", "-suffix", "example-suffix"),
    ],
)
def test_login_account_preserves_exact_input_and_supported_suffix(username, suffix, expected):
    assert login_account(username, suffix) == expected


@pytest.mark.parametrize("username", ["@school", "example@wrong", "example@school@school"])
def test_invalid_suffix_never_echoes_the_account(username):
    with pytest.raises(CampusError) as error:
        login_account(username, "@school")
    assert error.value.code == ErrorCode.MANUAL_ACTION
    assert username not in error.value.message
