import json

import pytest

from campus_autoconnect.core.errors import CampusError
from campus_autoconnect.services.capture_analysis import analyze_capture, capture_endpoints

pytestmark = pytest.mark.mock


def synthetic_capture():
    return {
        "tool": "Campus Portal Capture / sanitized v1.1.0",
        "count": 1,
        "candidate_api_paths": ["GET http://private.example.invalid/secret"],
        "requests": [
            {
                "method": "GET",
                "url": {
                    "scheme": "http",
                    "host": "private.example.invalid",
                    "port": 801,
                    "path": "/eportal/portal/login",
                    "query": [
                        {"name": "login_method", "value": "1"},
                        {"name": "user_password", "value": "[hidden: 11 chars]"},
                        {"name": "user_account", "value": "[hidden: 8 chars]"},
                        {"name": "lang", "value": "[hidden: 5 chars]"},
                        {"name": "lang", "value": "[hidden: 2 chars]"},
                    ],
                },
                "http_status": 200,
                "response_summary": {
                    "result": 1,
                    "text_signal": "login_success",
                    "msg": "must-never-escape",
                },
            }
        ],
    }


def save(tmp_path, payload):
    path = tmp_path / "capture.json"
    path.write_text(json.dumps(payload), encoding="utf-8")
    return path


def test_analysis_distinguishes_server_success_from_connectivity_and_hides_identifiers(tmp_path):
    report = analyze_capture(save(tmp_path, synthetic_capture()))
    assert report["server_success_summary_observed"]
    assert report["sensitive_query_values_hidden"]
    assert report["http_count"] == 1 and report["https_count"] == 0
    assert report["steps"][0]["duplicate_language_field"]
    assert "HTTPS" in report["transport_status"]
    text = json.dumps(report)
    for secret in ("private.example.invalid", "must-never-escape", "11 chars", "8 chars"):
        assert secret not in text


def test_raw_values_are_flagged_but_never_displayed(tmp_path):
    payload = synthetic_capture()
    payload["requests"][0]["url"]["query"][1]["value"] = "synthetic-private-password"
    report = analyze_capture(save(tmp_path, payload))
    assert not report["sensitive_query_values_hidden"]
    assert "synthetic-private-password" not in json.dumps(report)


def test_http_200_or_status_query_does_not_establish_login_success(tmp_path):
    payload = synthetic_capture()
    payload["requests"][0]["url"]["path"] = "/eportal/portal/online_list"
    report = analyze_capture(save(tmp_path, payload))
    assert not report["login_request_observed"]
    assert not report["server_success_summary_observed"]


@pytest.mark.parametrize(
    "payload",
    [
        [],
        {},
        {"requests": []},
        {"tool": "other", "requests": [], "count": 0},
        {"tool": "Campus Portal Capture / sanitized v1.1.0", "requests": [None], "count": 1},
    ],
)
def test_invalid_capture_has_fixed_safe_error(tmp_path, payload):
    with pytest.raises(CampusError) as error:
        analyze_capture(save(tmp_path, payload))
    assert error.value.message == "抓包文件无法读取或格式不支持；未显示原始内容。"


def test_capture_size_is_bounded(tmp_path):
    path = tmp_path / "too-big.json"
    path.write_bytes(b"x" * (2 * 1024 * 1024 + 1))
    with pytest.raises(CampusError):
        analyze_capture(path)


def endpoints_capture():
    payload = synthetic_capture()
    for path, port in (("/a79.htm", None), ("/eportal/portal/page/loadConfig", 801)):
        payload["requests"].append(
            {
                "method": "GET",
                "url": {
                    "scheme": "http",
                    "host": "private.example.invalid",
                    "port": port,
                    "path": path,
                    "query": [],
                },
            }
        )
    payload["count"] = len(payload["requests"])
    return payload


def test_capture_provides_explicit_local_editor_targets_without_permission(tmp_path):
    path = save(tmp_path, endpoints_capture())
    before = path.read_bytes()
    assert capture_endpoints(path) == (
        "http://private.example.invalid/a79.htm",
        "http://private.example.invalid:801",
    )
    assert path.read_bytes() == before
    assert not (tmp_path / "config.json").exists()


@pytest.mark.parametrize("change", ["missing", "other_host", "raw_password", "page_query"])
def test_capture_editor_targets_reject_missing_or_inconsistent_evidence(tmp_path, change):
    payload = endpoints_capture()
    if change == "missing":
        payload["requests"].pop()
        payload["count"] -= 1
    elif change == "other_host":
        payload["requests"][-1]["url"]["host"] = "evil.example.test"
    elif change == "raw_password":
        payload["requests"][0]["url"]["query"][1]["value"] = "synthetic-private-password"
    else:
        payload["requests"][1]["url"]["query"] = [{"name": "token", "value": "PRIVATE"}]
    with pytest.raises(CampusError) as error:
        capture_endpoints(save(tmp_path, payload))
    assert "PRIVATE" not in error.value.message
