import gzip
import hashlib
import json
import ssl

import httpx
import pytest

from scripts.inspect_portal import (
    InspectionError,
    StructureParser,
    check_https,
    inspect_page,
    javascript_signals,
    locator,
    read_bounded,
    static_script_url,
    tls_failure,
    validate_page_url,
)

pytestmark = pytest.mark.mock


def test_read_only_structure_excludes_field_values_and_query_values():
    parser = StructureParser("https://portal.example.edu/index.html")
    parser.feed(
        '<form method="post" action="/login?token=NEVER_SHARE">'
        '<input name="account" value="PRIVATE_ACCOUNT">'
        '<input name="password" type="password" value="PRIVATE_PASSWORD">'
        '<script src="/script.js?token=NEVER_SHARE"></script></form>'
    )
    output = str((parser.forms, parser.inputs, parser.scripts))
    assert all(
        value not in output for value in ("NEVER_SHARE", "PRIVATE_ACCOUNT", "PRIVATE_PASSWORD")
    )
    assert parser.forms[0]["method"] == "POST"
    assert parser.inputs[1] == {"name": "password", "type": "password"}
    assert parser.scripts[0]["query_fields"] == ["token"]


def test_locator_never_displays_host_or_query_values():
    output = locator("http://192.0.2.5/page?token=DO_NOT_SHARE", "https://portal.example.edu")
    assert output["origin"] == "external-origin"
    assert output["path"] == "/page"
    assert "192.0.2.5" not in str(output)
    assert "DO_NOT_SHARE" not in str(output)


@pytest.mark.parametrize(
    "value",
    [
        "file:///tmp/private",
        "http://user:secret@portal.example.edu/",
        "http://example.edu/?token=secret",
        "https://example.edu/#secret",
        "http://example.edu:bad/",
        "http://example.edu:65536/",
        "http://example.edu:0/",
        "http://example.edu\\@evil.test/",
        "http://example.edu/with space",
    ],
)
def test_inspection_rejects_secret_bearing_or_invalid_page_urls(value):
    with pytest.raises(InspectionError, match="invalid_page_url"):
        validate_page_url(value)


@pytest.mark.parametrize(
    "value",
    [
        "//evil.test/a.js",
        "//portal.example.edu/a.js",
        "/../a.js",
        "/a/../../b.js",
        "/a.js?token=secret",
        "/a.js#secret",
        "https://evil.test/a.js",
        "/logout",
    ],
)
def test_script_resolution_never_expands_to_other_origins_or_non_scripts(value):
    with pytest.raises(InspectionError):
        static_script_url("https://portal.example.edu/index.html", value)


def test_script_resolution_keeps_explicit_origin_and_port():
    assert static_script_url("https://portal.example.edu:8443/index.html", "/js/a.js") == (
        "https://portal.example.edu:8443/js/a.js"
    )


def test_bounded_gzip_accepts_small_complete_stream():
    raw = b"synthetic static script"
    response = httpx.Response(
        200, headers={"content-encoding": "gzip"}, stream=httpx.ByteStream(gzip.compress(raw))
    )
    assert read_bounded(response, 1024) == raw


@pytest.mark.parametrize(
    "kind", ["expanded", "truncated", "invalid", "concatenated", "unsupported", "wire"]
)
def test_bounded_reader_rejects_dangerous_or_incomplete_data(kind):
    body = gzip.compress(b"x" * 2000)
    headers = {"content-encoding": "gzip"}
    if kind == "truncated":
        body = body[:-4]
    elif kind == "invalid":
        body = b"not-gzip"
    elif kind == "concatenated":
        body = gzip.compress(b"one") + gzip.compress(b"two")
    elif kind == "unsupported":
        headers = {"content-encoding": "br"}
    elif kind == "wire":
        headers = {}
        body = b"x" * 2000
    response = httpx.Response(200, headers=headers, stream=httpx.ByteStream(body))
    with pytest.raises(InspectionError):
        read_bounded(response, 512)


def test_tls_identity_error_is_distinct_and_never_discloses_host():
    certificate = ssl.SSLCertVerificationError(1, "PRIVATE_HOST PRIVATE_SECRET")
    certificate.verify_code = 64
    certificate.verify_message = "IP address mismatch, certificate is not valid for PRIVATE_HOST"
    wrapped = httpx.ConnectError("PRIVATE_HOST PRIVATE_SECRET")
    wrapped.__cause__ = certificate
    result = tls_failure(wrapped)
    assert result["certificate_error"] == "identity_mismatch"
    assert result["verify_code"] == 64
    assert "PRIVATE_HOST" not in str(result)
    assert "PRIVATE_SECRET" not in str(result)


def test_https_probe_never_submits_secrets_or_follows_redirects():
    seen = []

    def respond(request):
        seen.append(request)
        return httpx.Response(302, headers={"location": "https://untrusted.example.test/"})

    def client():
        return httpx.Client(
            transport=httpx.MockTransport(respond), trust_env=False, follow_redirects=False
        )

    report = check_https("http://portal.example.edu:8080/index.html", client_factory=client)
    assert report["certificate_verified"]
    assert not report["authentication_verified"]
    assert report["redirect_discovered"]
    assert len(seen) == 1
    assert str(seen[0].url) == "https://portal.example.edu/index.html"
    assert seen[0].method == "GET" and seen[0].content == b""
    assert all(header not in seen[0].headers for header in ("authorization", "cookie"))


def test_https_probe_never_converts_certificate_failure_to_success():
    def fail(_):
        raise httpx.ConnectError("private") from ssl.SSLCertVerificationError("private")

    def client():
        return httpx.Client(transport=httpx.MockTransport(fail), trust_env=False)

    report = check_https("https://portal.example.edu:8443/index.html", client_factory=client)
    assert not report["certificate_verified"]
    assert not report["authentication_verified"]
    assert report["certificate_error"] == "verification_failed"
    assert "private" not in str(report)


def test_static_signals_preserve_evidence_boundary_and_hide_values():
    source = """
    var enableHttps=0; var epHTTPPort=801; var enHTTPSPort=802; var isJSMin=1;
    var domainName="PRIVATE_DOMAIN";
    page.login_method=parseInt(json.data.login_method)||0;
    var url=page.portal_api+"page/loadConfig";
    var x={default_login:function(){},portal_login:function(){},_jsonp:function(){}};
    script.src=params.url+"?"+data;
    if(page.en_md5){password=SECRET_VALUE;}
    """
    report = javascript_signals(source)
    assert report["template_constants"]["enHTTPSPort"] == 802
    assert report["template_constants"]["enableHttps"] is False
    assert report["domain_name_configured"]
    assert report["runtime_login_method_observed"] and report["configuration_route_observed"]
    assert report["login_branches_observed"] == ["default_login", "portal_login"]
    assert report["jsonp_script_url_observed"] and report["configuration_driven_md5_observed"]
    assert report["observations_do_not_authorize_login"]
    assert all(value not in str(report) for value in ("PRIVATE_DOMAIN", "SECRET_VALUE"))
    assert javascript_signals("var epHTTPPort=" + "9" * 5000 + ";")["template_constants"] == {}


def test_static_inspection_is_reproducible_and_never_executes_javascript(monkeypatch):
    source = (
        b'var epHTTPPort=801; window.location="https://untrusted.test/SECRET";'
        b'var template="<form method=post><input name=account value=SECRET></form>";'
    )
    seen = []

    def respond(request):
        seen.append(str(request.url))
        return httpx.Response(200, stream=httpx.ByteStream(source))

    monkeypatch.setattr(
        "scripts.inspect_portal.make_client",
        lambda: httpx.Client(
            transport=httpx.MockTransport(respond),
            trust_env=False,
            follow_redirects=False,
        ),
    )
    report = inspect_page("http://portal.example.edu/index.html", "/a.js")
    assert report["script_sha256"] == hashlib.sha256(source).hexdigest()
    assert seen == ["http://portal.example.edu/a.js"]
    assert report["html_structure_applicable"] is False
    assert report["forms"] == [] and report["inputs_without_values"] == []
    assert "SECRET" not in json.dumps(report)
    assert "untrusted.test" not in json.dumps(report)
