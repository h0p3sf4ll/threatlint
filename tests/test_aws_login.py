"""threatlint aws login: profile writing, private-window choice, and URL capture from the AWS CLI."""

import configparser
import io
import subprocess

from threatlint import aws_login


def test_profile_is_written_once_and_reused(tmp_path):
    config = tmp_path / "config"
    assert aws_login.ensure_profile("appsec", "https://example.awsapps.com/start", "eu-central-1", "111122223333", "ReadOnly", path=config)
    assert not aws_login.ensure_profile("appsec", "https://example.awsapps.com/start", "eu-central-1", "111122223333", "ReadOnly", path=config)
    parsed = configparser.RawConfigParser()
    parsed.read(config)
    assert parsed["profile appsec"]["sso_session"] == "threatlint" and parsed["profile appsec"]["region"] == "us-west-2"
    assert parsed["sso-session threatlint"]["sso_start_url"] == "https://example.awsapps.com/start"
    assert aws_login.existing_profile("appsec", config)["sso_role_name"] == "ReadOnly"


def test_private_window_prefers_default_browser_then_falls_back(monkeypatch):
    launched = []
    monkeypatch.setattr(aws_login.sys, "platform", "darwin")
    monkeypatch.setattr(aws_login, "_launch", lambda entry, url: launched.append(entry[5]) or entry[0] != "Google Chrome")
    monkeypatch.setattr(aws_login, "_default_browser_id", lambda: "com.microsoft.edgemac")
    assert aws_login.open_private("https://x") == ("Microsoft Edge", True)
    launched.clear()
    monkeypatch.setattr(aws_login, "_default_browser_id", lambda: "company.thebrowser.dia")
    assert aws_login.open_private("https://x") == ("Microsoft Edge", False)
    assert launched == ["--incognito", "--inprivate"]


def test_sso_login_opens_the_printed_url_privately(monkeypatch):
    printed = ("Browser will not be automatically opened.\nPlease visit the following URL:\n\nhttps://example.awsapps.com/start/#/device\n\n"
               "Then enter the code:\n\nABCD-EFGH\n\nAlternatively, you may visit the following URL which will autofill the code upon loading:\n"
               "https://example.awsapps.com/start/#/device?user_code=ABCD-EFGH\n")

    class Fake:
        def __init__(self, command, **_):
            assert command[1:] == ["sso", "login", "--no-browser", "--profile", "appsec"]
            self.stdout = io.StringIO(printed)

        def wait(self):
            return 0

    monkeypatch.setattr(aws_login, "_aws", lambda: "aws")
    monkeypatch.setattr(subprocess, "Popen", Fake)
    opened, out = [], io.StringIO()
    aws_login.sso_login("appsec", opener=lambda url: opened.append(url) or ("Firefox", True), out=out)
    assert opened == ["https://example.awsapps.com/start/#/device?user_code=ABCD-EFGH"]
    assert "private Firefox window" in out.getvalue()


def test_error_messages_with_aws_urls_never_open_a_browser(monkeypatch):
    printed = "SSL validation failed for https://oidc.us-east-2.amazonaws.com/client/register [SSL: CERTIFICATE_VERIFY_FAILED]\n"

    class Fake:
        def __init__(self, command, **kwargs):
            assert kwargs["env"].get("AWS_CA_BUNDLE") or not aws_login.tool_env().get("AWS_CA_BUNDLE")
            self.stdout = io.StringIO(printed)

        def wait(self):
            return 255

    monkeypatch.setattr(aws_login, "_aws", lambda: "aws")
    monkeypatch.setattr(subprocess, "Popen", Fake)
    opened = []
    try:
        aws_login.sso_login("appsec", opener=lambda url: opened.append(url) or ("Chrome", True), out=io.StringIO())
    except aws_login.AwsLoginError as exc:
        assert "before showing a sign-in page" in str(exc)
    assert opened == []


def test_region_is_detected_from_the_portal(monkeypatch):
    monkeypatch.setattr(aws_login, "portal_accepts", lambda url, region: region == "us-east-1")
    assert aws_login.detect_region("https://console-example.awsapps.com/start", "us-east-2") == "us-east-1"
