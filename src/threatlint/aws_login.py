"""Interactive AWS IAM Identity Center sign-in in a private browser window.

`threatlint aws login` writes (or reuses) an SSO profile in ~/.aws/config and runs
`aws sso login --no-browser`, opening the verification URL the AWS CLI prints in a private
window of the default browser. A normal window shares an existing Okta session and fails with
"Conflicting User IDs specified on state token". The AWS CLI keeps the resulting token in its
own cache, so `threatlint avit fetch`, `run fp-review --avit`, and the Workbench's
"Read with AWS CLI" all work afterwards with `--aws-profile <profile>`.
"""

from __future__ import annotations

import configparser
import json
import os
import plistlib
import re
import shutil
import subprocess
import sys
from pathlib import Path

from threatlint.servicenow import AWS_REGION
from threatlint.tls import tool_env

DEFAULT_PROFILE = "appsec"
DEFAULT_SESSION = "threatlint"
START_URL_ENV = "THREATLINT_AWS_SSO_START_URL"
SSO_REGION_ENV = "THREATLINT_AWS_SSO_REGION"
_START_URL = re.compile(r"^https://[a-z0-9-]+\.(?:awsapps\.com|app\.aws)/start/?(?:#.*)?$", re.IGNORECASE)
_REGION = re.compile(r"^[a-z]{2}(?:-gov)?-[a-z]+-\d$")
_NAME = re.compile(r"^[\w.@+-]{1,128}$")
# Only the sign-in page the AWS CLI asks the user to open: the access portal device page, or the
# regional device endpoint. Error messages also contain AWS URLs (e.g. oidc.<region>.amazonaws.com) and must not open.
_VERIFY_URL = re.compile(r"https://(?:[a-z0-9-]+\.(?:awsapps\.com|app\.aws)/start/?#/device|device\.sso\.[a-z0-9-]+\.amazonaws\.com/?)\S*", re.IGNORECASE)

# Browsers whose private mode can be requested from the command line.
# (name, macOS bundle-ID prefix, macOS app, Windows ProgId prefix, executable, flag)
_PRIVATE = (
    ("Google Chrome", "com.google.chrome", "Google Chrome", "ChromeHTML", "chrome", "--incognito"),
    ("Microsoft Edge", "com.microsoft.edge", "Microsoft Edge", "MSEdgeHTM", "msedge", "--inprivate"),
    ("Brave", "com.brave.browser", "Brave Browser", "BraveHTML", "brave", "--incognito"),
    ("Chromium", "org.chromium.chromium", "Chromium", "ChromiumHTM", "chromium", "--incognito"),
    ("Vivaldi", "com.vivaldi.vivaldi", "Vivaldi", "VivaldiHTM", "vivaldi", "--incognito"),
    ("Firefox", "org.mozilla.firefox", "Firefox", "FirefoxURL", "firefox", "-private-window"),
)


class AwsLoginError(RuntimeError):
    """A user-actionable sign-in failure."""


def aws_config_path() -> Path:
    return Path(os.environ.get("AWS_CONFIG_FILE") or Path.home() / ".aws" / "config").expanduser()


def _default_browser_id() -> str:
    """Bundle ID (macOS), ProgId (Windows), or .desktop name (Linux) of the default https handler."""
    try:
        if sys.platform == "darwin":
            plist = Path.home() / "Library/Preferences/com.apple.LaunchServices/com.apple.launchservices.secure.plist"
            handlers = plistlib.loads(plist.read_bytes()).get("LSHandlers", [])
            return next((h.get("LSHandlerRoleAll", "") for h in handlers if h.get("LSHandlerURLScheme") == "https"), "com.apple.safari")
        if sys.platform == "win32":
            import winreg  # noqa: PLC0415 - Windows only
            key = r"Software\Microsoft\Windows\Shell\Associations\UrlAssociations\https\UserChoice"
            with winreg.OpenKey(winreg.HKEY_CURRENT_USER, key) as handle:
                return winreg.QueryValueEx(handle, "ProgId")[0]
        return subprocess.run(["xdg-settings", "get", "default-web-browser"], capture_output=True, text=True, timeout=5, check=False).stdout.strip()
    except (OSError, ValueError, subprocess.SubprocessError):
        return ""


def _mac_app(app: str) -> Path | None:
    return next((path for path in (Path("/Applications") / f"{app}.app", Path.home() / "Applications" / f"{app}.app") if path.exists()), None)


def _candidates(default_id: str):
    """The default browser first when it supports private windows, then the others."""
    lowered = default_id.lower()
    def matches(entry):
        name, bundle, _app, progid, exe, _flag = entry
        if sys.platform == "darwin":
            return lowered.startswith(bundle)
        if sys.platform == "win32":
            return lowered.startswith(progid.lower())
        return exe in lowered or name.split()[-1].lower() in lowered
    preferred = [entry for entry in _PRIVATE if matches(entry)]
    return preferred + [entry for entry in _PRIVATE if entry not in preferred], bool(preferred)


def _windows_exe(exe: str) -> str | None:
    """Browser executable on Windows: PATH, then the App Paths registration browsers install."""
    found = shutil.which(exe)
    if found:
        return found
    try:
        import winreg  # noqa: PLC0415 - Windows only
    except ImportError:
        return None
    for root in (winreg.HKEY_CURRENT_USER, winreg.HKEY_LOCAL_MACHINE):
        try:
            with winreg.OpenKey(root, rf"Software\Microsoft\Windows\CurrentVersion\App Paths\{exe}.exe") as handle:
                value = winreg.QueryValueEx(handle, "")[0]
                if value and Path(value.strip('"')).exists():
                    return value.strip('"')
        except OSError:
            continue
    return None


def _launch(entry, url: str) -> bool:
    _name, _bundle, app, _progid, exe, flag = entry
    try:
        if sys.platform == "darwin":
            path = _mac_app(app)
            if not path:
                return False
            subprocess.run(["/usr/bin/open", "-na", str(path), "--args", flag, url], check=True, timeout=15)
        elif sys.platform == "win32":
            path = _windows_exe(exe)
            if not path:
                return False
            subprocess.Popen([path, flag, url], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
                             creationflags=getattr(subprocess, "DETACHED_PROCESS", 0))
        else:
            if not shutil.which(exe):
                return False
            subprocess.Popen([exe, flag, url], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, start_new_session=True)
        return True
    except (OSError, subprocess.SubprocessError):
        return False


def open_private(url: str) -> tuple[str | None, bool]:
    """Open url in a private window. Returns (browser name or None, whether it was the default browser)."""
    entries, default_supported = _candidates(_default_browser_id())
    for index, entry in enumerate(entries):
        if _launch(entry, url):
            return entry[0], default_supported and index == 0
    return None, False


def ensure_profile(profile: str, start_url: str, sso_region: str, account_id: str, role_name: str,
                   session: str = DEFAULT_SESSION, path: Path | None = None) -> bool:
    """Create or update the SSO session and profile. Returns True when the file changed."""
    path = path or aws_config_path()
    config = configparser.RawConfigParser()
    config.read(path, encoding="utf-8")
    wanted = {
        f"sso-session {session}": {"sso_start_url": start_url, "sso_region": sso_region, "sso_registration_scopes": "sso:account:access"},
        f"profile {profile}": {"sso_session": session, "sso_account_id": account_id, "sso_role_name": role_name, "region": AWS_REGION, "output": "json"},
    }
    changed = False
    for section, values in wanted.items():
        if not config.has_section(section):
            config.add_section(section)
        for key, value in values.items():
            if config.get(section, key, fallback=None) != value:
                config.set(section, key, value)
                changed = True
    if changed:
        path.parent.mkdir(parents=True, exist_ok=True)
        with open(path, "w", encoding="utf-8") as handle:
            config.write(handle)
    return changed


def existing_profile(profile: str, path: Path | None = None) -> dict[str, str] | None:
    config = configparser.RawConfigParser()
    config.read(path or aws_config_path(), encoding="utf-8")
    section = f"profile {profile}" if profile != "default" else "default"
    return dict(config.items(section)) if config.has_section(section) else None


def existing_session(name: str, path: Path | None = None) -> dict[str, str]:
    config = configparser.RawConfigParser()
    config.read(path or aws_config_path(), encoding="utf-8")
    section = f"sso-session {name}"
    return dict(config.items(section)) if name and config.has_section(section) else {}


def _aws() -> str:
    aws = shutil.which("aws")
    if not aws:
        raise AwsLoginError("The AWS CLI v2 is required: https://docs.aws.amazon.com/cli/latest/userguide/getting-started-install.html")
    return aws


# Identity Center regions to try when the entered one rejects the portal (most common first).
_REGIONS = ("us-east-1", "us-east-2", "us-west-2", "us-west-1", "eu-central-1", "eu-west-1", "eu-west-2", "ap-southeast-1",
            "ap-southeast-2", "ap-northeast-1", "ap-south-1", "ca-central-1", "sa-east-1")


def portal_accepts(start_url: str, region: str) -> bool:
    """True when Identity Center in this region hosts the portal; a wrong region answers InvalidRequestException."""
    result = subprocess.run([_aws(), "sso-oidc", "register-client", "--client-name", "threatlint-region-check", "--client-type", "public",
                             "--grant-types", "authorization_code", "refresh_token", "--redirect-uris", "http://127.0.0.1/oauth/callback",
                             "--issuer-url", start_url, "--scopes", "sso:account:access", "--region", region, "--query", "clientIdIssuedAt"],
                            capture_output=True, text=True, timeout=30, check=False, env=tool_env())
    return result.returncode == 0


def detect_region(start_url: str, preferred: str = "") -> str:
    """The Identity Center region for the portal, trying the preferred one first."""
    for region in dict.fromkeys([preferred, *_REGIONS]):
        if region and portal_accepts(start_url, region):
            return region
    raise AwsLoginError(f"No IAM Identity Center region accepted {start_url}. Check the access portal URL.")


def sso_login(profile: str, opener=open_private, out=sys.stdout) -> None:
    """Run `aws sso login --no-browser` and open the URL it prints in a private window."""
    process = subprocess.Popen([_aws(), "sso", "login", "--no-browser", "--profile", profile],
                               stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True, bufsize=1, env=tool_env())
    opened, plain = False, None
    def open_url(url):
        browser, used_default = opener(url)
        if browser and used_default:
            print(f"→ Opened in a private {browser} window. Approve the request there.", file=out)
        elif browser:
            print(f"→ Your default browser has no scriptable private mode; opened a private {browser} window instead.", file=out)
        else:
            print("→ No browser with a private window was found. Paste the URL above into a private/incognito window.", file=out)
    # The CLI prints the plain device URL, then one with the code pre-filled; open the latter when it appears.
    for line in process.stdout:
        out.write(line)
        out.flush()
        match = _VERIFY_URL.search(line)
        if not match or opened:
            continue
        if "user_code=" in match.group(0):
            opened = True
            open_url(match.group(0))
        elif plain is None:
            plain = match.group(0)
    if not opened and plain:
        opened = True
        open_url(plain)
    if process.wait() != 0:
        hint = "" if opened else " The AWS CLI failed before showing a sign-in page; see its message above."
        raise AwsLoginError("AWS sign-in did not complete." + (hint or " If the browser showed 'Conflicting User IDs', retry and use only the private window."))


def caller_identity(profile: str) -> dict:
    result = subprocess.run([_aws(), "sts", "get-caller-identity", "--profile", profile, "--output", "json"],
                            capture_output=True, text=True, timeout=60, check=False, env=tool_env())
    if result.returncode != 0:
        raise AwsLoginError((result.stderr.strip().splitlines() or ["sts get-caller-identity failed"])[-1])
    return json.loads(result.stdout)


# ── CLI ───────────────────────────────────────────────────────────────────────

def add_aws_parser(sub) -> None:
    p = sub.add_parser("aws", help="Sign in to AWS IAM Identity Center for Parameter Store access")
    actions = p.add_subparsers(dest="aws_command", required=True)
    login = actions.add_parser("login", help="Sign in through a private browser window and save a reusable profile")
    login.add_argument("--profile", default=DEFAULT_PROFILE, help=f"Profile name to create or use (default: {DEFAULT_PROFILE})")
    login.add_argument("--start-url", default=os.environ.get(START_URL_ENV, ""),
                       help=f"AWS access portal URL, e.g. https://<name>.awsapps.com/start (or {START_URL_ENV})")
    login.add_argument("--sso-region", default=os.environ.get(SSO_REGION_ENV, ""), help=f"IAM Identity Center region (or {SSO_REGION_ENV}); detected from the portal when omitted or wrong")
    login.add_argument("--account-id", help="AWS account ID holding the AppSec parameters")
    login.add_argument("--role", help="Permission set (role) name to assume")


def _ask(label: str, current: str, pattern: re.Pattern | None = None) -> str:
    if current:
        return current
    if not sys.stdin.isatty():
        raise AwsLoginError(f"Missing {label}; pass it as an option")
    value = input(f"{label}: ").strip()
    if pattern and not pattern.fullmatch(value):
        raise AwsLoginError(f"Invalid {label}: {value}")
    return value


def cmd_aws(args) -> int:
    try:
        profile = args.profile
        if not _NAME.fullmatch(profile):
            raise AwsLoginError("Invalid profile name")
        current = existing_profile(profile) or {}
        if not current.get("sso_session") and not current.get("sso_start_url"):
            start_url = _ask("AWS access portal URL (https://<name>.awsapps.com/start)", args.start_url, _START_URL)
            if not _START_URL.fullmatch(start_url):
                raise AwsLoginError("The access portal URL must look like https://<name>.awsapps.com/start")
            region = detect_region(start_url.split("#")[0].rstrip("/"), args.sso_region if _REGION.fullmatch(args.sso_region or "") else "")
            print(f"  Identity Center region: {region}")
            account = _ask("AWS account ID", args.account_id or "", re.compile(r"\d{12}"))
            role = _ask("Role (permission set) name", args.role or "", _NAME)
            ensure_profile(profile, start_url.split("#")[0].rstrip("/"), region, account, role)
            print(f"✓ Saved AWS profile '{profile}' in {aws_config_path()}")
        # Repair a saved profile whose region does not host the portal (AWS answers InvalidRequestException).
        session = existing_session(current.get("sso_session", ""))
        if session.get("sso_start_url") and session.get("sso_region") and not portal_accepts(session["sso_start_url"], session["sso_region"]):
            region = detect_region(session["sso_start_url"])
            ensure_profile(profile, session["sso_start_url"], region, current.get("sso_account_id", ""), current.get("sso_role_name", ""), session=current["sso_session"])
            print(f"✓ Corrected Identity Center region {session['sso_region']} → {region} for {session['sso_start_url']}")
        sso_login(profile)
        identity = caller_identity(profile)
        print(f"✓ Signed in as {identity.get('Arn', 'unknown')}")
        print(f"  Use it with: threatlint avit fetch <AVIT> --aws-profile {profile} -o avits.md")
        print(f"  Workbench:   Model & settings → ServiceNow → AWS CLI profile '{profile}' → Read with AWS CLI")
        return 0
    except (AwsLoginError, OSError, subprocess.SubprocessError) as exc:
        print(f"ERROR: {exc}", file=sys.stderr)
        return 1
