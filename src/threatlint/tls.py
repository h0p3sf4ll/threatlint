"""OS-trusted certificate authorities for tools that ship their own CA list.

Corporate networks inspect TLS with a root installed in the OS store (macOS System keychain, Windows
certificate store). The AWS CLI v2, Python's urllib on macOS, and Homebrew git do not read that store,
so their requests fail with "unable to get local issuer certificate". This module exports the OS roots,
plus Python's default roots, to ~/.threatlint/ca-bundle.pem once per process and hands it to:
  - AWS CLI subprocesses (AWS_CA_BUNDLE), git (GIT_SSL_CAINFO), and urllib (ssl_context()).
An explicit AWS_CA_BUNDLE / GIT_SSL_CAINFO / SSL_CERT_FILE set by the user always wins.
"""

from __future__ import annotations

import os
import ssl
import subprocess
import sys
from pathlib import Path

_MAC_KEYCHAINS = ("/System/Library/Keychains/SystemRootCertificates.keychain", "/Library/Keychains/System.keychain")
_bundle: str | None = None
_built = False


def _os_roots() -> list[str]:
    """PEM certificates from the OS trust store; empty where OpenSSL already reads it (Linux)."""
    if sys.platform == "darwin":
        pems = []
        for keychain in _MAC_KEYCHAINS:
            try:
                result = subprocess.run(["/usr/bin/security", "find-certificate", "-a", "-p", keychain],
                                        capture_output=True, text=True, timeout=30, check=False)
            except (OSError, subprocess.SubprocessError):
                continue
            pems.append(result.stdout)
        return pems
    if sys.platform == "win32":
        pems = []
        for store in ("ROOT", "CA"):
            try:
                for der, encoding, _trust in ssl.enum_certificates(store):  # type: ignore[attr-defined]
                    if encoding == "x509_asn":
                        pems.append(ssl.DER_cert_to_PEM_cert(der))
            except OSError:
                continue
        return pems
    return []


def ca_bundle() -> str | None:
    """Path to a PEM bundle of OS + default roots, or None when nothing extra is needed or available."""
    global _bundle, _built
    if _built:
        return _bundle
    _built = True
    roots = [pem for pem in _os_roots() if "BEGIN CERTIFICATE" in pem]
    if not roots:
        return None
    default = ssl.get_default_verify_paths().cafile
    if default and os.path.exists(default):
        try:
            roots.append(Path(default).read_text(encoding="utf-8"))
        except OSError:
            pass
    path = Path(os.environ.get("THREATLINT_HOME") or Path.home() / ".threatlint") / "ca-bundle.pem"
    try:
        path.parent.mkdir(parents=True, exist_ok=True)
        # Write-then-rename: concurrent threatlint processes must never read a half-written bundle.
        temp = path.with_name(f"{path.name}.{os.getpid()}.tmp")
        temp.write_text("\n".join(roots), encoding="utf-8")
        os.replace(temp, path)
    except OSError:
        return None
    _bundle = str(path)
    return _bundle


def tool_env(base: dict[str, str] | None = None) -> dict[str, str]:
    """Environment for aws/git subprocesses with the OS roots, unless the user configured their own."""
    env = dict(os.environ if base is None else base)
    bundle = ca_bundle()
    if bundle:
        env.setdefault("AWS_CA_BUNDLE", bundle)
        env.setdefault("GIT_SSL_CAINFO", bundle)
    return env


def ssl_context() -> ssl.SSLContext:
    context = ssl.create_default_context(cafile=os.environ.get("SSL_CERT_FILE") or None)
    bundle = None if os.environ.get("SSL_CERT_FILE") else ca_bundle()
    if bundle:
        context.load_verify_locations(cafile=bundle)
    return context
