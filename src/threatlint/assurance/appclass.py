"""Classify a checkout as a web/API application or a mobile application.

The classification routes the dynamic stage: a web or API app is built in an ephemeral environment and probed with
the runtime engine (Invicti is the external submission target); a mobile app is handed to the mobile analyzer
(NowSecure). Detection is signal-based over the checkout and bounded; when nothing mobile is found, the target is
treated as web/API, which is the only kind the ephemeral build understands.
"""

from __future__ import annotations

import os

MAX_SCAN_FILES = 4000

# Each signal: (type, platform, reason, matcher(relpath, lower_name) -> bool). Mobile signals win over web.
_IOS = lambda rel, name: name.endswith((".xcodeproj", ".xcworkspace")) or name == "podfile" or name == "podfile.lock"
_ANDROID = lambda rel, name: name == "androidmanifest.xml"


def _android_gradle(path: str) -> bool:
    try:
        with open(path, encoding="utf-8", errors="ignore") as handle:
            text = handle.read(20000)
    except OSError:
        return False
    return "com.android.application" in text or "com.android.library" in text


def _flutter_pubspec(path: str) -> bool:
    try:
        with open(path, encoding="utf-8", errors="ignore") as handle:
            return "flutter:" in handle.read(20000)
    except OSError:
        return False


def _react_native(path: str) -> bool:
    try:
        with open(path, encoding="utf-8", errors="ignore") as handle:
            return '"react-native"' in handle.read(40000)
    except OSError:
        return False


def classify(checkout: str) -> dict:
    """Return ``{"type": "web"|"mobile", "platform": str, "signals": [...]}``."""
    signals: list[str] = []
    platform = ""
    seen = 0
    for root, dirs, files in os.walk(checkout):
        dirs[:] = [name for name in dirs if name not in (".git", "node_modules", ".venv", "venv", "build", "dist", "Pods")]
        for name in files:
            seen += 1
            if seen > MAX_SCAN_FILES:
                break
            lower = name.lower()
            path = os.path.join(root, name)
            if _ANDROID(root, lower):
                signals.append(f"{name} (Android)"); platform = platform or "android"
            elif lower in ("build.gradle", "build.gradle.kts") and _android_gradle(path):
                signals.append(f"{name} (Android Gradle)"); platform = platform or "android"
            elif _IOS(root, lower) or os.path.basename(root).lower().endswith((".xcodeproj", ".xcworkspace")):
                signals.append(f"{name} (iOS)"); platform = platform or "ios"
            elif lower == "pubspec.yaml" and _flutter_pubspec(path):
                signals.append("pubspec.yaml (Flutter)"); platform = platform or "flutter"
            elif lower == "package.json" and _react_native(path):
                signals.append("package.json (React Native)"); platform = platform or "react-native"
        if seen > MAX_SCAN_FILES:
            break
    if signals:
        return {"type": "mobile", "platform": platform or "mobile", "signals": signals[:8]}
    return {"type": "web", "platform": "web/api", "signals": ["no mobile project files found; treating as a web/API application"]}
