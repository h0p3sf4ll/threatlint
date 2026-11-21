"""Repository identity and bounded, symlink-free source snapshots."""

from __future__ import annotations

import hashlib
import os
import subprocess
import stat
from pathlib import Path

from threatlint.guard.scanning import MAX_FILE_BYTES, SKIP_DIRS, _scannable

MAX_FILES = 10000
MAX_BYTES = 30_000_000


class ScannerError(ValueError):
    pass


class ScannerCancelled(Exception):
    """Cancellation must propagate through engine failure normalization."""


def git(root: Path, *args: str) -> str:
    try:
        result = subprocess.run(["git", "-C", str(root), *args], capture_output=True, text=True,
                                timeout=15, check=False, shell=False)
        return result.stdout.strip() if result.returncode == 0 else ""
    except (OSError, subprocess.TimeoutExpired):
        return ""


def content_digest(files: dict[str, bytes]) -> str:
    digest = hashlib.sha256()
    for name, data in sorted(files.items()):
        digest.update(name.encode("utf-8", errors="replace") + b"\0" + hashlib.sha256(data).digest())
    return digest.hexdigest()


def snapshot(repository: str) -> tuple[dict, dict[str, bytes], dict]:
    root = Path(repository).resolve()
    if not root.is_dir():
        raise ScannerError("Choose an existing repository directory")
    files: dict[str, bytes] = {}
    skipped = {"symlink": 0, "large": 0, "unreadable": 0, "unsupported": 0, "budget": 0}
    total = 0
    for directory, directories, names in os.walk(root, followlinks=False):
        safe_dirs = []
        for name in sorted(directories):
            candidate = Path(directory) / name
            if candidate.is_symlink():
                skipped["symlink"] += 1
            elif name not in SKIP_DIRS:
                safe_dirs.append(name)
        directories[:] = safe_dirs
        for name in sorted(names):
            file = Path(directory) / name
            relative = file.relative_to(root).as_posix()
            if file.is_symlink():
                skipped["symlink"] += 1
                continue
            if not (_scannable(file) or file.suffix == ".lock" or name.startswith("Dockerfile") or name in {"Gemfile", "go.mod", "go.sum", "Pipfile"}):
                skipped["unsupported"] += 1
                continue
            try:
                metadata = file.stat()
                if not stat.S_ISREG(metadata.st_mode):
                    skipped["unsupported"] += 1
                    continue
                size = metadata.st_size
                if size > MAX_FILE_BYTES:
                    skipped["large"] += 1
                    continue
                if len(files) >= MAX_FILES or total + size > MAX_BYTES:
                    skipped["budget"] += 1
                    continue
                # O_NOFOLLOW rejects a last-component symlink replaced after enumeration.
                descriptor = os.open(file, os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0))
                with os.fdopen(descriptor, "rb") as stream:
                    data = stream.read(MAX_FILE_BYTES + 1)
                if len(data) > MAX_FILE_BYTES or b"\x00" in data:
                    skipped["large" if len(data) > MAX_FILE_BYTES else "unsupported"] += 1
                    continue
                files[relative] = data
                total += len(data)
            except OSError:
                skipped["unreadable"] += 1
    binding = {"repository": str(root), "branch": git(root, "branch", "--show-current") or "unknown",
               "commit": git(root, "rev-parse", "HEAD") or "unknown", "contentDigest": content_digest(files)}
    coverage = {"files": len(files), "bytes": total, "skipped": skipped,
                "excludedDirectories": sorted(SKIP_DIRS), "maxFileBytes": MAX_FILE_BYTES,
                "maxFiles": MAX_FILES, "maxBytes": MAX_BYTES,
                "scope": "Current supported text files; no git history, runtime, or exploit verification"}
    return binding, files, coverage


def safe_file(root: Path, relative: str) -> Path:
    if not isinstance(relative, str) or not relative or "\\" in relative or "\x00" in relative:
        raise ScannerError("Invalid repository-relative path")
    parts = relative.split("/")
    if any(part in {"", ".", ".."} for part in parts) or Path(relative).is_absolute():
        raise ScannerError("The file must stay within the repository")
    candidate = root
    for part in parts:
        candidate /= part
        if candidate.is_symlink():
            raise ScannerError("Symlink paths are not eligible")
    if not candidate.is_file() or candidate.resolve().parent != candidate.parent.resolve():
        raise ScannerError("The target must be an existing regular file")
    return candidate
