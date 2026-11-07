"""A tiny deterministic edit allowlist, bound to the reviewed snapshot.

No model output or user-supplied replacement text is executed. Validation parses
Python without importing the repository. Unknown fixes remain advisory.
"""

from __future__ import annotations

import ast
import hashlib
import os
import re
import stat
import secrets
from pathlib import Path

from .snapshot import ScannerError, safe_file, snapshot, content_digest
from .normalize import redacted

RULE = "TL-DEBUG-ENABLED"
DEBUG_ASSIGNMENT = re.compile(r"^(DEBUG\s*=\s*)True(\s*(?:#.*)?)(\r?\n)?$")
PROTECTED = {".git", ".github", ".gitlab", ".circleci", ".codex", ".claude", ".agents"}


def protected(path: str) -> bool:
    parts = path.lower().split("/")
    return any(part in PROTECTED or part.startswith(".env") or any(word in part for word in ("secret", "credential"))
               for part in parts) or parts[-1] in {"agents.md", "jenkinsfile"} or Path(path).suffix.lower() in {".pem", ".key", ".p12", ".pfx"}


def _replacement(item: dict, files: dict[str, bytes]) -> tuple[bytes, bytes] | None:
    path = item.get("path", "")
    if item.get("source") != "guard" or item.get("ruleId") != RULE or not path.endswith(".py") or protected(path):
        return None
    before = files.get(path)
    if before is None:
        return None
    try:
        text = before.decode("utf-8")
        tree = ast.parse(text)
        lines = text.splitlines(keepends=True)
        index = int(item.get("line", 0)) - 1
        if not 0 <= index < len(lines) or not DEBUG_ASSIGNMENT.fullmatch(lines[index]):
            return None
        if redacted(lines[index].rstrip("\r\n")) != lines[index].rstrip("\r\n"):
            return None  # Never send a secret-bearing edit to a browser, artifact, or suggestion.
        # Only a real module-level assignment, never a docstring or nested source fragment.
        if not any(isinstance(node, ast.Assign) and node.lineno == index + 1 and len(node.targets) == 1
                   and isinstance(node.targets[0], ast.Name) and node.targets[0].id == "DEBUG"
                   and isinstance(node.value, ast.Constant) and node.value.value is True for node in tree.body):
            return None
        lines[index] = DEBUG_ASSIGNMENT.sub(lambda match: match[1] + "False" + match[2] + (match[3] or ""), lines[index])
        after = "".join(lines).encode("utf-8")
        ast.parse(after.decode("utf-8"))
        return before, after
    except (ValueError, UnicodeError, SyntaxError):
        return None


def eligible(item: dict, files: dict[str, bytes]) -> bool:
    return _replacement(item, files) is not None


def propose_fix(report: dict, finding_id: str) -> dict:
    binding = report.get("binding", {})
    current, files, _coverage = snapshot(binding.get("repository", ""))
    if current != binding:
        raise ScannerError("Repository, branch, commit, or current content changed; scan again before proposing a fix")
    item = next((item for item in report.get("findings", []) if item["id"] == finding_id), None)
    edit = _replacement(item or {}, files)
    if not edit:
        raise ScannerError("This finding has no eligible deterministic fix; follow the advisory recommendation")
    before, after = edit
    line = item["line"]
    return {"schemaVersion": 1, "binding": binding, "findingId": finding_id, "ruleId": RULE, "path": item["path"],
            "line": line, "beforeSha256": hashlib.sha256(before).hexdigest(), "afterSha256": hashlib.sha256(after).hexdigest(),
            "before": before.decode("utf-8").splitlines()[line - 1], "after": after.decode("utf-8").splitlines()[line - 1],
            "description": "Disable the module-level DEBUG setting. Review the runtime behavior before applying.",
            "validation": "Python syntax parsing and a fresh baseline security scan; application tests are not run.",
            "status": "proposed", "requiresReview": True}


def _replace(root: Path, relative: str, data: bytes, expected: bytes) -> None:
    # Anchor traversal and replacement to open directories; parent symlink swaps
    # cannot redirect the write outside the reviewed checkout.
    if os.open not in os.supports_dir_fd or os.rename not in os.supports_dir_fd or not hasattr(os, "O_NOFOLLOW"):
        raise ScannerError("Safe directory-relative replacement is unavailable on this platform; apply the reviewed diff manually")
    safe_file(root, relative)
    descriptor = os.open(root, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
    temporary = ".threatlint-fix-" + secrets.token_hex(12)
    name = relative.split("/")[-1]
    try:
        for part in relative.split("/")[:-1]:
            child = os.open(part, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=descriptor)
            os.close(descriptor)
            descriptor = child
        original = os.open(name, os.O_RDONLY | os.O_NOFOLLOW, dir_fd=descriptor)
        with os.fdopen(original, "rb") as stream:
            metadata = os.fstat(stream.fileno())
            if not stat.S_ISREG(metadata.st_mode) or stream.read(len(expected) + 1) != expected:
                raise ScannerError("File changed during validation; nothing was overwritten")
        output = os.open(temporary, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW,
                         stat.S_IMODE(metadata.st_mode), dir_fd=descriptor)
        with os.fdopen(output, "wb") as stream:
            os.fchmod(stream.fileno(), stat.S_IMODE(metadata.st_mode))
            stream.write(data)
            stream.flush()
            os.fsync(stream.fileno())
        current = os.stat(name, dir_fd=descriptor, follow_symlinks=False)
        if (current.st_dev, current.st_ino, current.st_mtime_ns, current.st_size) != (metadata.st_dev, metadata.st_ino, metadata.st_mtime_ns, metadata.st_size):
            raise ScannerError("File changed before replacement")
        os.replace(temporary, name, src_dir_fd=descriptor, dst_dir_fd=descriptor)
    finally:
        try:
            os.unlink(temporary, dir_fd=descriptor)
        except FileNotFoundError:
            pass
        os.close(descriptor)


def apply_fix(plan: dict, *, confirm=False, policy=None, scan=None) -> dict:
    from .scan import scan_repository
    scan = scan or scan_repository
    policy = policy or {}
    auto = policy.get("autoApply") is True and plan.get("ruleId") in policy.get("rules", [])
    if confirm is not True and not auto:
        raise ScannerError("Review and explicitly confirm this fix, or opt in to its specific auto-apply rule")
    repository = plan.get("binding", {}).get("repository", "")
    report = scan_repository(repository)
    canonical = propose_fix(report, plan.get("findingId", ""))
    # Compare every signed-by-construction field; the browser cannot supply arbitrary edits.
    if any(plan.get(key) != canonical[key] for key in canonical):
        raise ScannerError("Fix plan is stale or modified; generate a new proposal")
    root = Path(repository).resolve()
    safe_file(root, canonical["path"])
    _binding, files, _coverage = snapshot(repository)
    if _binding != canonical["binding"]:
        raise ScannerError("The repository changed during fix validation")
    item = next(item for item in report["findings"] if item["id"] == canonical["findingId"])
    before, after = _replacement(item, files)
    try:
        _replace(root, canonical["path"], after, before)
        rescanned = scan(repository)
        expected_binding = {**canonical["binding"], "contentDigest": content_digest({**files, canonical["path"]: after})}
        final_binding, _final_files, _coverage = snapshot(repository)
        if rescanned.get("binding") != expected_binding or final_binding != expected_binding:
            raise ScannerError("Repository changed during fix validation")
        if any(item["id"] == plan["findingId"] for item in rescanned.get("findings", [])):
            raise ScannerError("The finding remains after the edit")
    except BaseException:
        file = safe_file(root, canonical["path"])
        current = file.read_bytes()
        if current == after:
            _replace(root, canonical["path"], before, after)
        elif current != before:
            raise ScannerError("Fix validation was interrupted and the file changed concurrently; inspect it and rescan") from None
        raise ScannerError("Rescan did not validate the correction; the original file was restored") from None
    return {"status": "applied", "path": canonical["path"], "findingId": canonical["findingId"],
            "validation": {"syntax": "passed", "baselineRescan": "passed", "applicationTests": "not_run"},
            "scan": rescanned, "reviewRequiredBeforeMerge": True, "autoApplied": auto and confirm is not True}
