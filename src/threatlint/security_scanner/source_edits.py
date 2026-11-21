"""Small, syntax-aware source transformations; never interpret replacement code.

These change security-relevant behavior and need review or a specific opted-in
rule. Import checks establish static provenance only, not runtime equivalence.
"""

from __future__ import annotations

import ast
import re

DEBUG_ASSIGNMENT = re.compile(r"^(DEBUG\s*=\s*)True(\s*(?:#.*)?)(\r?\n)?$")
RULES = {
    "TL-DEBUG-ENABLED": "Disable the module-level DEBUG setting. Review production configuration before applying.",
    "TL-PY-YAML": "Use PyYAML's safe loader for data. Custom Python object tags will be rejected; review compatibility before applying.",
    "TL-TLS-VERIFY-OFF": "Enable certificate verification for this requests call. Configure a trusted private CA if needed; review connectivity before applying.",
}
REQUEST_METHODS = {"request", "get", "post", "put", "patch", "delete", "head", "options"}
YAML_METHODS = {"load": "safe_load", "unsafe_load": "safe_load", "load_all": "safe_load_all"}
YAML_LOADERS = {"Loader": "SafeLoader", "UnsafeLoader": "SafeLoader", "CLoader": "CSafeLoader", "CUnsafeLoader": "CSafeLoader"}
NAMED_BINDINGS = tuple(getattr(ast, name) for name in
                       ("FunctionDef", "AsyncFunctionDef", "ClassDef", "ExceptHandler", "MatchAs", "MatchStar") if hasattr(ast, name))


def _unshadowed_import(tree: ast.Module, module: str, line: int) -> bool:
    imports = [(node, alias) for node in ast.walk(tree) if isinstance(node, ast.Import)
               for alias in node.names if (alias.asname or alias.name.split(".")[0]) == module]
    if len(imports) != 1 or imports[0][0] not in tree.body or imports[0][0].lineno >= line or imports[0][1].name != module:
        return False
    for node in ast.walk(tree):
        if isinstance(node, ast.ImportFrom) and any(alias.name == "*" or (alias.asname or alias.name) == module for alias in node.names):
            return False
        if isinstance(node, ast.Name) and node.id == module and isinstance(node.ctx, (ast.Store, ast.Del)):
            return False
        if isinstance(node, NAMED_BINDINGS) and node.name == module:
            return False
        if isinstance(node, getattr(ast, "MatchMapping", ())) and node.rest == module:
            return False
        if isinstance(node, ast.arg) and node.arg == module:
            return False
        if isinstance(node, (ast.Attribute, ast.Subscript)) and isinstance(node.ctx, (ast.Store, ast.Del)):
            owner = node.value
            while isinstance(owner, (ast.Attribute, ast.Subscript)):
                owner = owner.value
            if isinstance(owner, ast.Name) and owner.id == module:
                return False
        if isinstance(node, ast.Call) and isinstance(node.func, ast.Name) and node.func.id in {"setattr", "delattr"} and node.args:
            if isinstance(node.args[0], ast.Name) and node.args[0].id == module:
                return False
    return True


def _call_edits(tree, rule, line):
    """Return byte-column edits only for explicit single-line, supported calls."""
    edits = []
    for node in ast.walk(tree):
        if not isinstance(node, ast.Call) or node.lineno != line or node.end_lineno != line:
            continue
        function = node.func
        if not isinstance(function, ast.Attribute) or not isinstance(function.value, ast.Name):
            continue
        if rule == "TL-PY-YAML" and function.value.id == "yaml" and function.attr in YAML_METHODS:
            if len(node.args) == 1 and not isinstance(node.args[0], ast.Starred) and not node.keywords:
                edits.append((function.end_col_offset - len(function.attr), function.end_col_offset, YAML_METHODS[function.attr]))
            elif function.attr in {"load", "load_all"} and len(node.args) == 1 and not isinstance(node.args[0], ast.Starred) and len(node.keywords) == 1 and node.keywords[0].arg == "Loader":
                loader = node.keywords[0].value
                if isinstance(loader, ast.Attribute) and isinstance(loader.value, ast.Name) and loader.value.id == "yaml" and loader.attr in YAML_LOADERS:
                    edits.append((loader.end_col_offset - len(loader.attr), loader.end_col_offset, YAML_LOADERS[loader.attr]))
        if rule == "TL-TLS-VERIFY-OFF" and function.value.id == "requests" and function.attr in REQUEST_METHODS:
            # **kwargs can override or duplicate security options; leave these advisory.
            if any(keyword.arg is None for keyword in node.keywords):
                continue
            options = [keyword for keyword in node.keywords if keyword.arg == "verify"]
            if len(options) == 1 and isinstance(options[0].value, ast.Constant) and options[0].value.value is False:
                value = options[0].value
                edits.append((value.col_offset, value.end_col_offset, "True"))
    return edits


def _edit_line(value: str, edit) -> str:
    start, end, replacement = edit
    data = value.encode("utf-8")
    return (data[:start] + replacement.encode("utf-8") + data[end:]).decode("utf-8")


def replacement(text: str, rule: str, line: int) -> str | None:
    tree = ast.parse(text)
    lines = text.splitlines(keepends=True)
    if rule not in RULES or not 1 <= line <= len(lines):
        return None
    if rule == "TL-DEBUG-ENABLED":
        match = DEBUG_ASSIGNMENT.fullmatch(lines[line - 1])
        if not match or not any(isinstance(node, ast.Assign) and node.lineno == line and len(node.targets) == 1
                                and isinstance(node.targets[0], ast.Name) and node.targets[0].id == "DEBUG"
                                and isinstance(node.value, ast.Constant) and node.value.value is True for node in tree.body):
            return None
        lines[line - 1] = match[1] + "False" + match[2] + (match[3] or "")
    else:
        module = "yaml" if rule == "TL-PY-YAML" else "requests"
        if not _unshadowed_import(tree, module, line):
            return None
        edits = _call_edits(tree, rule, line)
        if len(edits) != 1:
            return None
        lines[line - 1] = _edit_line(lines[line - 1], edits[0])
    after = "".join(lines)
    ast.parse(after)
    if not valid_line_change(rule, text.splitlines()[line - 1], after.splitlines()[line - 1]):
        return None
    return after


def valid_line_change(rule: str, before: str, after: str) -> bool:
    """Independently bound native suggestions to the same narrow transformations."""
    if rule not in RULES or any("\n" in value or "\r" in value or "```" in value for value in (before, after)):
        return False
    if rule == "TL-DEBUG-ENABLED":
        match = DEBUG_ASSIGNMENT.fullmatch(before)
        return bool(match and after == match[1] + "False" + match[2])
    try:
        stripped = before.lstrip()
        indent = before[:len(before) - len(stripped)]
        edits = _call_edits(ast.parse(stripped), rule, 1)
        return len(edits) == 1 and after == indent + _edit_line(stripped, edits[0])
    except (SyntaxError, UnicodeError, ValueError):
        return False
