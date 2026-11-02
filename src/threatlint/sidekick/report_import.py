"""Pure workbook-table validation and normalization, separate from import storage."""

from __future__ import annotations

import re
from collections.abc import Callable, Sequence

from threatlint.sidekick.clients import SidekickError

ALIASES = {"repo": "repository", "org": "organization", "secrets": "open_secrets", "open_secrets": "open_secrets",
           "manager": "repo_manager", "repo_manager": "repo_manager"}


def normalize_header(header) -> str:
    return re.sub(r"^_+|_+$", "", re.sub(r"[\s-]+", "_", str(header or "").strip().lower()))


def import_columns(table: list[list], *, aliases: dict[str, str] = ALIASES,
                   normalize: Callable = normalize_header) -> list[str]:
    """Validate the workbook shape and map its human-readable headers to row fields."""
    if len(table) < 2:
        raise SidekickError("The workbook has a header but no rows")
    columns = [aliases.get(normalize(header), normalize(header)) for header in table[0]]
    if "repository" not in columns or "project" not in columns:
        raise SidekickError("The workbook needs repository and project columns")
    return columns


def import_rows(raw_rows: list[list], columns: list[str], default_org: str, metrics: Sequence[str]) -> list[dict]:
    """Normalize ragged rows, skipping incomplete identities and retaining unknown metrics as None."""
    rows = []
    for raw in raw_rows:
        record = {columns[i]: raw[i] for i in range(min(len(columns), len(raw)))}
        if not record.get("repository") or not record.get("project"):
            continue
        row = {"repository": str(record["repository"]), "project": str(record["project"]),
               "organization": str(record.get("organization") or default_org), "status": "complete",
               "repo_manager": record.get("repo_manager") or "", "director": record.get("director") or ""}
        for metric in metrics:
            value = record.get(metric)
            try:
                row[metric] = int(float(value)) if value not in (None, "") else None
            except (TypeError, ValueError):
                row[metric] = None
        rows.append(row)
    if not rows:
        raise SidekickError("No rows with a repository and project")
    return rows
