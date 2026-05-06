"""Detection Lookups MCP Server.

Machine-readable detection lookup tables exposed as MCP tools.
Agents can query LOLBAS binaries, process parent-child baselines,
and more without embedding data in prompts.
"""

from __future__ import annotations

import csv
import os
from fnmatch import fnmatch
from pathlib import Path
from typing import Any

from fastmcp import FastMCP

LOOKUPS_DIR = Path(__file__).parent.parent / "lookups"

mcp = FastMCP(
    "detection-lookups",
    instructions=(
        "Security detection lookup tools. Use lookup_binary to check if a Windows/Linux "
        "binary is a known LOLBAS (Living Off The Land Binary). Use check_parent_child "
        "to determine if a process parent-child relationship is expected or suspicious. "
        "Use list_by_category or list_by_mitre to find binaries by attack category or "
        "MITRE technique. Use search_lookups for freeform text search across all data."
    ),
)


def _load_csv(filename: str) -> list[dict[str, str]]:
    """Load a CSV lookup file and return rows as list of dicts."""
    filepath = LOOKUPS_DIR / filename
    if not filepath.exists():
        return []
    with open(filepath, "r", encoding="utf-8") as f:
        return list(csv.DictReader(f))


def _match_filename(pattern: str, value: str) -> bool:
    """Match with glob support (e.g., 'tomcat*.exe')."""
    return fnmatch(value.lower(), pattern.lower())


# Cache loaded data in memory (small files, fast startup)
_lolbas_cache: list[dict[str, str]] | None = None
_parent_child_cache: list[dict[str, str]] | None = None


def _get_lolbas() -> list[dict[str, str]]:
    global _lolbas_cache
    if _lolbas_cache is None:
        _lolbas_cache = _load_csv("lolbas_binaries.csv")
    return _lolbas_cache


def _get_parent_child() -> list[dict[str, str]]:
    global _parent_child_cache
    if _parent_child_cache is None:
        _parent_child_cache = _load_csv("parent_child_baselines.csv")
    return _parent_child_cache


@mcp.tool()
def lookup_binary(filename: str) -> dict[str, Any]:
    """Check if a binary is a known LOLBAS (Living Off The Land Binary/Script/Library).

    Provide the filename (e.g., 'certutil.exe', 'mshta.exe').
    Returns risk level, abuse categories, MITRE ATT&CK technique IDs, and description.
    If not found, returns {found: false}.
    """
    filename_lower = filename.lower().strip()
    # Strip path if provided
    if "\\" in filename_lower or "/" in filename_lower:
        filename_lower = filename_lower.replace("\\", "/").split("/")[-1]

    for row in _get_lolbas():
        if row.get("filename", "").lower() == filename_lower:
            return {
                "found": True,
                "binary_name": row.get("binary_name", ""),
                "primary_path": row.get("primary_path", ""),
                "categories": row.get("categories", "").split("|") if row.get("categories") else [],
                "mitre_ids": row.get("mitre_ids", "").split("|") if row.get("mitre_ids") else [],
                "risk": row.get("risk", ""),
                "description": row.get("description", ""),
            }

    return {"found": False, "filename": filename_lower}


@mcp.tool()
def check_parent_child(
    parent: str,
    child: str,
    os_filter: str = "windows",
) -> dict[str, Any]:
    """Check if a process parent-child relationship is expected or suspicious.

    Provide parent and child process filenames (e.g., parent='winword.exe', child='cmd.exe').
    Returns whether the relationship is expected, the risk if unexpected, MITRE technique, and triage notes.
    """
    parent_lower = parent.lower().strip()
    child_lower = child.lower().strip()

    # Strip paths
    if "\\" in parent_lower or "/" in parent_lower:
        parent_lower = parent_lower.replace("\\", "/").split("/")[-1]
    if "\\" in child_lower or "/" in child_lower:
        child_lower = child_lower.replace("\\", "/").split("/")[-1]

    matches = []
    for row in _get_parent_child():
        if row.get("os", "").lower() != os_filter.lower():
            continue

        row_parent = row.get("parent", "").lower()
        row_child = row.get("child", "").lower()

        # Check parent match (exact or glob)
        parent_match = _match_filename(row_parent, parent_lower)
        # Check child match (exact, glob, or wildcard)
        child_match = row_child == "*" or _match_filename(row_child, child_lower)

        if parent_match and child_match:
            matches.append({
                "parent": row.get("parent", ""),
                "child": row.get("child", ""),
                "os": row.get("os", ""),
                "expected": row.get("expected", ""),
                "risk_if_unexpected": row.get("risk_if_unexpected", ""),
                "mitre_id": row.get("mitre_id", ""),
                "context": row.get("context", ""),
                "notes": row.get("notes", ""),
            })

    if not matches:
        return {
            "found": False,
            "parent": parent_lower,
            "child": child_lower,
            "os": os_filter,
            "assessment": "No baseline entry found. Relationship not documented — investigate based on context.",
        }

    # Return most specific match (prefer exact child over wildcard)
    best = sorted(matches, key=lambda m: (m["child"] == "*", m["expected"] == "true"))
    return {"found": True, "matches": best}


@mcp.tool()
def list_by_category(category: str) -> dict[str, Any]:
    """List all LOLBAS binaries in a specific abuse category.

    Valid categories: Execute, Download, Upload, AWL Bypass, UAC Bypass,
    Compile, Credentials, Dump, Encode, Reconnaissance.
    """
    category_lower = category.lower().strip()
    results = []
    for row in _get_lolbas():
        categories = [c.lower() for c in row.get("categories", "").split("|") if c]
        if category_lower in categories:
            results.append({
                "filename": row.get("filename", ""),
                "binary_name": row.get("binary_name", ""),
                "risk": row.get("risk", ""),
                "mitre_ids": row.get("mitre_ids", ""),
            })

    return {
        "category": category,
        "count": len(results),
        "binaries": results,
    }


@mcp.tool()
def list_by_mitre(technique_id: str) -> dict[str, Any]:
    """List all LOLBAS binaries mapped to a specific MITRE ATT&CK technique.

    Provide a technique ID like 'T1218', 'T1059.001', etc.
    """
    tid = technique_id.upper().strip()
    results = []
    for row in _get_lolbas():
        mitre_ids = [m.upper() for m in row.get("mitre_ids", "").split("|") if m]
        # Support hierarchy: T1059 matches T1059, T1059.001, T1059.003, etc.
        # T1059.001 matches only T1059.001 exactly.
        if any(m == tid or m.startswith(tid + ".") for m in mitre_ids):
            results.append({
                "filename": row.get("filename", ""),
                "binary_name": row.get("binary_name", ""),
                "categories": row.get("categories", ""),
                "risk": row.get("risk", ""),
            })

    return {
        "technique_id": tid,
        "count": len(results),
        "binaries": results,
    }


@mcp.tool()
def search_lookups(query: str, limit: int = 20) -> dict[str, Any]:
    """Search across all lookup files for a text match.

    Searches filename, description, categories, MITRE IDs, and notes fields.
    Returns up to `limit` results (default 20).
    """
    query_lower = query.lower().strip()
    if not query_lower:
        return {"error": "Query must not be empty"}

    results = []

    # Search LOLBAS
    for row in _get_lolbas():
        searchable = " ".join(row.values()).lower()
        if query_lower in searchable:
            results.append({
                "source": "lolbas_binaries",
                "filename": row.get("filename", ""),
                "match_context": row.get("description", ""),
                "risk": row.get("risk", ""),
            })
            if len(results) >= limit:
                break

    # Search parent-child baselines
    if len(results) < limit:
        for row in _get_parent_child():
            searchable = " ".join(row.values()).lower()
            if query_lower in searchable:
                results.append({
                    "source": "parent_child_baselines",
                    "parent": row.get("parent", ""),
                    "child": row.get("child", ""),
                    "notes": row.get("notes", ""),
                    "risk_if_unexpected": row.get("risk_if_unexpected", ""),
                })
                if len(results) >= limit:
                    break

    return {
        "query": query,
        "count": len(results),
        "results": results,
    }


@mcp.tool()
def list_available_lookups() -> dict[str, Any]:
    """List all available lookup files and their metadata (row counts, columns)."""
    lookups = []
    for csv_file in sorted(LOOKUPS_DIR.glob("*.csv")):
        with open(csv_file, "r", encoding="utf-8") as f:
            reader = csv.DictReader(f)
            rows = list(reader)
            lookups.append({
                "filename": csv_file.name,
                "rows": len(rows),
                "columns": reader.fieldnames or [],
            })

    return {"count": len(lookups), "lookups": lookups}


def main() -> None:
    """Run the MCP server."""
    mcp.run()


if __name__ == "__main__":
    main()
