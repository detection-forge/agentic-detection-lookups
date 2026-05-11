"""Detection Lookups MCP Server.

Machine-readable detection lookup tables exposed as MCP tools.
Agents can query LOLBAS binaries (Windows), GTFOBins (Linux),
process parent-child baselines, and more without embedding data in prompts.
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
        "Security detection lookup tools. Use detection_lookup_binary to check if a "
        "Windows/Linux binary is a known LOLBAS or GTFOBins living-off-the-land binary. "
        "Use detection_check_parent_child to determine if a process parent-child "
        "relationship is expected or suspicious. Use detection_list_by_category or "
        "detection_list_by_mitre to find binaries by attack category or MITRE technique. "
        "Use detection_search for freeform text search across all data. "
        "Use detection_list_lookups to see available lookup files."
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
_gtfobins_cache: list[dict[str, str]] | None = None


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


def _get_gtfobins() -> list[dict[str, str]]:
    global _gtfobins_cache
    if _gtfobins_cache is None:
        _gtfobins_cache = _load_csv("gtfobins.csv")
    return _gtfobins_cache


@mcp.tool(
    annotations={
        "title": "Lookup Binary",
        "readOnlyHint": True,
        "destructiveHint": False,
        "idempotentHint": True,
        "openWorldHint": False,
    },
)
def detection_lookup_binary(filename: str) -> dict[str, Any]:
    """Check if a binary is a known LOLBAS (Windows) or GTFOBins (Linux) living-off-the-land binary.

    Provide the filename (e.g., 'certutil.exe', 'curl', 'python').
    Returns risk level, abuse categories, MITRE ATT&CK technique IDs, description, and source.
    Searches both LOLBAS (Windows) and GTFOBins (Linux) datasets.
    If not found in either, returns {found: false} with a suggestion.
    """
    filename_lower = filename.lower().strip()
    # Strip path if provided
    if "\\" in filename_lower or "/" in filename_lower:
        filename_lower = filename_lower.replace("\\", "/").split("/")[-1]

    results = []

    # Search LOLBAS (Windows)
    for row in _get_lolbas():
        if row.get("filename", "").lower() == filename_lower:
            results.append({
                "source": "lolbas",
                "binary_name": row.get("binary_name", ""),
                "primary_path": row.get("primary_path", ""),
                "categories": row.get("categories", "").split("|") if row.get("categories") else [],
                "mitre_ids": row.get("mitre_ids", "").split("|") if row.get("mitre_ids") else [],
                "risk": row.get("risk", ""),
                "description": row.get("description", ""),
            })

    # Search GTFOBins (Linux)
    for row in _get_gtfobins():
        if row.get("filename", "").lower() == filename_lower:
            results.append({
                "source": "gtfobins",
                "binary_name": row.get("binary_name", ""),
                "primary_path": row.get("primary_path", ""),
                "categories": row.get("categories", "").split("|") if row.get("categories") else [],
                "mitre_ids": row.get("mitre_ids", "").split("|") if row.get("mitre_ids") else [],
                "risk": row.get("risk", ""),
                "description": row.get("description", ""),
            })

    if not results:
        return {
            "found": False,
            "filename": filename_lower,
            "suggestion": (
                "Binary not in LOLBAS or GTFOBins datasets. "
                "Try without the file extension (e.g., 'notepad' instead of 'notepad.exe'), "
                "or use detection_search to search by keyword."
            ),
        }

    # If found in one source, return that; if both, return all matches
    if len(results) == 1:
        return {"found": True, **results[0]}
    return {"found": True, "matches": results}


@mcp.tool(
    annotations={
        "title": "Check Parent-Child Process",
        "readOnlyHint": True,
        "destructiveHint": False,
        "idempotentHint": True,
        "openWorldHint": False,
    },
)
def detection_check_parent_child(
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
            "assessment": (
                "No baseline entry found. This may be suspicious — "
                "undocumented parent-child relationships warrant investigation."
            ),
            "suggestion": (
                "Try checking each process individually with "
                "detection_lookup_binary to see if either is a known LOLBin."
            ),
        }

    # Return most specific match (prefer exact child over wildcard)
    best = sorted(matches, key=lambda m: (m["child"] == "*", m["expected"] == "true"))
    return {"found": True, "matches": best}


@mcp.tool(
    annotations={
        "title": "List Binaries by Category",
        "readOnlyHint": True,
        "destructiveHint": False,
        "idempotentHint": True,
        "openWorldHint": False,
    },
)
def detection_list_by_category(
    category: str,
    limit: int = 50,
    offset: int = 0,
) -> dict[str, Any]:
    """List all binaries in a specific abuse category.

    LOLBAS categories: Execute, Download, Upload, AWL Bypass, UAC Bypass,
    Compile, Credentials, Dump, Encode, Reconnaissance.
    GTFOBins categories: shell, reverse-shell, bind-shell, file-read, file-write,
    download, upload, library-load, command, inherit, privilege-escalation.

    Supports pagination via limit (default 50) and offset (default 0).
    """
    category_lower = category.lower().strip()
    all_results = []

    # Search LOLBAS
    for row in _get_lolbas():
        categories = [c.lower() for c in row.get("categories", "").split("|") if c]
        if category_lower in categories:
            all_results.append({
                "source": "lolbas",
                "filename": row.get("filename", ""),
                "binary_name": row.get("binary_name", ""),
                "risk": row.get("risk", ""),
                "mitre_ids": row.get("mitre_ids", ""),
            })

    # Search GTFOBins
    for row in _get_gtfobins():
        categories = [c.lower() for c in row.get("categories", "").split("|") if c]
        if category_lower in categories:
            all_results.append({
                "source": "gtfobins",
                "filename": row.get("filename", ""),
                "binary_name": row.get("binary_name", ""),
                "risk": row.get("risk", ""),
                "mitre_ids": row.get("mitre_ids", ""),
            })

    total = len(all_results)
    page = all_results[offset : offset + limit]

    response: dict[str, Any] = {
        "category": category,
        "total": total,
        "count": len(page),
        "offset": offset,
        "has_more": (offset + limit) < total,
        "binaries": page,
    }

    if total == 0:
        response["suggestion"] = (
            "Category not found. "
            "LOLBAS categories: Execute, Download, Upload, AWL Bypass, Credentials. "
            "GTFOBins categories: shell, reverse-shell, file-read, file-write, download, upload. "
            "Use detection_list_lookups to see all available data."
        )

    return response


@mcp.tool(
    annotations={
        "title": "List Binaries by MITRE Technique",
        "readOnlyHint": True,
        "destructiveHint": False,
        "idempotentHint": True,
        "openWorldHint": False,
    },
)
def detection_list_by_mitre(
    technique_id: str,
    limit: int = 50,
    offset: int = 0,
) -> dict[str, Any]:
    """List all binaries (LOLBAS + GTFOBins) mapped to a specific MITRE ATT&CK technique.

    Provide a technique ID like 'T1218', 'T1059.001', 'T1105', etc.
    Searching a parent technique (e.g., T1218) also returns sub-techniques (T1218.011).
    Supports pagination via limit (default 50) and offset (default 0).
    """
    tid = technique_id.upper().strip()
    all_results = []

    # Search LOLBAS
    for row in _get_lolbas():
        mitre_ids = [m.upper() for m in row.get("mitre_ids", "").split("|") if m]
        if any(m == tid or m.startswith(tid + ".") for m in mitre_ids):
            all_results.append({
                "source": "lolbas",
                "filename": row.get("filename", ""),
                "binary_name": row.get("binary_name", ""),
                "categories": row.get("categories", ""),
                "risk": row.get("risk", ""),
            })

    # Search GTFOBins
    for row in _get_gtfobins():
        mitre_ids = [m.upper() for m in row.get("mitre_ids", "").split("|") if m]
        if any(m == tid or m.startswith(tid + ".") for m in mitre_ids):
            all_results.append({
                "source": "gtfobins",
                "filename": row.get("filename", ""),
                "binary_name": row.get("binary_name", ""),
                "categories": row.get("categories", ""),
                "risk": row.get("risk", ""),
            })

    total = len(all_results)
    page = all_results[offset : offset + limit]

    response: dict[str, Any] = {
        "technique_id": tid,
        "total": total,
        "count": len(page),
        "offset": offset,
        "has_more": (offset + limit) < total,
        "binaries": page,
    }

    if total == 0:
        response["suggestion"] = (
            "No binaries mapped to this technique. "
            "Common techniques: T1059 (Command Execution), T1218 (Signed Binary Proxy), "
            "T1105 (Ingress Tool Transfer), T1548 (Abuse Elevation). "
            "Try a parent technique without the sub-ID (e.g., T1059 instead of T1059.009)."
        )

    return response


@mcp.tool(
    annotations={
        "title": "Search Lookups",
        "readOnlyHint": True,
        "destructiveHint": False,
        "idempotentHint": True,
        "openWorldHint": False,
    },
)
def detection_search(query: str, limit: int = 20) -> dict[str, Any]:
    """Search across all lookup files for a text match.

    Searches filename, description, categories, MITRE IDs, and notes fields
    across LOLBAS, GTFOBins, and parent-child baselines.
    Returns up to `limit` results (default 20).
    """
    query_lower = query.lower().strip()
    if not query_lower:
        return {
            "error": "Query must not be empty",
            "suggestion": "Provide a search term such as a binary name, MITRE ID, or keyword.",
        }

    results = []
    total_matches = 0

    # Search LOLBAS
    for row in _get_lolbas():
        searchable = " ".join(row.values()).lower()
        if query_lower in searchable:
            total_matches += 1
            if len(results) < limit:
                results.append({
                    "source": "lolbas_binaries",
                    "filename": row.get("filename", ""),
                    "match_context": row.get("description", ""),
                    "risk": row.get("risk", ""),
                })

    # Search GTFOBins
    for row in _get_gtfobins():
        searchable = " ".join(row.values()).lower()
        if query_lower in searchable:
            total_matches += 1
            if len(results) < limit:
                results.append({
                    "source": "gtfobins",
                    "filename": row.get("filename", ""),
                    "match_context": row.get("description", ""),
                    "risk": row.get("risk", ""),
                })

    # Search parent-child baselines
    for row in _get_parent_child():
        searchable = " ".join(row.values()).lower()
        if query_lower in searchable:
            total_matches += 1
            if len(results) < limit:
                results.append({
                    "source": "parent_child_baselines",
                    "parent": row.get("parent", ""),
                    "child": row.get("child", ""),
                    "notes": row.get("notes", ""),
                    "risk_if_unexpected": row.get("risk_if_unexpected", ""),
                })

    response: dict[str, Any] = {
        "query": query,
        "total": total_matches,
        "count": len(results),
        "has_more": total_matches > limit,
        "results": results,
    }

    if total_matches == 0:
        response["suggestion"] = (
            "No matches found. Try a broader term, a MITRE technique ID (e.g., T1059), "
            "or a category name (e.g., shell, Download)."
        )

    return response


@mcp.tool(
    annotations={
        "title": "List Available Lookups",
        "readOnlyHint": True,
        "destructiveHint": False,
        "idempotentHint": True,
        "openWorldHint": False,
    },
)
def detection_list_lookups() -> dict[str, Any]:
    """List all available lookup files and their metadata (row counts, columns).

    Use this tool to discover what datasets are available before querying.
    """
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
