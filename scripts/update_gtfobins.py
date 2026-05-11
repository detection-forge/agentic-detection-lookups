"""Update GTFOBins lookup from upstream source.

Fetches latest data from the GTFOBins GitHub repository and regenerates
the lookups/gtfobins.csv file.

GTFOBins is a curated list of Unix binaries that can be used to bypass
local security restrictions in misconfigured systems. This script parses
the YAML source files and produces a flat CSV for detection lookups.

Usage:
    python scripts/update_gtfobins.py

Requires:
    pip install requests pyyaml
"""

import csv
import io
import tarfile
from pathlib import Path

import requests
import yaml

GTFOBINS_TARBALL_URL = (
    "https://api.github.com/repos/GTFOBins/GTFOBins.github.io/tarball/master"
)
OUTPUT_PATH = Path(__file__).parent.parent / "lookups" / "gtfobins.csv"

# GTFOBins function types → MITRE ATT&CK technique mapping
FUNCTION_MITRE_MAP = {
    "shell": "T1059",
    "command": "T1059",
    "reverse-shell": "T1059",
    "bind-shell": "T1059",
    "non-interactive-bind-shell": "T1059",
    "non-interactive-reverse-shell": "T1059",
    "file-read": "T1005",
    "file-write": "T1565.001",
    "download": "T1105",
    "upload": "T1048",
    "sudo": "T1548.003",
    "suid": "T1548.001",
    "limited-suid": "T1548.001",
    "capabilities": "T1548",
    "library-load": "T1574.006",
    "inherit": "T1059",
    "privilege-escalation": "T1548",
}

HIGH_RISK_FUNCTIONS = {
    "sudo",
    "suid",
    "limited-suid",
    "capabilities",
    "reverse-shell",
    "bind-shell",
    "library-load",
    "privilege-escalation",
}
MEDIUM_RISK_FUNCTIONS = {
    "shell",
    "command",
    "file-write",
    "download",
    "upload",
    "non-interactive-bind-shell",
    "non-interactive-reverse-shell",
    "inherit",
}


def fetch_gtfobins_data() -> dict[str, dict]:
    """Fetch GTFOBins YAML files from the GitHub tarball (one HTTP call)."""
    print(f"Fetching tarball from {GTFOBINS_TARBALL_URL}...")
    headers = {"Accept": "application/vnd.github+json"}
    r = requests.get(GTFOBINS_TARBALL_URL, timeout=120, headers=headers)
    r.raise_for_status()

    entries: dict[str, dict] = {}
    with tarfile.open(fileobj=io.BytesIO(r.content), mode="r:gz") as tar:
        for member in tar.getmembers():
            parts = member.name.split("/")
            # Match files under _gtfobins/ directory
            if len(parts) >= 3 and parts[-2] == "_gtfobins" and member.isfile():
                binary_name = parts[-1]
                f = tar.extractfile(member)
                if f:
                    content = f.read().decode("utf-8")
                    try:
                        docs = list(yaml.safe_load_all(content))
                        if docs and docs[0]:
                            entries[binary_name] = docs[0]
                    except yaml.YAMLError:
                        print(f"  Warning: failed to parse {binary_name}")

    print(f"Parsed {len(entries)} GTFOBins entries.")
    return entries


def resolve_aliases(entries: dict[str, dict]) -> dict[str, dict]:
    """Resolve alias entries to their target's functions."""
    resolved = {}
    aliases = {}

    for name, data in entries.items():
        if "alias" in data:
            aliases[name] = data["alias"]
        else:
            resolved[name] = data

    # Resolve aliases — alias binary gets the same data as its target
    for alias_name, target_name in aliases.items():
        if target_name in resolved:
            resolved[alias_name] = resolved[target_name]
        else:
            print(f"  Warning: alias '{alias_name}' -> '{target_name}' (target not found)")

    return resolved


def extract_categories(data: dict) -> set[str]:
    """Extract function types from a GTFOBins entry.

    Returns the set of function types (top-level keys under 'functions'),
    e.g., shell, file-read, file-write, download, upload, library-load.
    Contexts (sudo, suid, capabilities) are not included as categories —
    they describe privilege conditions, not capabilities.
    """
    functions_data = data.get("functions", {})
    if not functions_data:
        return set()

    return set(functions_data.keys())


def compute_risk(categories: set[str]) -> str:
    """Determine risk level based on GTFOBins function types."""
    if categories & HIGH_RISK_FUNCTIONS:
        return "high"
    elif categories & MEDIUM_RISK_FUNCTIONS:
        return "medium"
    return "low"


def compute_mitre_ids(categories: set[str]) -> set[str]:
    """Map function types to MITRE ATT&CK technique IDs."""
    mitre_ids = set()
    for cat in categories:
        if cat in FUNCTION_MITRE_MAP:
            mitre_ids.add(FUNCTION_MITRE_MAP[cat])
    return mitre_ids


def transform_entries(entries: dict[str, dict]) -> list[dict]:
    """Transform parsed GTFOBins data into CSV rows."""
    rows = []
    for name, data in entries.items():
        categories = extract_categories(data)
        if not categories:
            continue

        mitre_ids = compute_mitre_ids(categories)
        risk = compute_risk(categories)

        # Build human-readable description
        func_types = sorted(categories)
        description = f"GTFOBins: {name} can be used for {'; '.join(func_types)}"

        rows.append({
            "filename": name.lower(),
            "binary_name": name,
            "primary_path": f"/usr/bin/{name}",
            "categories": "|".join(sorted(categories)),
            "mitre_ids": "|".join(sorted(mitre_ids)),
            "risk": risk,
            "description": description,
        })

    rows.sort(key=lambda x: x["filename"])
    return rows


def write_csv(rows: list[dict]) -> None:
    """Write rows to CSV file."""
    fieldnames = [
        "filename",
        "binary_name",
        "primary_path",
        "categories",
        "mitre_ids",
        "risk",
        "description",
    ]
    OUTPUT_PATH.parent.mkdir(parents=True, exist_ok=True)

    with open(OUTPUT_PATH, "w", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(f, fieldnames=fieldnames)
        writer.writeheader()
        writer.writerows(rows)

    print(f"Written {len(rows)} entries to {OUTPUT_PATH}")


def main():
    entries = fetch_gtfobins_data()
    resolved = resolve_aliases(entries)
    rows = transform_entries(resolved)
    write_csv(rows)

    # Summary stats
    risk_counts = {}
    for row in rows:
        risk_counts[row["risk"]] = risk_counts.get(row["risk"], 0) + 1
    print(f"\nRisk distribution: {risk_counts}")
    print("Done.")


if __name__ == "__main__":
    main()
