"""Update LOLBAS lookup from upstream source.

Fetches latest data from lolbas-project.github.io and regenerates
the lookups/lolbas_binaries.csv file.

Usage:
    python scripts/update_lolbas.py
"""

import csv
import os
import sys
from pathlib import Path

import requests
import urllib3

urllib3.disable_warnings()

LOLBAS_API_URL = "https://lolbas-project.github.io/api/lolbas.json"
OUTPUT_PATH = Path(__file__).parent.parent / "lookups" / "lolbas_binaries.csv"

HIGH_RISK_CATEGORIES = {"Execute", "AWL Bypass", "UAC Bypass", "Credentials"}
MEDIUM_RISK_CATEGORIES = {"Download", "Upload", "Compile"}


def fetch_lolbas_data() -> list[dict]:
    """Fetch LOLBAS JSON from the project API."""
    print(f"Fetching data from {LOLBAS_API_URL}...")
    r = requests.get(LOLBAS_API_URL, timeout=30, verify=False)
    r.raise_for_status()
    data = r.json()
    print(f"Fetched {len(data)} entries.")
    return data


def compute_risk(categories: set[str]) -> str:
    """Determine risk level based on abuse categories."""
    if categories & HIGH_RISK_CATEGORIES:
        return "high"
    elif categories & MEDIUM_RISK_CATEGORIES:
        return "medium"
    return "low"


def transform_entries(data: list[dict]) -> list[dict]:
    """Transform raw LOLBAS JSON into CSV rows."""
    rows = []
    for entry in data:
        name = entry["Name"]
        desc = entry.get("Description", "")

        categories = set()
        mitre_ids = set()
        for cmd in entry.get("Commands", []):
            cat = cmd.get("Category", "")
            mid = cmd.get("MitreID", "")
            if cat:
                categories.add(cat)
            if mid:
                mitre_ids.add(mid)

        paths = [p.get("Path", "") for p in entry.get("Full_Path", [])]
        primary_path = paths[0] if paths else ""

        rows.append({
            "filename": name.lower(),
            "binary_name": name,
            "primary_path": primary_path,
            "categories": "|".join(sorted(categories)),
            "mitre_ids": "|".join(sorted(mitre_ids)),
            "risk": compute_risk(categories),
            "description": desc.replace(",", ";"),
        })

    rows.sort(key=lambda x: x["filename"])
    return rows


def write_csv(rows: list[dict]) -> None:
    """Write rows to CSV file."""
    fieldnames = ["filename", "binary_name", "primary_path", "categories", "mitre_ids", "risk", "description"]
    OUTPUT_PATH.parent.mkdir(parents=True, exist_ok=True)

    with open(OUTPUT_PATH, "w", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(f, fieldnames=fieldnames)
        writer.writeheader()
        writer.writerows(rows)

    print(f"Written {len(rows)} entries to {OUTPUT_PATH}")


def main():
    data = fetch_lolbas_data()
    rows = transform_entries(data)
    write_csv(rows)
    print("Done.")


if __name__ == "__main__":
    main()
