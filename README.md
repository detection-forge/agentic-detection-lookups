# Agentic Detection Lookups

Machine-readable detection lookups for SIEM enrichment and AI agents. MCP-native.

> Stop regex-matching 200+ binaries. Enrich in one `match()` call.  
> Feed it to your SIEM, your SOAR, your agent, or your LLM.

## What is this?

A collection of structured CSV lookup files purpose-built for:
- **SIEM enrichment** — one `match()`/`lookup`/`join` replaces entire rule categories
- **AI agent tooling** — MCP server included, agents query detection context in real-time
- **Detection automation** — consistent schema, CI-updated, deploy-ready

## Lookup Files

| File | Entries | Description |
|------|---------|-------------|
| [`lolbas_binaries.csv`](lookups/lolbas_binaries.csv) | 232 | Living Off The Land Binaries and Scripts — risk-scored, categorized, MITRE-mapped |
| [`parent_child_baselines.csv`](lookups/parent_child_baselines.csv) | 97 | Expected/suspicious process parent→child relationships for Windows and Linux |

### Schema Contract

Every lookup file follows:
1. First column = **match key** (the field you join on)
2. Always includes `risk` or `risk_if_unexpected` column
3. Always includes MITRE ATT&CK technique mapping
4. No nested data — flat columns, pipe-delimited for multi-value
5. UTF-8, no BOM, Unix line endings, header row always present

## Quick Start

### SIEM (copy-paste)

**CrowdStrike NG-SIEM:**
```cql
#event_simpleName=ProcessRollup2
| binary := lower(FileName)
| match(file="lolbas_binaries.csv", field=binary, column=filename, include=[categories, mitre_ids, risk])
| risk="high"
```

**Splunk:**
```spl
index=crowdstrike event_simpleName=ProcessRollup2
| rex field=FileName "(?<binary>[^\\\\]+)$"
| lookup lolbas_binaries.csv filename AS binary OUTPUT categories mitre_ids risk
| where risk="high"
```

**Elastic (ES|QL):**
```esql
FROM logs-endpoint.events.process-*
| WHERE event.action == "start"
| ENRICH lolbas-policy ON process.name = filename WITH categories, risk
| WHERE risk == "high"
```

**Microsoft Sentinel:**
```kql
DeviceProcessEvents
| extend binary = tolower(FileName)
| join kind=inner (_GetWatchlist('lolbas_binaries')) on $left.binary == $right.filename
| where risk == "high"
```

See [`queries/`](queries/) for full query libraries per platform.

### MCP Server (AI agents)

```json
{
  "servers": {
    "detection-lookups": {
      "type": "stdio",
      "command": "python",
      "args": ["-m", "mcp_server"],
      "cwd": "/path/to/agentic-detection-lookups"
    }
  }
}
```

Then your agent can:
```
→ lookup_binary("certutil.exe")
← {risk: "medium", categories: ["Download"], mitre_ids: ["T1105"]}

→ check_parent_child("winword.exe", "cmd.exe")
← {expected: false, risk_if_unexpected: "critical", mitre_id: "T1204.002"}
```

## MCP Tools

| Tool | Input | Output |
|------|-------|--------|
| `lookup_binary` | filename | Risk, categories, MITRE IDs, description |
| `check_parent_child` | parent, child | Expected/suspicious, risk level, triage guidance |
| `list_by_category` | category name | All binaries in that abuse category |
| `list_by_mitre` | technique ID | All binaries mapped to that technique |
| `search_lookups` | free text | Matches across all lookup data |
| `list_available_lookups` | — | All files with row counts and columns |

## Data Sources

| Lookup | Source | Update Frequency |
|--------|--------|-----------------|
| LOLBAS binaries | [LOLBAS Project](https://lolbas-project.github.io) | Weekly (automated) |
| Parent-child baselines | MITRE ATT&CK, SANS, Microsoft docs, public threat reports | Manual curation |

## Installation

### Prerequisites
- Python 3.10+
- VS Code with GitHub Copilot (for MCP integration)

### Install

```bash
git clone https://github.com/detection-forge/agentic-detection-lookups.git
cd agentic-detection-lookups
python -m venv .venv
# Windows:
.venv\Scripts\activate
# Linux/macOS:
source .venv/bin/activate
pip install -e .
```

### Configure MCP Client (VS Code)

Add to your VS Code User settings (`Ctrl+Shift+P` → "Preferences: Open User Settings (JSON)") or `~/.vscode/mcp.json`:

```json
{
  "servers": {
    "detection-lookups": {
      "type": "stdio",
      "command": "/absolute/path/to/.venv/bin/python",
      "args": ["-m", "mcp_server"],
      "cwd": "/absolute/path/to/agentic-detection-lookups"
    }
  }
}
```

> **Windows example:**
> ```json
> {
>   "servers": {
>     "detection-lookups": {
>       "type": "stdio",
>       "command": "C:\\Code\\.venv\\Scripts\\python.exe",
>       "args": ["-m", "mcp_server"],
>       "cwd": "C:\\Code\\agentic-detection-lookups"
>     }
>   }
> }
> ```

Reload VS Code: `Ctrl+Shift+P` → "Reload Window"

### Verify

In Copilot Chat (Agent mode):
```
Is certutil.exe a LOLBAS binary?
```

✅ Returns risk, categories, and MITRE mappings = working!

### Run standalone (CLI)

```bash
detection-lookups
```

This starts the MCP server on stdio transport (useful for piping JSON-RPC or connecting other MCP clients).

### Upload to your SIEM

- **CrowdStrike NG-SIEM:** Upload via API or UI (Settings → Lookup Files)
- **Splunk:** Settings → Lookups → Lookup table files → Add new
- **Elastic:** Create enrich index + ingest pipeline
- **Sentinel:** Configuration → Watchlist → Add new

## Project Structure

```
agentic-detection-lookups/
├── lookups/                    # The data (CSV files)
│   ├── lolbas_binaries.csv
│   └── parent_child_baselines.csv
├── queries/                    # Copy-paste detection queries
│   ├── crowdstrike_ngsiem.md
│   ├── splunk.md
│   ├── elastic.md
│   └── microsoft_sentinel.md
├── mcp_server/                 # MCP server for AI agents
│   ├── server.py
│   └── __init__.py
├── scripts/                    # Update/maintenance scripts
├── LICENSE                     # Apache 2.0
├── NOTICE
└── pyproject.toml
```

## Contributing

PRs welcome. See [CONTRIBUTING.md](CONTRIBUTING.md) for guidelines.

To add a new lookup file:
1. Follow the schema contract (match key first, include risk + MITRE columns)
2. Include at least one query example per SIEM platform
3. Add a tool to the MCP server

## License

Apache 2.0 — See [LICENSE](LICENSE) and [NOTICE](NOTICE).

---

Built by [Gene Kazimiarovich](https://github.com/gkazimiarovich) | Part of [Detection Forge](https://github.com/detection-forge)
