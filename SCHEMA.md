# Schema Specification

All lookup files in this project follow a consistent schema contract to ensure
machine-readability and cross-platform compatibility.

## Universal Rules

1. **Format:** CSV (RFC 4180 compliant)
2. **Encoding:** UTF-8, no BOM
3. **Line endings:** LF (Unix)
4. **Header:** Always present as first row
5. **Quoting:** Fields containing commas, newlines, or quotes must be quoted
6. **Multi-value:** Pipe-delimited (`|`) within a single field

## Required Columns

Every lookup file MUST include:

| Column | Purpose | Values |
|--------|---------|--------|
| First column | Match key — the field consumers join on | Varies per file |
| `risk` or `risk_if_unexpected` | Severity assessment | `critical`, `high`, `medium`, `low` |
| MITRE column (`mitre_id` or `mitre_ids`) | ATT&CK technique mapping | `T####` or `T####.###`, pipe-delimited |

## Optional Standard Columns

| Column | Purpose |
|--------|---------|
| `description` / `notes` | Human-readable context |
| `context` | When "conditional" — what makes it legitimate |
| `os` | Operating system applicability |
| `categories` | Abuse/function categories (pipe-delimited) |

## File-Specific Schemas

### lolbas_binaries.csv

| Column | Type | Description |
|--------|------|-------------|
| `filename` | string | Match key — lowercase binary name |
| `binary_name` | string | Original case binary name |
| `primary_path` | string | Most common filesystem path |
| `categories` | string | Pipe-delimited abuse categories |
| `mitre_ids` | string | Pipe-delimited MITRE technique IDs |
| `risk` | string | `high`, `medium`, or `low` |
| `description` | string | What the binary does |

### parent_child_baselines.csv

| Column | Type | Description |
|--------|------|-------------|
| `parent` | string | Match key — parent process filename |
| `child` | string | Match key — child process filename (or `*` for any) |
| `os` | string | `windows` or `linux` |
| `expected` | string | `true`, `false`, or `conditional` |
| `risk_if_unexpected` | string | `critical`, `high`, `medium`, `low` |
| `mitre_id` | string | MITRE technique if suspicious |
| `context` | string | When conditional — what makes it legit |
| `notes` | string | Triage guidance |

### gtfobins.csv

| Column | Type | Description |
|--------|------|-------------|
| `filename` | string | Match key — lowercase binary name |
| `binary_name` | string | Original case binary name |
| `primary_path` | string | Common Linux path (typically `/usr/bin/<name>`) |
| `categories` | string | Pipe-delimited GTFOBins function types |
| `mitre_ids` | string | Pipe-delimited MITRE technique IDs |
| `risk` | string | `high`, `medium`, or `low` |
| `description` | string | Summary of abuse capabilities |

**GTFOBins categories:** `shell`, `reverse-shell`, `bind-shell`,
`non-interactive-bind-shell`, `non-interactive-reverse-shell`, `file-read`,
`file-write`, `download`, `upload`, `library-load`, `command`, `inherit`,
`privilege-escalation`

**Risk mapping:**
- **High:** reverse-shell, bind-shell, library-load, privilege-escalation
- **Medium:** shell, command, file-write, download, upload, inherit
- **Low:** file-read only
