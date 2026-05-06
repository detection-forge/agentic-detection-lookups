# Detection Lookups MCP Server

This MCP server exposes the lookup data as queryable tools for AI agents.

## Tools

| Tool | Description |
|------|-------------|
| `lookup_binary` | Check if a binary is a known LOLBAS |
| `check_parent_child` | Determine if a process parent→child relationship is expected |
| `list_by_category` | List all LOLBAS binaries by abuse category |
| `list_by_mitre` | List all binaries mapped to a MITRE technique |
| `search_lookups` | Freeform text search across all lookup data |
| `list_available_lookups` | List all available lookup files with metadata |

## Usage

### With Claude Desktop

Add to your `claude_desktop_config.json`:

```json
{
  "mcpServers": {
    "detection-lookups": {
      "command": "python",
      "args": ["-m", "mcp_server"],
      "cwd": "/path/to/agentic-detection-lookups"
    }
  }
}
```

### With uvx (no install)

```bash
uvx --from git+https://github.com/detection-forge/agentic-detection-lookups detection-lookups
```

### Standalone

```bash
cd agentic-detection-lookups
pip install -e .
detection-lookups
```

## Examples

Agent asks: *"Is certutil.exe suspicious?"*
→ Calls `lookup_binary("certutil.exe")`
→ Returns: `{risk: "medium", categories: ["Download"], mitre_ids: ["T1105"]}`

Agent asks: *"Should svchost spawn PowerShell?"*
→ Calls `check_parent_child("svchost.exe", "powershell.exe")`
→ Returns: `{expected: false, risk_if_unexpected: "high", mitre_id: "T1059.001"}`
