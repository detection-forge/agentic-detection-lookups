# Contributing to Agentic Detection Lookups

## Adding a New Lookup File

1. **Schema requirements:**
   - First column = match key (the field consumers join on)
   - Include `risk` or `risk_if_unexpected` column (values: `critical`, `high`, `medium`, `low`)
   - Include MITRE ATT&CK technique column (pipe-delimited for multiple)
   - Include `description` or `notes` column
   - Flat structure — no nested data, use pipe `|` for multi-value fields

2. **Format requirements:**
   - UTF-8 encoding, no BOM
   - Unix line endings (LF, not CRLF)
   - Header row always present
   - No trailing commas or whitespace

3. **Required additions with new lookup:**
   - Query examples for all 4 platforms in `queries/`
   - Tool added to `mcp-server/server.py`
   - Entry in README table

## Adding Queries

- One file per SIEM platform in `queries/`
- Include setup instructions (how to upload/configure the lookup)
- At least 3 query examples per lookup file
- Include dashboard widget examples where applicable

## Code Style

- Python: follow existing patterns in `mcp-server/server.py`
- Use type hints
- Docstrings on all public functions

## Pull Request Process

1. Fork the repo
2. Create a feature branch
3. Add your lookup/queries/tools
4. Test the MCP server locally: `python -m mcp-server.server`
5. Submit PR with:
   - Summary (1-2 sentences)
   - What lookup/tool was added
   - Data source (URL)

## Data Quality

- All entries must have a citable source
- No proprietary/internal data
- Risk scores must be justifiable
- MITRE mappings must be accurate (verify against attack.mitre.org)
