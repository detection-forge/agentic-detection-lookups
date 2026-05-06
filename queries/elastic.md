# Elastic (ES|QL & KQL)

Detection queries using lookup files in Elastic Security / Elasticsearch.

## Setup

Upload CSV files as Elasticsearch enrichment indices:

```bash
# Create index from CSV
python -c "
import csv, json
with open('lookups/lolbas_binaries.csv') as f:
    for row in csv.DictReader(f):
        print(json.dumps({'index': {'_index': 'lolbas-binaries'}}))
        print(json.dumps(row))
" | curl -s -XPOST 'localhost:9200/_bulk' -H 'Content-Type: application/x-ndjson' --data-binary @-
```

Or use Elastic's [enrich processor](https://www.elastic.co/guide/en/elasticsearch/reference/current/enrich-processor.html) in an ingest pipeline.

## LOLBAS Enrichment

### ES|QL — Tag processes with LOLBAS context

```esql
FROM logs-endpoint.events.process-*
| WHERE event.action == "start"
| EVAL binary = TO_LOWER(SUBSTRING(process.executable, LENGTH(process.executable) - LOCATE(REVERSE(process.executable), "\\") + 2))
| ENRICH lolbas-policy ON binary = filename WITH categories, mitre_ids, risk
| WHERE risk IS NOT NULL
| KEEP @timestamp, host.name, binary, process.command_line, categories, risk, mitre_ids
```

### KQL — High-risk LOLBAS (detection rule)

```kql
event.action: "start" AND process.name: (
  "certutil.exe" OR "mshta.exe" OR "regsvr32.exe" OR "rundll32.exe" OR
  "msbuild.exe" OR "installutil.exe" OR "cmstp.exe" OR "wmic.exe"
)
```

### ES|QL — LOLBAS download activity

```esql
FROM logs-endpoint.events.process-*
| WHERE event.action == "start"
| EVAL binary = TO_LOWER(process.name)
| ENRICH lolbas-policy ON binary = filename WITH categories, risk
| WHERE categories LIKE "*Download*" AND process.command_line LIKE "*http*"
| KEEP @timestamp, host.name, binary, process.command_line, process.parent.name
```

### ES|QL — Office spawning LOLBAS

```esql
FROM logs-endpoint.events.process-*
| WHERE event.action == "start"
  AND process.parent.name IN ("WINWORD.EXE", "EXCEL.EXE", "POWERPNT.EXE", "OUTLOOK.EXE")
| EVAL binary = TO_LOWER(process.name)
| ENRICH lolbas-policy ON binary = filename WITH categories, risk
| WHERE risk IS NOT NULL
| KEEP @timestamp, host.name, process.parent.name, binary, process.command_line, categories, risk
```

## Parent-Child Baselines

### ES|QL — Detect suspicious parent-child

```esql
FROM logs-endpoint.events.process-*
| WHERE event.action == "start"
| EVAL parent = TO_LOWER(process.parent.name), child = TO_LOWER(process.name)
| ENRICH parent-child-policy ON parent, child WITH expected, risk_if_unexpected, mitre_id, notes
| WHERE expected == "false" AND risk_if_unexpected == "critical"
| KEEP @timestamp, host.name, parent, child, process.command_line, mitre_id, notes
```

### KQL — Web server spawning shell (detection rule)

```kql
event.action: "start"
  AND process.parent.name: ("w3wp.exe" OR "httpd.exe" OR "apache2" OR "nginx" OR "tomcat*")
  AND process.name: ("cmd.exe" OR "powershell.exe" OR "bash" OR "sh")
```

## Elastic Detection Rule (TOML)

```toml
[rule]
name = "LOLBAS Binary Spawned by Office Application"
description = "Detects Living Off The Land binary execution from Microsoft Office process"
type = "eql"
language = "eql"
severity = "critical"
risk_score = 90
tags = ["LOLBAS", "T1204.002", "T1218"]

[rule.query]
query = '''
process where event.action == "start" and
  process.parent.name in ("WINWORD.EXE", "EXCEL.EXE", "POWERPNT.EXE", "OUTLOOK.EXE") and
  process.name in ("cmd.exe", "powershell.exe", "mshta.exe", "certutil.exe", "regsvr32.exe", "rundll32.exe", "wscript.exe", "cscript.exe")
'''
```
