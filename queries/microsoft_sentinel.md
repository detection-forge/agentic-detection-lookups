# Microsoft Sentinel (KQL)

Detection queries using lookup files in Microsoft Sentinel / Azure Log Analytics.

## Setup

Upload CSV files as Sentinel watchlists:

1. **Sentinel → Configuration → Watchlist → Add new**
2. Name: `lolbas_binaries` / `parent_child_baselines`
3. SearchKey: `filename` / `parent`
4. Upload CSV file

Or use the API:
```bash
az sentinel watchlist create \
  --resource-group <rg> --workspace-name <ws> \
  --watchlist-alias lolbas_binaries \
  --display-name "LOLBAS Binaries" \
  --provider "Detection Forge" \
  --source "lolbas_binaries.csv" \
  --items-search-key "filename"
```

## LOLBAS Enrichment

### Tag all processes with LOLBAS context

```kql
DeviceProcessEvents
| extend binary = tolower(FileName)
| join kind=inner (_GetWatchlist('lolbas_binaries')) on $left.binary == $right.filename
| project TimeGenerated, DeviceName, binary, ProcessCommandLine, categories, mitre_ids, risk
```

### High-risk LOLBAS execution

```kql
DeviceProcessEvents
| extend binary = tolower(FileName)
| join kind=inner (_GetWatchlist('lolbas_binaries')) on $left.binary == $right.filename
| where risk == "high"
| summarize count() by DeviceName, binary, categories
| sort by count_ desc
```

### LOLBAS download activity

```kql
DeviceProcessEvents
| extend binary = tolower(FileName)
| join kind=inner (_GetWatchlist('lolbas_binaries')) on $left.binary == $right.filename
| where categories has "Download"
| where ProcessCommandLine matches regex @"https?://"
| project TimeGenerated, DeviceName, binary, ProcessCommandLine, mitre_ids
```

### LOLBAS spawned by Office

```kql
DeviceProcessEvents
| extend binary = tolower(FileName)
| where InitiatingProcessFileName in~ ("winword.exe", "excel.exe", "powerpnt.exe", "outlook.exe")
| join kind=inner (_GetWatchlist('lolbas_binaries')) on $left.binary == $right.filename
| where categories has_any ("Execute", "AWL Bypass")
| project TimeGenerated, DeviceName, InitiatingProcessFileName, binary, ProcessCommandLine, categories, risk
```

## Parent-Child Baselines

### Detect known-bad process lineage

```kql
DeviceProcessEvents
| extend parent = tolower(InitiatingProcessFileName), child = tolower(FileName)
| join kind=inner (
    _GetWatchlist('parent_child_baselines')
    | where expected == "false"
) on $left.parent == $right.parent, $left.child == $right.child
| where risk_if_unexpected == "critical"
| project TimeGenerated, DeviceName, parent, child, ProcessCommandLine, mitre_id, notes
```

### Web server spawning shell

```kql
DeviceProcessEvents
| where InitiatingProcessFileName in~ ("w3wp.exe", "httpd.exe", "apache2", "nginx", "tomcat")
| where FileName in~ ("cmd.exe", "powershell.exe", "bash", "sh")
| extend parent = tolower(InitiatingProcessFileName), child = tolower(FileName)
| join kind=leftouter (_GetWatchlist('parent_child_baselines')) on $left.parent == $right.parent, $left.child == $right.child
| project TimeGenerated, DeviceName, parent, child, ProcessCommandLine, risk_if_unexpected, mitre_id
```

### Office spawning suspicious processes

```kql
DeviceProcessEvents
| where InitiatingProcessFileName in~ ("winword.exe", "excel.exe", "powerpnt.exe", "outlook.exe")
| extend parent = tolower(InitiatingProcessFileName), child = tolower(FileName)
| join kind=inner (
    _GetWatchlist('parent_child_baselines')
    | where expected == "false"
) on $left.parent == $right.parent, $left.child == $right.child
| project TimeGenerated, DeviceName, parent, child, ProcessCommandLine, risk_if_unexpected, mitre_id, notes
```

## Sentinel Analytics Rule (ARM template snippet)

```json
{
  "kind": "Scheduled",
  "properties": {
    "displayName": "LOLBAS Binary Spawned by Office Application",
    "severity": "High",
    "query": "DeviceProcessEvents\n| extend binary = tolower(FileName)\n| where InitiatingProcessFileName in~ (\"winword.exe\", \"excel.exe\", \"powerpnt.exe\", \"outlook.exe\")\n| join kind=inner (_GetWatchlist('lolbas_binaries')) on $left.binary == $right.filename\n| where categories has_any (\"Execute\", \"AWL Bypass\")\n| project TimeGenerated, DeviceName, InitiatingProcessFileName, binary, ProcessCommandLine, categories, risk, mitre_ids",
    "queryFrequency": "PT5M",
    "queryPeriod": "PT5M",
    "triggerOperator": "GreaterThan",
    "triggerThreshold": 0,
    "tactics": ["Execution", "DefenseEvasion"],
    "techniques": ["T1218", "T1204"]
  }
}
```
