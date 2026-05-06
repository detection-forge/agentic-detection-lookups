# Splunk Queries (SPL)

Detection queries using lookup files in Splunk.

## Setup

Upload CSV files to Splunk as lookup tables:
```
Settings → Lookups → Lookup table files → Add new
```

Or use CLI:
```bash
splunk add lookup-definition lolbas_binaries -filename lolbas_binaries.csv
splunk add lookup-definition parent_child_baselines -filename parent_child_baselines.csv
```

## LOLBAS Enrichment

### Tag all processes with LOLBAS context

```spl
index=crowdstrike sourcetype="crowdstrike:events" event_simpleName=ProcessRollup2
| rex field=FileName "(?<binary>[^\\\\]+)$"
| eval binary=lower(binary)
| lookup lolbas_binaries.csv filename AS binary OUTPUT categories mitre_ids risk description
| where isnotnull(risk)
```

### High-risk LOLBAS execution

```spl
index=crowdstrike sourcetype="crowdstrike:events" event_simpleName=ProcessRollup2
| rex field=FileName "(?<binary>[^\\\\]+)$"
| eval binary=lower(binary)
| lookup lolbas_binaries.csv filename AS binary OUTPUT categories mitre_ids risk
| where risk="high"
| stats count by ComputerName, binary, categories
| sort -count
```

### LOLBAS download with URL in command line

```spl
index=crowdstrike sourcetype="crowdstrike:events" event_simpleName=ProcessRollup2
| rex field=FileName "(?<binary>[^\\\\]+)$"
| eval binary=lower(binary)
| lookup lolbas_binaries.csv filename AS binary OUTPUT categories risk
| where like(categories, "%Download%") AND match(CommandLine, "https?://")
| table _time ComputerName binary CommandLine
```

### LOLBAS spawned by Office applications

```spl
index=crowdstrike sourcetype="crowdstrike:events" event_simpleName=ProcessRollup2
| rex field=FileName "(?<binary>[^\\\\]+)$"
| eval binary=lower(binary)
| lookup lolbas_binaries.csv filename AS binary OUTPUT categories risk
| where (like(categories, "%Execute%") OR like(categories, "%AWL Bypass%"))
| where match(ParentBaseFileName, "(?i)(winword|excel|powerpnt|outlook)")
| table _time ComputerName ParentBaseFileName binary CommandLine categories
```

## Parent-Child Baselines

### Detect known-bad process lineage

```spl
index=crowdstrike sourcetype="crowdstrike:events" event_simpleName=ProcessRollup2
| eval parent=lower(ParentBaseFileName)
| rex field=FileName "(?<child>[^\\\\]+)$"
| eval child=lower(child)
| lookup parent_child_baselines.csv parent AS parent child AS child OUTPUT expected risk_if_unexpected mitre_id notes
| where expected="false" AND risk_if_unexpected="critical"
| table _time ComputerName parent child CommandLine mitre_id notes
```

### Web server spawning shell

```spl
index=crowdstrike sourcetype="crowdstrike:events" event_simpleName=ProcessRollup2
| where match(ParentBaseFileName, "(?i)(w3wp|httpd|apache2|nginx|tomcat)")
| rex field=FileName "(?<child>[^\\\\]+)$"
| eval parent=lower(ParentBaseFileName), child=lower(child)
| lookup parent_child_baselines.csv parent AS parent child AS child OUTPUT expected risk_if_unexpected mitre_id
| where expected="false"
| table _time ComputerName parent child CommandLine mitre_id
```

## Sysmon Variant

### LOLBAS enrichment for Sysmon Event ID 1

```spl
index=sysmon EventCode=1
| rex field=Image "(?<binary>[^\\\\]+)$"
| eval binary=lower(binary)
| lookup lolbas_binaries.csv filename AS binary OUTPUT categories mitre_ids risk
| where isnotnull(risk)
| table _time Computer binary ParentImage CommandLine categories risk
```

### Parent-child baseline for Sysmon

```spl
index=sysmon EventCode=1
| rex field=ParentImage "(?<parent>[^\\\\]+)$"
| rex field=Image "(?<child>[^\\\\]+)$"
| eval parent=lower(parent), child=lower(child)
| lookup parent_child_baselines.csv parent AS parent child AS child OUTPUT expected risk_if_unexpected mitre_id notes
| where expected="false"
| table _time Computer parent child CommandLine risk_if_unexpected mitre_id
```
