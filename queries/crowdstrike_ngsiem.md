# CrowdStrike NG-SIEM (LogScale) Queries

Detection queries using lookup files in CrowdStrike NG-SIEM / LogScale CQL.

## LOLBAS Enrichment

### Tag all processes with LOLBAS context

```cql
#event_simpleName=ProcessRollup2
| FileName=/\\(?<binary>[^\\]+)$/
| match(file="lolbas_binaries.csv", field=binary, column=filename, include=[categories, mitre_ids, risk])
| risk=*
```

### High-risk LOLBAS execution

```cql
#event_simpleName=ProcessRollup2
| FileName=/\\(?<binary>[^\\]+)$/
| match(file="lolbas_binaries.csv", field=binary, column=filename, include=[categories, mitre_ids, risk])
| risk="high"
| groupBy([ComputerName, binary, categories], function=count())
| sort(_count, order=desc)
```

### LOLBAS download activity (binary downloading from URL)

```cql
#event_simpleName=ProcessRollup2
| FileName=/\\(?<binary>[^\\]+)$/
| match(file="lolbas_binaries.csv", field=binary, column=filename, include=[categories])
| categories=/Download/
| CommandLine=/https?:\/\//i
```

### LOLBAS execution spawned by Office

```cql
#event_simpleName=ProcessRollup2
| FileName=/\\(?<binary>[^\\]+)$/
| match(file="lolbas_binaries.csv", field=binary, column=filename, include=[categories, risk])
| categories=/Execute|AWL Bypass/
| ParentBaseFileName=/winword|excel|powerpnt|outlook/i
```

## Parent-Child Baselines

### Detect known-bad process lineage

```cql
#event_simpleName=ProcessRollup2
| ParentBaseFileName=lower(ParentBaseFileName)
| FileName=/\\(?<child>[^\\]+)$/
| child=lower(child)
| match(file="parent_child_baselines.csv", field=[ParentBaseFileName, child], column=[parent, child], include=[expected, risk_if_unexpected, mitre_id, notes])
| expected="false"
| risk_if_unexpected="critical"
```

### Web server spawning shell (webshell detection)

```cql
#event_simpleName=ProcessRollup2
| ParentBaseFileName=/w3wp|httpd|apache2|nginx|tomcat/i
| FileName=/\\(?<child>[^\\]+)$/
| match(file="parent_child_baselines.csv", field=[ParentBaseFileName, child], column=[parent, child], include=[expected, risk_if_unexpected, mitre_id])
| expected="false"
```

### Office spawning suspicious children

```cql
#event_simpleName=ProcessRollup2
| ParentBaseFileName=/winword|excel|powerpnt|outlook/i
| FileName=/\\(?<child>[^\\]+)$/
| child=lower(child)
| match(file="parent_child_baselines.csv", field=[ParentBaseFileName, child], column=[parent, child], include=[expected, risk_if_unexpected, mitre_id])
| expected="false"
```

## Dashboard Widgets

### Top LOLBAS usage by host (last 24h)

```cql
#event_simpleName=ProcessRollup2
| FileName=/\\(?<binary>[^\\]+)$/
| match(file="lolbas_binaries.csv", field=binary, column=filename, include=[categories, risk])
| risk="high"
| groupBy([ComputerName, binary], function=count())
| sort(_count, order=desc)
| head(20)
```

### Suspicious parent-child pairs (last 24h)

```cql
#event_simpleName=ProcessRollup2
| ParentBaseFileName=lower(ParentBaseFileName)
| FileName=/\\(?<child>[^\\]+)$/
| child=lower(child)
| match(file="parent_child_baselines.csv", field=[ParentBaseFileName, child], column=[parent, child], include=[expected, risk_if_unexpected])
| expected="false"
| groupBy([ParentBaseFileName, child, risk_if_unexpected], function=count())
| sort(_count, order=desc)
```
