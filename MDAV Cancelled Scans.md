# Description

KQL query to detect cancelled MDAV scans.

# Query

```KQL
DeviceEvents
| where ActionType == "AntivirusScanCancelled"
| extend ScanId = tostring(parse_json(AdditionalFields).ScanId)
    // ScanParametersIndex: 1 (Quick), 2 (Full)
    , ScanParametersIndex = toint(parse_json(AdditionalFields).ScanParametersIndex)
    , ScanTypeIndex = tostring(parse_json(AdditionalFields).ScanTypeIndex)
    // Troubleshoot MDAV performance issues:
        // https://learn.microsoft.com/en-us/defender-endpoint/troubleshoot-microsoft-defender-antivirus
    , ErrorCode = tostring(parse_json(AdditionalFields).ErrorCode)
    , ErrorDescription = tostring(parse_json(AdditionalFields).ErrorDescription)
| summarize count() by ScanTypeIndex
```
