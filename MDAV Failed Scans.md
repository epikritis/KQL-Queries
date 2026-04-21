# MDAV Failed Scans

### Description

KQL query to detect failed MDAV scans.

### Query

```KQL
DeviceEvents
| where ActionType == "AntivirusScanFailed"
| extend ScanId = tostring(parse_json(AdditionalFields).ScanId)
    // ScanParametersIndex: 1 (Quick), 2 (Full)
    , ScanParametersIndex = toint(parse_json(AdditionalFields).ScanParametersIndex)
    , ScanTypeIndex = tostring(parse_json(AdditionalFields).ScanTypeIndex)
    // Troubleshoot MDAV performance issues:
        // https://learn.microsoft.com/en-us/defender-endpoint/troubleshoot-microsoft-defender-antivirus
    , ErrorCode = tostring(parse_json(AdditionalFields).ErrorCode)
    , ErrorDescription = tostring(parse_json(AdditionalFields).ErrorDescription)
| project Timestamp, DeviceName, ScanId, ScanParametersIndex, ScanTypeIndex, ErrorCode, ErrorDescription
```

### References

- https://learn.microsoft.com/en-us/defender-endpoint/troubleshoot-microsoft-defender-antivirus
