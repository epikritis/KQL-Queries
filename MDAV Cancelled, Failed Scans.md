# MDAV Cancelled/Failed Scans

### Description

KQL query to detect cancelled and failed MDAV scans.

### Query

```KQL
DeviceEvents
| where ActionType in ("AntivirusScanCancelled", "AntivirusScanFailed")
| extend ScanId = tostring(parse_json(AdditionalFields).ScanId),
         // ScanParametersIndex: 1 (Quick), 2 (Full)
         ScanParametersIndex = toint(parse_json(AdditionalFields).ScanParametersIndex),
         ScanTypeIndex = tostring(parse_json(AdditionalFields).ScanTypeIndex),
         errCode = tostring(parse_json(AdditionalFields).ErrorCode),
         errDesc = tostring(parse_json(AdditionalFields).ErrorDescription),
         User = tostring(parse_json(AdditionalFields).User),
         AV_ScanResult = iff(ActionType == "AntivirusScanCancelled", "Cancelled", "Failed")
| extend ErrorCode = iff(isempty(errCode), "Not available", ErrorCode),
         ErrorDescription = iff(isempty(errDesc), "Not available", ErrorDescription)
| summarize arg_max(Timestamp, *) by DeviceName
| project Timestamp, DeviceName, User, AV_ScanResult, ScanId, ScanParametersIndex,
          ScanTypeIndex, ErrorCode, ErrorDescription, DeviceId, ReportId
//| summarize count() by ScanTypeIndex
```

### References

- https://learn.microsoft.com/en-us/defender-endpoint/troubleshoot-microsoft-defender-antivirus
