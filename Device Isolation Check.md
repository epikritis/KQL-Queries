# Device Isolation Check

### Description
Query to check if device has been isolated in the past 24h. If isolated, the 'IsIsolated' field has the value 'Yes', otherwise the value is 'No'.

### Microsoft Defender XDR
```KQL
let host = "paste-the-device-name-here";
DeviceInfo
| where Timestamp > ago(24h)
| where DeviceName =~ host
// Get logged on user
| extend DeviceUser = parse_json(LoggedOnUsers)
| mv-expand DeviceUser
| extend LoggedOnUsername = tostring(DeviceUser.UserName)
// Get isolation status
| extend MitigationStatusObject = parse_json(MitigationStatus)
| mv-expand MitigationStatusObject
| extend IsolationStatus = MitigationStatusObject.Isolated
| extend IsIsolated = iff((IsolationStatus == true), "Yes", "No")
//| where IsIsolated == "Yes"
// Get earliest device isolation event captured
| summarize arg_min(Timestamp, DeviceId, AadDeviceId, DeviceName, OSPlatform, OSVersionInfo
  , IsIsolated, IsAzureADJoined = iff(true, "Yes", "No"), LoggedOnUsername)
```
