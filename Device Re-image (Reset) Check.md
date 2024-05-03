# Device Re-image / Reset Check

### Description
This set of queries help determine if a device has been reset / re-imaged.
Every onboarded device is issued an `AadDeviceId` that is immutable no matter how many times the device is reset.
Using the `AadDeviceId`, one can identify different instances of the same device.
In each query, the latest image is displayed on top.
If there's only one instance, the device was not re-imaged.
Limitation: Queries only fetch data from the last 30 days.

### Microsoft Defender XDR
##### Using `AadDeviceId`
```KQL
DeviceInfo
| where AadDeviceId == "paste-the-aad-deviceid-here"
| where Timestamp >= ago(30d)
| summarize FirstSeen=min(Timestamp), LastSeen=max(Timestamp) by DeviceName, DeviceId
| order by LastSeen desc
```

##### Using `DeviceName`
```KQL
let host = "paste-the-device-name-here";
// Get AadDeviceId for device
let aadId = (DeviceInfo
| where DeviceName =~ host
| project AadDeviceId
| take 1);
// Use obtained AadDeviceId to check if device is re-imaged
DeviceInfo
| where AadDeviceId in (aadId)
| where Timestamp >= ago(30d)
| summarize FirstSeen=min(Timestamp), LastSeen=max(Timestamp) by DeviceName, DeviceId
| order by LastSeen desc
```
