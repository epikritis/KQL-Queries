# Expansion of `Additional Fields` JSON Object for Antivirus Checks

### Description
Query to display antivirus events captured for a device.

Noteworthy: Information on actions taken by Windows Defender has been sourced from the URL: https://learn.microsoft.com/en-us/windows/client-management/mdm/policy-csp-defender#defender-threatseveritydefaultaction.

### Microsoft Defender XDR
```KQL
// Additional fields in DeviceEvents for 'AntivirusDetection' and 'AntivirusReport' action types
DeviceEvents
| where DeviceName == "device-name"
| extend parsedFields = parse_json(AdditionalFields)
| extend InitiatingProcess = parsedFields.InitiatingProcess
        , ThreatName = parsedFields.ThreatName
        , ExecutionStatusWhenDetected = parsedFields.WasExecutingWhileDetected
        , ExecutableSignedBy = parsedFields.Signer
        , ActionTaken = case(parsedFields.Action == 2, "Quarantined", parsedFields.Action == 3, "Removed", parsedFields.Action == 6
            , "Ignored", "N/A")
        // ThreatSeverityDefaultAction, see URL below
        // https://learn.microsoft.com/en-us/windows/client-management/mdm/policy-csp-defender#defender-threatseveritydefaultaction
        , RemediationStatus = parsedFields.WasRemediated
        , ReportSource = parsedFields.ReportSource
| extend FileFullPath = strcat(FolderPath, "\\", FileName)
| project Timestamp, WhatIsThisAbout = ActionType, FileFullPath, ThreatName, FileSHA1 = SHA1, InitiatingProcess
    , ExecutionStatusWhenDetected, ExecutableSignedBy, ActionTaken, RemediationStatus, ReportId, ReportSource
```
