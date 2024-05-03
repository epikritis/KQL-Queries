# Mounted Disk Info from Registry

### Description
Query runs through the Windows Registry to find evidence of any mounted disks. It uses the registry keys defined in the `registryKeysMountedDisks` array.

### Microsoft Defender XDR
```KQL
let host = "paste-the-device-name-here";
let registryKeysMountedDisks = dynamic([@"\SYSTEM\CURRENTCONTROLSET\ENUM\USBSTOR", @"\SYSTEM\MOUNTEDDEVICES", @"\SYSTEM\CURRENTCONTROLSET\ENUM\USB", @"\SOFTWARE\MICROSOFT\WINDOWS\CURRENTVERSION\EXPLORER\MOUNTPOINTS2"]);
DeviceRegistryEvents
| where DeviceName =~ host
| where Timestamp >= ago(30d) // Modify accordingly.
| where RegistryKey has_any (registryKeysMountedDisks)
| project Timestamp, RegistryKey, RegistryValueName, ResponsibleProcess = InitiatingProcessVersionInfoOriginalFileName, CommandLine = InitiatingProcessCommandLine
| sort by Timestamp desc
```
