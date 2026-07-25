# URL Execution Across the Tenant

### Description

This query checks all tables containing URL attributes for execution of malicious/suspicious domains specified by the analyst.

### Query

```KQL
let url_list = pack_array(
    "list_of_domains here"
);
union isfuzzy=true withsource=SourceTable DeviceEvents,
    DeviceNetworkEvents, DeviceFileEvents, DeviceProcessEvents,
    UrlClickEvents, EmailUrlInfo, MessageUrlInfo
| where Timestamp >= ago(30d)
| where RemoteUrl has_any (url_list) or 
        ProcessCommandLine  has_any (url_list) or 
        FileOriginUrl  has_any (url_list) or 
        FileOriginReferrerUrl  has_any (url_list) or 
        Url has_any (url_list)
| project-reorder SourceTable, Timestamp, Url, NetworkMessageId, UrlLocation
```
