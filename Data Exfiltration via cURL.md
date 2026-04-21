# Data Exfiltration via cURL

### Description

Detecting exfiltration of data via cURL. To be used with caution as it is prone to false positives. May be used as a starting point then fine-tuned.

### MITRE ATT&CK Mapping

- [T1048.001](https://attack.mitre.org/techniques/T1048/001)
- [T1048.003](https://attack.mitre.org/techniques/T1048/003)

### Query

```KQL
// Specific arguments for upload activity
let data_args = pack_array(
    "-d",
    "--data",
    "--data-raw",
    "--data-binary",
    "--data-urlencode",
    "--data-ascii",
    "-F",
    "-T",
    "--upload-file"
    );
let known_endpoints = pack_array(
    "list_of_known_endpoints"
    );
DeviceProcessEvents
| where ProcessCommandLine has_any ("curl", "curl.exe") and
        ProcessCommandLine has_any (data_args) and 
        not(
            ProcessCommandLine has_cs "-f" or 
            ProcessCommandLine has_cs "-D" or 
            ProcessCommandLine has_cs "-t"
            ) and
        ProcessCommandLine matches regex "\\.zip|\\.rar|\\.7z|\\.gz|\\.tar|\\.bz2"
| extend cURL_request_endpoint = extract(@"http[s]?://([^/]+)", 1, ProcessCommandLine)
| where not(
    cURL_request_endpoint matches regex "^10\\." or
    cURL_request_endpoint matches regex "^172\\.(1[6-9]|2[0-9]|3[0-1])\\." or
    cURL_request_endpoint matches regex "^192\\.168\\." or
    cURL_request_endpoint matches regex "^127\\.0\\.0\\.1" or 
    cURL_request_endpoint matches regex "localhost" or 
    cURL_request_endpoint in (known_endpoints)
)
```

### References

- https://everything.curl.dev/usingcurl/uploads
