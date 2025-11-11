# No Sender, No Return Path!?

### Background
Social engineers will try anything to successfully deliver bait to their targets. One technique recently observed is having missing sender and return path information in the email headers. Surprisingly, some of the emails delivered had a pass for SPF (sender policy framework) authentication.
In Microsoft Defender, the sender is represented as `SenderFromAddress`, and the return path as `SenderMailFromAddress`. Consequently, the domain equivalents are `SenderFromDomain` and `SenderMailFromDomain` respectively.

### Detection
This technique can be detected as follows. You may want to further inspect the email authentication records (SPF, DKIM, DMARC).

#### Microsoft Defender XDR
```KQL
let duration = 7d;
EmailEvents
| where Timestamp >= ago(duration)
| where EmailDirection == "Inbound"
| where isempty(tostring(SenderFromDomain)) and tostring(SenderMailFromDomain) == "<>"
| extend dkim = tostring(parse_json(AuthenticationDetails).DKIM)
| extend dmarc = tostring(parse_json(AuthenticationDetails).DMARC)
| extend spf = tostring(parse_json(AuthenticationDetails).SPF)
| extend DKIM_Record = iff(isempty(dkim), "empty", dkim)
| extend DMARC_Record = iff(isempty(dmarc), "empty", dmarc)
| extend SPF_Record = iff(isempty(spf), "empty", spf)
| project-reorder SenderMailFromAddress, SenderFromAddress, SenderMailFromDomain, SenderFromDomain
    , SenderIPv4, SPF_Record, DKIM_Record, DMARC_Record, RecipientEmailAddress, LatestDeliveryLocation, LatestDeliveryAction
| sort by Timestamp desc
```

### Prevention
Receiving any form of communication from an unknown sender is an indicator of suspicious activity. Why would a sender not want the recipient know who they are (or even hide their true identity)?

Such activity can be dealt with in multiple ways, depending on configuration policy:
- Creating a mail flow rule in Exchange to quarantine email with no sender or return path header information.
- Creating an automated response in Defender XDR based on a custom detection rule using the above KQL query, for instance, soft delete or quarantine. See [Defender XDR Remediation Actions](https://learn.microsoft.com/en-us/defender-xdr/m365d-remediation-actions).
- Creating policies to remediate non-authenticated emails (failed/no SPF, DKIM, DMARC).
> CAUTION: This last option may be prone to false positives.
