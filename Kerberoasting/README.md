# Phase 1: Kerberoasting (T1558.003)

## Attack

An SPN was registered on a target service account. Impacket's ticket-extraction tooling (Kali Linux) was used to request and dump the Kerberos service ticket (EventID 4769), which was cracked offline with hashcat.

## Detection pipeline

No native Sentinel connector exists for this on-prem telemetry, so a custom shipping pipeline was built:

1. `ship-kerberos-events.ps1` pulls new EventID 4769 records from the local Security log
2. Extracts TargetUserName, ServiceName, TicketEncryptionType, IpAddress
3. Ships them to a custom Log Analytics table (`KerberoastDetection_CL`) via the HTTP Data Collector API, HMAC-SHA256 signed
4. Tracks its own cursor (`lastRecordId_4769.txt`) so re-runs only ship new events

## Detection rule

Sentinel Analytics Rule flags RC4-encrypted ticket requests (a known Kerberoasting indicator), mapped to MITRE ATT&CK T1558.003. Validated end to end: real attack → real telemetry → real Sentinel incident.

See [`ship-kerberos-events.ps1`](ship-kerberos-events.ps1) for the full script.
