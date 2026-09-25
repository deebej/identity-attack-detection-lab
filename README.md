# Hybrid AD/Entra ID Identity Attack Detection Lab

A hands-on identity security project: simulating real Active Directory attack techniques in a hybrid AD/Entra ID homelab, then building custom telemetry pipelines, Microsoft Sentinel detections, and automated SOAR response for each one.

Full write-up: [docs/case-study.md](docs/case-study.md)

## What's in this repo

- [`kerberoasting/`](kerberoasting/) — SPN abuse, ticket extraction, offline cracking, and the custom PowerShell pipeline that ships EventID 4769 to Sentinel
- [`password-spraying/`](password-spraying/) — spray simulation, detection KQL, and the Windows Server 2025 anti-spray throttling + audit policy findings
- [`soar-playbook/`](soar-playbook/) — Logic Apps automation rule that auto-triages incidents and sends alert notifications
- [`docs/case-study.md`](docs/case-study.md) — the full case study write-up

## Stack

Windows Server 2025 (AD DC) · Microsoft Entra ID · Microsoft Sentinel · Log Analytics · Kali Linux · Impacket · hashcat · PowerShell · KQL · Azure Logic Apps

## Status

Kerberoasting (T1558.003) and Password Spraying (T1110.003) phases complete, detected, and automated end to end. OAuth consent-phishing (T1528) and a Prowler cloud misconfiguration scan are planned as follow-on phases.

## Author

Dhiraj Anbunathan — [LinkedIn](https://linkedin.com/in/dhiraj-anbu) · [GitHub](https://github.com/deebej)
