# Automated Response (SOAR)

A Sentinel-triggered Azure Logic Apps playbook (`LA-IncidentResponse-Spray-Kerb`) attached to both Analytics Rules via Automation Rules ("When incident is created" → Run playbook).

## Actions

1. **Add comment to incident** — auto-triage note with incident title and related entities
2. **HTTP POST notification** — incident title, severity, and link sent to a webhook endpoint

## Validation

Confirmed with real incident data: the auto-added comment and the webhook payload both populate correctly from the trigger's incident context (title, severity, incidentUrl).

## Notes for anyone extending this

- Logic App and Log Analytics workspace must be in the same Azure region
- The Logic App's managed identity needs **Microsoft Sentinel Automation Contributor** on the resource group
- The `Azure Security Insights` service principal also needs that same role (usually granted via the "Manage playbook permissions" link in the automation rule's playbook picker)
- Directory-level permissions (Entra ID roles like Security Administrator) matter separately from Azure resource RBAC in the Defender portal, this tripped up setup more than the RBAC itself did
