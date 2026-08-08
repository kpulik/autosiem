# Runbook: Credential Dumping (T1003 / T1003.001)

## Scope
Local credential extraction — tools like mimikatz, procdump, or LSASS access
patterns. Fires on rule `AUTO-CRED-002`.

## Detection signals
- Processes named for known credential-dumping tools (mimikatz, procdump, lazagne).
- Command lines referencing `sekurlsa`, `lsass`, `logonpasswords`, `dumpcred`.
- Unusual access to LSASS from a non-system process.

## Triage
1. Confirm whether the process is a legitimate tool (admin tooling is still a finding).
2. Check who executed it (`user`, `host`) and whether the account is privileged.
3. Look for follow-on lateral movement (T1021) or remote session creation.

## Containment (approval-gated)
- `disable_user` — disable the executing account (approval required).
- `isolate_host` — isolate the endpoint (approval required).
- `enrich_entities` — gather context on the account and host.

## References
- ATT&CK: T1003 OS Credential Dumping; T1003.001 LSASS Memory.
- Credential dumping often precedes lateral movement and account takeover.
