# Runbook: Command and Scripting Interpreter (T1059 / T1059.001)

## Scope
Suspicious use of command shells and scripting interpreters — PowerShell,
cmd, wscript/cscript, python — often for download-and-execute or
obfuscated payloads. Fires on rules `SIG-EXEC-001`, `AUTO-EXEC-001`,
`AUTO-EXEC-002`.

## Detection signals
- Encoded PowerShell (`-enc`, `-e`), base64 command blobs.
- Script interpreters downloading binaries (certutil, bitsadmin, curl | sh).
- PowerShell executing from unusual paths or with `-nop -w hidden`.
- Process trees where a script interpreter spawns network tools.

## Triage
1. Identify the parent process and the full command line for the event.
2. Correlate with network egress (T1041) and any C2 indicators (T1573).
3. Determine whether the execution was scheduled/legit (e.g. admin scripts).

## Containment (approval-gated)
- `isolate_host` — isolate the endpoint (approval required).
- `block_indicator` — block the download source URL/hash (approval required).
- `search_related_events` — find other executions from the same host or user.

## References
- ATT&CK: T1059 Command and Scripting Interpreter; T1059.001 PowerShell.
- Obfuscated payloads may also map to T1027 (Obfuscated Files or Information).
