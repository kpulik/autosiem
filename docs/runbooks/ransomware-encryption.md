# Runbook: Ransomware Encryption (T1486)

## Scope
Mass file encryption or destructive-encryption tooling (LockBit, Conti,
BlackCat families). Fires on rule `AUTO-IMPACT-001`. This is a critical
impact technique — respond fast, approve every destructive action.

## Detection signals
- Processes named for known ransomware families.
- Command lines encrypting many files (`-encrypt`, `--encrypt <dir>`).
- Rapid file-extension churn or mass rename/delete events.
- Large outbound transfers (T1041) right before encryption.

## Triage
1. Confirm encryption is actually in progress; do not reboot or power-cycle
   affected hosts (evidence loss).
2. Identify the initial access path (phishing T1566, valid accounts T1078,
   RDP/lateral movement T1021).
3. Scope: which hosts, users, and shares are affected.

## Containment (approval-gated)
- `isolate_host` — network-isolate affected endpoints (approval required).
- `block_indicator` — block C2 and payload download sources (approval required).
- `disable_user` — disable the initiating account (approval required).
- `notify_channel` — declare an incident in the response channel.

## References
- ATT&CK: T1486 Data Encrypted for Impact.
- Preserve evidence (memory + disk) before any destructive response action.
