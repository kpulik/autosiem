# Runbook: Brute Force / Credential Access (T1110)

## Scope
Authentication events that look like password guessing or credential stuffing
against interactive or service accounts. Fires primarily on repeated
authentication failures (rule `AUTO-AUTH-001`).

## Detection signals
- Failed authentication events for a single user from one source IP (outcome contains fail/denied/error).
- High failure-to-success ratio in a short window.
- Same source IP trying many distinct usernames.
- Failures followed by a success (possible successful guess).

## Triage
1. Confirm the account actually exists and whether the failures are interactive or service-based.
2. Pull surrounding events for the source IP, user, and host for +/- 24 hours (`search_related_events`).
3. Check if any failure was followed by a successful login; if so, treat as potential account compromise.

## Containment (approval-gated)
- `disable_user` — disable the affected account (approval required).
- `block_indicator` — block the source IP at the enforcement layer (approval required).
- `notify_channel` — notify the SOC escalation channel.

## References
- ATT&CK: T1110 Brute Force (credential-access).
- Do not self-service reset accounts without verifying MFA and session tokens.
