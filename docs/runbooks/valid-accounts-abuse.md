# Runbook: Valid Accounts Abuse (T1078 / T1078.001 / T1078.004)

## Scope
Legitimate credentials used in suspicious ways — remote login from unusual
locations, admin role assumption, or service-account reuse. Fires on rules
`AUTO-CRED-001` and `AUTO-CLOUD-001`.

## Detection signals
- Successful remote login (authentication/login_success) from a new or
  unexpected source IP or host.
- Cloud admin role assumption (AssumeRole to AdminRole) by non-admin users.
- Logins outside normal business hours or from geoblocked regions.
- Service accounts with interactive logins.

## Triage
1. Verify the login is expected: location, time, device, MFA posture.
2. Check the account's privilege level and recent password/reset events.
3. Correlate with credential-dumping (T1003) or brute-force (T1110) findings.

## Containment (approval-gated)
- `disable_user` — disable the identity if compromise is suspected (approval required).
- `isolate_host` — contain the endpoint involved in the login (approval required).
- `notify_channel` — escalate to the identity team.

## References
- ATT&CK: T1078 Valid Accounts; T1078.001 Default Accounts; T1078.004 Cloud Accounts.
- Cloud role assumption (T1098) can expand access beyond the original account.
