# Runbook: Phishing Triage (T1566 / T1566.001)

## Scope
Delivered phishing messages with suspicious attachments or URLs. Fires on rule
`AUTO-EMAIL-001`. T1566.001 covers spearphishing attachments specifically.

## Detection signals
- Email events with action `phishing_email_received` or `malicious_email`.
- Urgency language in subject (verify, urgent, account locked, payment).
- Executable or macro attachments (`invoice.exe`, `.docm`, `.js`).
- URLs with suspicious domains, punycode, or IP literals.

## Triage
1. Inspect the sender, subject, and attachment/URL against threat intel (`AUTO-INTEL-001`).
2. Determine whether the message reached a user's mailbox and whether it was opened.
3. Correlate with subsequent process events on the recipient's host.

## Containment (approval-gated)
- `block_indicator` — block the URL/domain/hash (approval required).
- `isolate_host` — isolate the recipient host if the payload executed (approval required).
- `notify_channel` — notify the security team about the campaign.

## References
- ATT&CK: T1566 Phishing; T1566.001 Spearphishing Attachment.
- Phishing frequently feeds initial access for T1078 valid-account abuse.
