# AutoSIEM product vision: safe AI SOC automation

## Core thesis

AutoSIEM should automate as much of the junior analyst workflow as safely possible while remaining a proper SIEM: evidence-preserving, auditable, standards-aligned, explainable, and controllable by the customer.

The target is not a reckless "AI replaces security team" product. The target is an AI SOC automation platform that can handle repetitive tier-1 alert work, escalate intelligently, reduce noise, and preserve analyst trust.

## Can AI replace a junior analyst?

AI can automate a large portion of common tier-1 SOC work:

- alert intake
- deduplication
- enrichment
- severity/risk scoring
- related-event lookup
- entity history review
- threat-intel lookups
- MITRE mapping
- timeline building
- initial triage notes
- recommended next steps
- ticket drafting
- case summarization
- false-positive suggestions
- escalation packaging

AI should not be allowed to silently perform high-impact decisions without policy controls:

- suppressing detections globally
- deleting evidence
- changing rules in production
- disabling accounts
- isolating hosts
- blocking business-critical IPs/domains
- closing high-risk incidents
- ignoring confirmed compromise indicators

## Product positioning

AutoSIEM should be:

1. **A proper SIEM** — ingestion, normalization, storage, search, rules, correlation, incidents, retention, audit, compliance.
2. **AI-native** — AI drives triage, summarization, investigation, correlation suggestions, and rule authoring.
3. **Automation-first** — repeated low-risk workflows are automated with policy gates.
4. **Safe by design** — deterministic detection/risk pipeline, AI explanations, approval gates, rollback, audit logs.
5. **Self-hostable** — customers can use their own models, local inference, or hosted model providers.
6. **Beautiful and simple** — modern UI, guided workflows, low cognitive load, but full power underneath.
7. **Always current** — hourly backend updates for threat intel, detection content, ATT&CK metadata, schema mappings, and integration metadata, with safe staged rollout.

## Safety model

AutoSIEM should use a graduated autonomy model.

### Level 0: observe only

AI summarizes and recommends. No state changes.

### Level 1: low-risk automation

AI can enrich alerts, group duplicates, draft tickets, and mark obvious duplicates as linked, not closed.

### Level 2: reversible workflow automation

AI can perform approved playbook steps that are reversible or low impact, such as adding a case comment, requesting MFA logs, querying EDR, or notifying a channel.

### Level 3: approval-gated response

AI proposes containment actions, but a human approves:

- disable user
- isolate host
- block domain/IP
- revoke token
- rotate credential

### Level 4: policy-bounded autonomous response

Only for mature customers with explicit policies, high confidence, and automatic rollback/escalation.

Examples:

- isolate confirmed malware sandbox host
- disable known compromised test account
- block known malicious hash in non-production fleet

Default product behavior should stop at Level 2 or Level 3.

## Hourly updates without unsafe drift

Hourly updates are feasible, but they must be controlled.

Update streams:

- threat-intel indicators
- detection rules
- parser/schema mappings
- MITRE ATT&CK metadata
- vulnerability/exposure metadata
- integration connector metadata
- model prompts/evaluation packs
- UI content/help/runbooks

Safety requirements:

- signed update packages
- semantic versioning
- changelog and provenance
- customer pinning/rollback
- staging before production
- canary mode
- compatibility checks
- rule simulation against recent customer telemetry before enabling
- update policies per tenant
- no silent high-impact detection changes for regulated customers

## Self-hosted AI strategy

AutoSIEM should support multiple AI modes:

1. **No external AI** — deterministic local investigation summaries only.
2. **Customer-hosted local model** — Ollama/vLLM/TGI/OpenAI-compatible endpoint.
3. **Customer cloud model** — Azure OpenAI, Bedrock, Vertex AI, private OpenAI-compatible deployment.
4. **AutoSIEM-hosted AI** — managed paid tier.

The model adapter should be provider-neutral:

```text
AutoSIEM AI Gateway
  ├─ redaction policy
  ├─ prompt templates
  ├─ model routing
  ├─ retrieval context
  ├─ tool permissions
  ├─ audit logs
  ├─ eval/scoring
  └─ provider adapters
```

## Consumer/free tier path

A free personal tier is feasible if scoped carefully:

- local/self-hosted only
- limited connectors
- local logs, endpoint telemetry, home lab firewall/DNS/GitHub
- community rules
- local model support
- no expensive hosted AI by default
- upgrade path to managed cloud, enterprise connectors, compliance, team workflows, SOAR, and premium detection content

## Enterprise credibility requirements

Companies will require:

- RBAC/SSO/SAML/OIDC
- multi-tenancy
- audit logs
- retention policies
- encryption at rest/in transit
- customer-managed keys option
- evidence integrity
- API access
- SIEM/SOAR/EDR integrations
- compliance mappings
- uptime/SLOs
- secure update supply chain
- explainable detections
- transparent AI decision logs
- support for self-hosted/private AI

## Differentiator

The differentiator should be "AI SOC autopilot with trust controls":

- AI performs the boring tier-1 work.
- Deterministic detections remain the source of truth.
- Every AI decision is cited, logged, reversible, and policy-bound.
- Customers decide autonomy level.
- Self-hosted AI is first-class, not an afterthought.
