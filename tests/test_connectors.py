from __future__ import annotations

import json
from pathlib import Path

import pytest

from autosiem import connectors
from autosiem.connectors import (
    AssetConnector,
    CloudTrailConnector,
    ConnectorRegistry,
    EntraConnector,
    FilePollerConnector,
    GitHubConnector,
    OktaConnector,
    SuricataConnector,
    SysmonConnector,
    ZeekConnector,
    asset_to_raw,
    cloudtrail_record_to_raw,
    entra_to_raw,
    github_to_raw,
    okta_to_raw,
    registry,
    suricata_to_raw,
    sysmon_to_raw,
    zeek_to_raw,
)
from autosiem.normalization import normalize
from autosiem.pipeline import AutoSIEMPipeline
from autosiem.rules import load_rules


def _trail(name: str = "alice", role: str = "AdminRole", event_name: str = "AssumeRole") -> dict:
    return {
        "eventVersion": "1.08",
        "userIdentity": {"type": "IAMUser", "arn": f"arn:aws:iam::123456789012:user/{name}", "accountId": "123456789012", "userName": name},
        "eventTime": "2026-08-04T10:08:00Z",
        "eventSource": "iam.amazonaws.com",
        "eventName": event_name,
        "awsRegion": "us-east-1",
        "sourceIPAddress": "198.51.100.25",
        "requestParameters": {"roleArn": f"arn:aws:iam::123456789012:role/{role}", "roleSessionName": "s"},
        "requestID": "R",
        "eventID": "E",
        "eventType": "AwsApiCall",
        "recipientAccountId": "123456789012",
        "errorCode": None,
    }


def test_file_connector_polls_new_lines_only(tmp_path: Path) -> None:
    source = tmp_path / "in.jsonl"
    source.write_text(json.dumps({"category": "authentication", "action": "login_failed", "user": "bob"}) + "\n", encoding="utf-8")
    connector = FilePollerConnector({"path": str(source)})
    first = connector.poll()
    assert len(first) == 1
    assert first[0]["user"] == "bob"
    assert connector.poll() == []  # nothing new on a second poll
    with source.open("a", encoding="utf-8") as handle:
        handle.write(json.dumps({"category": "network", "action": "http_request"}) + "\n")
    second = connector.poll()
    assert len(second) == 1
    assert second[0]["category"] == "network"
    health = connector.health()
    assert health.ok
    assert health.events_received == 2


def test_file_connector_directory(tmp_path: Path) -> None:
    (tmp_path / "a.jsonl").write_text(json.dumps({"message": "one"}) + "\n", encoding="utf-8")
    (tmp_path / "b.jsonl").write_text(json.dumps({"message": "two"}) + "\n", encoding="utf-8")
    connector = FilePollerConnector({"path": str(tmp_path)})
    events = connector.poll()
    assert {event["message"] for event in events} == {"one", "two"}


def test_file_connector_handles_rotation(tmp_path: Path) -> None:
    source = tmp_path / "rot.jsonl"
    source.write_text(json.dumps({"message": "one"}) + "\n", encoding="utf-8")
    connector = FilePollerConnector({"path": str(source)})
    assert len(connector.poll()) == 1
    source.write_text("", encoding="utf-8")  # log rotation: file truncated
    assert connector.poll() == []  # truncation detected, offset reset to 0
    with source.open("a", encoding="utf-8") as handle:
        handle.write(json.dumps({"message": "fresh"}) + "\n")
    fresh = connector.poll()
    assert len(fresh) == 1
    assert fresh[0]["message"] == "fresh"


def test_connector_missing_path_health() -> None:
    connector = FilePollerConnector({"path": "/definitely/not/here.jsonl"})
    assert connector.poll() == []
    assert connector.health().ok is False
    assert "not found" in connector.health().detail


def test_connector_registry() -> None:
    registry = ConnectorRegistry()
    registry.register("file", FilePollerConnector)
    assert "file" in registry.names()
    connector = registry.create("file", {"path": "/tmp"})
    assert isinstance(connector, FilePollerConnector)
    with pytest.raises(KeyError):
        registry.create("does-not-exist")


def test_connector_feed_detection(tmp_path: Path) -> None:
    source = tmp_path / "events.jsonl"
    source.write_text(
        json.dumps({"category": "authentication", "action": "login_failed", "user": "bob", "outcome": "failure"}) + "\n",
        encoding="utf-8",
    )
    connector = FilePollerConnector({"path": str(source)})
    events = connector.poll()
    root = Path(__file__).resolve().parents[1]
    pipeline = AutoSIEMPipeline(load_rules(root / "rules"))
    result = pipeline.process_lines([json.dumps(event) for event in events])
    assert any(finding.rule_id == "AUTO-AUTH-001" for finding in result.findings)


def test_cloudtrail_record_maps_to_normalized_fields() -> None:
    raw = cloudtrail_record_to_raw(_trail())
    assert raw["category"] == "cloud"
    assert raw["action"] == "AssumeRole"
    assert raw["user"] == "alice"
    assert raw["src_ip"] == "198.51.100.25"
    assert raw["cloud_account"] == "123456789012"
    assert raw["resource"] == "AdminRole"
    assert raw["outcome"] == "success"
    assert raw["timestamp"] == "2026-08-04T10:08:00Z"


def test_cloudtrail_failed_record_sets_outcome_and_fallback_user_from_arn() -> None:
    record = _trail()
    record["userIdentity"].pop("userName")
    record["errorCode"] = "AccessDenied"
    record["eventName"] = "PutRolePolicy"
    raw = cloudtrail_record_to_raw(record)
    assert raw["user"] == "alice"  # derived from arn .../user/alice
    assert raw["resource"] == "AdminRole"  # from roleArn tail
    assert raw["outcome"] == "failure"


def test_cloudtrail_connector_polls_s3_export_and_tails(tmp_path: Path) -> None:
    source = tmp_path / "ct.json"
    source.write_text(
        json.dumps({"Records": [_trail("alice", "AdminRole"), _trail("bob", "ReadOnlyRole")]}),
        encoding="utf-8",
    )
    connector = CloudTrailConnector({"path": str(source)})
    events = connector.poll()
    assert [e["user"] for e in events] == ["alice", "bob"]
    assert [e["category"] for e in events] == ["cloud", "cloud"]
    assert connector.poll() == []  # nothing new on a second poll
    assert connector.health().ok
    assert connector.health().events_received == 2


def test_cloudtrail_connector_jsonl_and_directory(tmp_path: Path) -> None:
    a = tmp_path / "a.jsonl"
    a.write_text(json.dumps(_trail("carol", "AdminRole")) + "\n", encoding="utf-8")
    b = tmp_path / "b.jsonl"
    b.write_text(json.dumps({"Records": [_trail("dave", "ReadOnly")]}) + "\n", encoding="utf-8")
    connector = CloudTrailConnector({"path": str(tmp_path)})
    events = connector.poll()
    assert {e["user"] for e in events} == {"carol", "dave"}


def test_cloudtrail_feed_fires_cloud_rule(tmp_path: Path) -> None:
    source = tmp_path / "ct.json"
    source.write_text(json.dumps({"Records": [_trail("alice", "AdminRole")]}), encoding="utf-8")
    connector = CloudTrailConnector({"path": str(source)})
    events = connector.poll()
    root = Path(__file__).resolve().parents[1]
    pipeline = AutoSIEMPipeline(load_rules(root / "rules"))
    result = pipeline.process_lines([json.dumps(e) for e in events])
    assert any(finding.rule_id == "AUTO-CLOUD-001" for finding in result.findings)


def test_cloudtrail_registered_in_global_registry() -> None:
    assert "cloudtrail" in registry.names()
    assert isinstance(registry.create("cloudtrail", {"path": "/tmp"}), CloudTrailConnector)


def test_cloudtrail_missing_path_health() -> None:
    connector = CloudTrailConnector({"path": "/definitely/not/here.json"})
    assert connector.poll() == []
    assert connector.health().ok is False
    assert "not found" in connector.health().detail


def _okta(event_type: str = "user.session.start", result: str = "FAILURE", ip: str = "198.51.100.25") -> dict:
    return {
        "published": "2026-08-04T10:08:00.000Z",
        "uuid": "u-1",
        "eventType": event_type,
        "actor": [{"type": "User", "alternateId": "alice@example.com"}],
        "outcome": {"result": result, "reason": "reason"},
        "client": {"ipAddress": ip},
        "target": [{"type": "AppUser", "id": "0oa", "alternateId": "Salesforce"}],
    }


def test_okta_maps_to_normalized_fields() -> None:
    raw = okta_to_raw(_okta())
    assert raw["category"] == "authentication"
    assert raw["user"] == "alice@example.com"
    assert raw["src_ip"] == "198.51.100.25"
    assert raw["action"] == "login_failed"
    assert raw["outcome"] == "failure"
    assert raw["resource"] == "Salesforce"


def test_okta_failed_login_fires_auth_rule(tmp_path: Path) -> None:
    source = tmp_path / "okta.jsonl"
    source.write_text(json.dumps(_okta()) + "\n", encoding="utf-8")
    events = OktaConnector({"path": str(source)}).poll()
    root = Path(__file__).resolve().parents[1]
    result = AutoSIEMPipeline(load_rules(root / "rules")).process_lines([json.dumps(e) for e in events])
    assert any(f.rule_id == "AUTO-AUTH-001" for f in result.findings)


def test_okta_success_login_fires_cred001(tmp_path: Path) -> None:
    source = tmp_path / "okta.jsonl"
    source.write_text(json.dumps(_okta(result="SUCCESS")) + "\n", encoding="utf-8")
    events = OktaConnector({"path": str(source)}).poll()
    root = Path(__file__).resolve().parents[1]
    result = AutoSIEMPipeline(load_rules(root / "rules")).process_lines([json.dumps(e) for e in events])
    assert any(f.rule_id == "AUTO-CRED-001" for f in result.findings)


def test_okta_registered_in_registry() -> None:
    assert "okta" in registry.names()
    assert isinstance(registry.create("okta", {"path": "/tmp"}), OktaConnector)


def test_github_maps_cloud_fields() -> None:
    raw = github_to_raw({"@timestamp": 1720000000000, "actor": "alice", "action": "repo.create", "ip": "198.51.100.25", "org": "acme", "repo": "acme/webapp"})
    assert raw["category"] == "cloud"
    assert raw["user"] == "alice"
    assert raw["src_ip"] == "198.51.100.25"
    assert raw["cloud_account"] == "acme"
    assert raw["resource"] == "acme/webapp"
    assert isinstance(raw["timestamp"], float)  # ms -> seconds


def test_github_registered_in_registry() -> None:
    assert "github" in registry.names()
    assert isinstance(registry.create("github", {"path": "/tmp"}), GitHubConnector)


def test_entra_maps_and_fires(tmp_path: Path) -> None:
    raw = entra_to_raw({"createdDateTime": "2026-08-04T10:08:00Z", "id": "i1", "userPrincipalName": "alice@x.com", "ipAddress": "198.51.100.25", "appDisplayName": "Portal", "resultType": "failure"})
    assert raw["category"] == "authentication"
    assert raw["action"] == "login_failed"
    assert raw["outcome"] == "failure"
    assert raw["src_ip"] == "198.51.100.25"
    source = tmp_path / "entra.jsonl"
    source.write_text(json.dumps({"createdDateTime": "2026-08-04T10:08:00Z", "id": "i1", "userPrincipalName": "alice@x.com", "ipAddress": "198.51.100.25", "resultType": "failure"}) + "\n", encoding="utf-8")
    events = EntraConnector({"path": str(source)}).poll()
    root = Path(__file__).resolve().parents[1]
    result = AutoSIEMPipeline(load_rules(root / "rules")).process_lines([json.dumps(e) for e in events])
    assert any(f.rule_id == "AUTO-AUTH-001" for f in result.findings)
    assert "entra" in registry.names()
    assert isinstance(registry.create("entra", {"path": "/tmp"}), EntraConnector)


def test_entra_numeric_result_codes_decide_success_and_failure(tmp_path: Path) -> None:
    """resultType is a numeric code, not a word: "0" succeeds, 50126 fails.

    Matching those against "fail"/"denied" classified every real failed sign-in
    as a successful login, and passing the code through as `outcome` meant
    neither AUTO-AUTH-001 nor AUTO-CRED-001 could match Entra data at all.
    """
    failed = entra_to_raw({"createdDateTime": "2026-08-04T10:08:00Z", "id": "i1",
                           "userPrincipalName": "alice@x.com", "ipAddress": "198.51.100.25",
                           "resultType": "50126"})
    assert failed["action"] == "login_failed"
    assert failed["outcome"] == "failure"
    assert failed["result_code"] == "50126"

    ok = entra_to_raw({"createdDateTime": "2026-08-04T10:09:00Z", "id": "i2",
                       "userPrincipalName": "alice@x.com", "ipAddress": "198.51.100.25",
                       "resultType": "0"})
    assert ok["action"] == "login"
    assert ok["outcome"] == "success"

    absent = entra_to_raw({"createdDateTime": "2026-08-04T10:10:00Z", "id": "i3"})
    assert absent["outcome"] == "unknown"
    assert absent["result_code"] is None

    root = Path(__file__).resolve().parents[1]
    rules = load_rules(root / "rules")
    result = AutoSIEMPipeline(rules).process_lines([json.dumps(failed), json.dumps(ok)])
    fired = {f.rule_id for f in result.findings}
    assert "AUTO-AUTH-001" in fired   # the numeric failure code
    assert "AUTO-CRED-001" in fired   # the numeric success code


def test_sysmon_dict_fires_cred_dump(tmp_path: Path) -> None:
    source = tmp_path / "sysmon.jsonl"
    sysmon = {"Event": {"System": {"EventID": 1, "EventRecordID": 41, "UtcTime": "2026-08-04T10:08:00Z", "Computer": "alice-pc"}, "EventData": {"Image": "C:\\Tools\\mimikatz.exe", "CommandLine": "mimikatz.exe sekurlsa::logonpasswords", "OriginalFileName": "mimikatz.exe", "ParentImage": "C:\\Windows\\explorer.exe", "ParentCommandLine": "explorer.exe", "IntegrityLevel": "High"}}}
    source.write_text(json.dumps(sysmon) + "\n", encoding="utf-8")
    events = SysmonConnector({"path": str(source)}).poll()
    assert events[0]["process_name"] == "mimikatz.exe"
    assert events[0]["category"] == "process"
    assert events[0]["event_id"] == "41"
    assert events[0]["event_code"] == 1
    assert events[0]["log_product"] == "windows"
    assert events[0]["log_service"] == "sysmon"
    assert events[0]["parent_process_name"].endswith("explorer.exe")
    assert events[0]["integrity_level"] == "High"
    root = Path(__file__).resolve().parents[1]
    result = AutoSIEMPipeline(load_rules(root / "rules")).process_lines([json.dumps(e) for e in events])
    assert any(f.rule_id == "AUTO-CRED-002" for f in result.findings)


def test_sysmon_xml_string_parsed() -> None:
    xml = '''<Event xmlns="http://schemas.microsoft.com/win/2004/08/events/event"><System><Provider Name="Microsoft-Windows-Sysmon"/><EventID>1</EventID><Computer>alice-pc</Computer><UtcTime>2026-08-04T10:08:00Z</UtcTime></System><EventData><Data Name="Image">C:\\Tools\\mimikatz.exe</Data><Data Name="CommandLine">mimikatz.exe sekurlsa::logonpasswords</Data></EventData></Event>'''
    raw = sysmon_to_raw(xml)
    assert raw["process_name"] == "mimikatz.exe"
    assert "sekurlsa" in raw["command_line"]
    assert raw["host"] == "alice-pc"
    assert raw["provider_name"] == "Microsoft-Windows-Sysmon"
    assert "sysmon" in registry.names()


def test_normalizer_projects_sigma_detection_fields() -> None:
    raw = {
        "EventID": 4688,
        "OriginalFileName": "powershell.exe",
        "ParentImage": r"C:\\Windows\\explorer.exe",
        "ParentCommandLine": "explorer.exe",
        "TargetObject": r"HKLM\\Software\\Run",
        "TargetFilename": r"C:\\Temp\\payload.exe",
        "Details": "DWORD (0x00000001)",
        "ScriptBlockText": "Invoke-Expression",
        "ImageLoaded": r"C:\\Temp\\suspicious.dll",
        "ProviderName": "Microsoft-Windows-Security-Auditing",
        "Hashes": "SHA256=abc",
        "IntegrityLevel": "High",
    }
    event = normalize(raw)
    assert event.event_code == 4688
    assert event.original_file_name == "powershell.exe"
    assert event.parent_process_name == r"C:\\Windows\\explorer.exe"
    assert event.parent_command_line == "explorer.exe"
    assert event.target_object == r"HKLM\\Software\\Run"
    assert event.target_file_name == r"C:\\Temp\\payload.exe"
    assert event.details == "DWORD (0x00000001)"
    assert event.script_block_text == "Invoke-Expression"
    assert event.image_loaded == r"C:\\Temp\\suspicious.dll"
    assert event.provider_name == "Microsoft-Windows-Security-Auditing"
    assert event.hashes == "SHA256=abc"
    assert event.integrity_level == "High"


def test_normalizer_preserves_sigma_logsource_scope() -> None:
    event = normalize({"product": "Windows", "service": "Security"})
    assert event.log_product == "windows"
    assert event.log_service == "security"


def test_zeek_http_fires_web_rule(tmp_path: Path) -> None:
    raw = zeek_to_raw({"ts": 1720000000, "uid": "C1", "id.orig_h": "10.0.0.5", "id.resp_h": "203.0.113.20", "proto": "http", "host": "web.example.com", "uri": "/index.php?page=../../../../etc/passwd"})
    assert raw["category"] == "network"
    assert raw["action"] == "http_request"
    assert "../../" in raw["url"]
    source = tmp_path / "http.jsonl"
    source.write_text(json.dumps({"ts": 1720000000, "uid": "C1", "id.orig_h": "10.0.0.5", "id.resp_h": "203.0.113.20", "proto": "http", "host": "web.example.com", "uri": "/index.php?page=../../../../etc/passwd"}) + "\n", encoding="utf-8")
    events = ZeekConnector({"path": str(source)}).poll()
    root = Path(__file__).resolve().parents[1]
    result = AutoSIEMPipeline(load_rules(root / "rules")).process_lines([json.dumps(e) for e in events])
    assert any(f.rule_id == "AUTO-WEB-001" for f in result.findings)
    assert "zeek" in registry.names()
    assert isinstance(registry.create("zeek", {"path": "/tmp"}), ZeekConnector)


def test_suricata_maps_severity_and_pairs() -> None:
    raw = suricata_to_raw({"timestamp": "2026-08-04T10:08:00Z", "event_type": "alert", "src_ip": "198.51.100.25", "dest_ip": "203.0.113.9", "proto": "TCP", "alert": {"signature": "ET something", "severity": 1}})
    assert raw["category"] == "network"
    assert raw["src_ip"] == "198.51.100.25"
    assert raw["dst_ip"] == "203.0.113.9"
    assert raw["severity"] == "critical"
    assert raw["resource"] == "ET something"
    assert "suricata" in registry.names()
    assert isinstance(registry.create("suricata", {"path": "/tmp"}), SuricataConnector)


def test_asset_maps_endpoint_fields() -> None:
    raw = asset_to_raw({"hostname": "web-01", "ip": "10.0.0.5", "owner": "alice", "os": "ubuntu-22.04", "org": "acme"})
    assert raw["category"] == "endpoint"
    assert raw["host"] == "web-01"
    assert raw["src_ip"] == "10.0.0.5"
    assert raw["user"] == "alice"
    assert raw["cloud_account"] == "acme"
    assert isinstance(registry.create("asset", {"path": "/tmp"}), AssetConnector)


def test_every_connector_http_call_carries_a_timeout(monkeypatch) -> None:
    """urlopen inherits a None global default, so a silent peer hangs a poll forever."""
    seen: list[object] = []

    class FakeResponse:
        status = 200
        headers: dict[str, str] = {}

        def read(self) -> bytes:
            return b"{}"

        def __enter__(self) -> "FakeResponse":
            return self

        def __exit__(self, *_exc: object) -> None:
            return None

    def fake_urlopen(request: object, timeout: object = None) -> FakeResponse:
        seen.append(timeout)
        return FakeResponse()

    monkeypatch.setattr(connectors.urllib.request, "urlopen", fake_urlopen)
    connectors._urllib_get("https://example.test/a", {})
    connectors._urllib_post_form("https://example.test/token", {}, {"k": "v"})
    assert seen == [connectors.HTTP_TIMEOUT_SECONDS, connectors.HTTP_TIMEOUT_SECONDS]
    assert all(isinstance(value, float) and value > 0 for value in seen)


def test_xml_and_json_sysmon_agree_on_eventid_type() -> None:
    """XML left EventID a string, so it failed every numeric Sigma EventID rule."""
    from autosiem.schemas import DetectionRule, Severity
    from autosiem.detection import evaluate_rule
    from autosiem.normalization import normalize

    xml = '<Event><System><EventID>1</EventID></System><EventData><Data Name="Image">C:\\evil.exe</Data></EventData></Event>'
    as_json = {"Event": {"System": {"EventID": 1}, "EventData": {"Image": "C:\\evil.exe"}}}
    rule = DetectionRule(rule_id="S", name="t", description="", severity=Severity.HIGH,
                         risk_points=50, selection={"event_code": 1}, mitre_attack=[], tags=[])
    for raw in (xml, as_json):
        assert evaluate_rule(normalize(connectors.sysmon_to_raw(raw)), rule) is not None

    # A non-numeric channel name must survive untouched.
    named = connectors.sysmon_to_raw('<Event><System><EventID>Security</EventID></System><EventData/></Event>')
    assert named["event_code"] == "Security"
