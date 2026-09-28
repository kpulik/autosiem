"""SEC-016 (a): deeply nested JSON must not crash ingest.

Before the fix a 900-deep body returned 500 from /api/ingest (the web stack's
own frames pushed the pipeline over the interpreter recursion limit), and one
5000-deep line made ``cli ingest`` exit with a RecursionError traceback,
dropping every good line in the same file.
"""

from __future__ import annotations

import json
import sys
from pathlib import Path

import pytest
from fastapi.testclient import TestClient

from autosiem.cli import main
from autosiem.normalization import MAX_JSON_DEPTH, load_json_bounded, parse_raw_line
from autosiem.web.api import app

ROOT = Path(__file__).resolve().parents[1]


def _nested(depth: int) -> str:
    """An event whose ``a`` field sits ``depth`` containers deep (the event object is level 1)."""
    inner = depth - 1
    return '{"user": "mallory", "a": ' + "[" * inner + "]" * inner + "}"


def test_the_limit_is_exact() -> None:
    assert isinstance(load_json_bounded(_nested(MAX_JSON_DEPTH)), dict)
    with pytest.raises(ValueError, match="nested deeper"):
        load_json_bounded(_nested(MAX_JSON_DEPTH + 1))


def test_interpreter_recursion_is_reported_as_a_value_error() -> None:
    with pytest.raises(ValueError, match="nested deeper"):
        load_json_bounded(_nested(50_000))


def test_a_too_deep_line_becomes_a_message_event_instead_of_raising() -> None:
    line = _nested(5000)
    raw = parse_raw_line(line)
    assert raw["format"] == "json-too-deep"
    assert raw["message"] == line


@pytest.mark.parametrize("depth", [MAX_JSON_DEPTH + 1, 900, 5000])
@pytest.mark.parametrize("content_type", ["application/json", "application/x-ndjson"])
def test_api_rejects_deep_json_with_400(monkeypatch, tmp_path, depth: int, content_type: str) -> None:
    monkeypatch.setenv("AUTOSIEM_DB", str(tmp_path / "api.db"))
    client = TestClient(app, raise_server_exceptions=False)
    response = client.post("/api/ingest", content=_nested(depth), headers={"content-type": content_type})
    assert response.status_code == 400
    assert response.json() == {"detail": "invalid event payload"}


def test_api_accepts_json_at_the_limit(monkeypatch, tmp_path) -> None:
    monkeypatch.setenv("AUTOSIEM_DB", str(tmp_path / "api.db"))
    client = TestClient(app, raise_server_exceptions=False)
    response = client.post("/api/ingest", content=_nested(MAX_JSON_DEPTH), headers={"content-type": "application/json"})
    assert response.status_code == 200
    assert response.json()["accepted"] == 1


def test_cli_ingest_keeps_the_good_lines_around_a_deep_one(capsys, monkeypatch, tmp_path) -> None:
    events = tmp_path / "mixed.jsonl"
    events.write_text(
        "\n".join(
            [
                json.dumps({"user": "alice", "action": "login"}),
                _nested(5000),
                json.dumps({"user": "bob", "action": "login"}),
            ]
        )
        + "\n",
        encoding="utf-8",
    )
    monkeypatch.setattr(
        sys, "argv", ["autosiem", "ingest", "--file", str(events), "--db", str(tmp_path / "cli.db"), "--rules", str(ROOT / "rules")]
    )
    main()
    payload = json.loads(capsys.readouterr().out.split("\n=== AI Investigation Report ===")[0])
    assert payload["events"] == 3
