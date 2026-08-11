"""Outbound transport policy (net.py) — SEC-017.

The data AutoSIEM pulls decides what it detects, and none of it is signed, so
transport is the only integrity check available. These tests pin the rule down
at each place it is applied.
"""
from __future__ import annotations

import json
from pathlib import Path

import pytest

from autosiem.attack_matrix import ATTACK_INDEX_URL, refresh_index
from autosiem.llm import LLMConfig, LLMError, make_backend
from autosiem.net import InsecureURLError, is_loopback, require_https
from autosiem.update_job import UpdateJob


# --------------------------------------------------------------------------
# the rule itself
# --------------------------------------------------------------------------


def test_https_is_allowed() -> None:
    assert require_https("https://example.test/bundle.json") == "https://example.test/bundle.json"


def test_plaintext_remote_is_refused() -> None:
    with pytest.raises(InsecureURLError, match="non-HTTPS"):
        require_https("http://example.test/bundle.json")


def test_insecure_url_error_is_a_value_error() -> None:
    """Existing `except ValueError` handlers keep working."""
    assert issubclass(InsecureURLError, ValueError)


def test_loopback_is_refused_unless_opted_in() -> None:
    with pytest.raises(InsecureURLError):
        require_https("http://localhost:1234/v1")
    assert require_https("http://localhost:1234/v1", allow_loopback=True)


@pytest.mark.parametrize(
    "url",
    ["http://localhost:1234/v1", "http://127.0.0.1:11434", "http://127.0.0.5:8080", "http://[::1]:9000"],
)
def test_loopback_forms_are_recognised(url: str) -> None:
    assert is_loopback(url) is True
    assert require_https(url, allow_loopback=True) == url


@pytest.mark.parametrize(
    "url",
    ["http://example.test/x", "http://10.0.0.5:1234/v1", "http://127evil.example/x", "http://localhost.evil.test/x"],
)
def test_non_loopback_hosts_are_not_exempted(url: str) -> None:
    """A hostname that merely starts with `localhost` or `127` is remote."""
    assert is_loopback(url) is False
    with pytest.raises(InsecureURLError):
        require_https(url, allow_loopback=True)


def test_empty_url_is_refused() -> None:
    with pytest.raises(InsecureURLError):
        require_https("", allow_loopback=True)


# --------------------------------------------------------------------------
# threat intel — the finding's primary target
# --------------------------------------------------------------------------


def test_intel_refresh_refuses_plaintext_and_reports_why(tmp_path: Path) -> None:
    job = UpdateJob(db_path=tmp_path / "a.db", intel_url="http://feed.test/bundle.json")
    report = job.run_once()
    assert report.intel_refreshed is False
    assert any("intel refresh failed" in message for message in report.messages)
    assert any("non-HTTPS" in message for message in report.messages)
    # The rest of the cycle still ran.
    assert report.coverage["matrix"]["available"] is True


def test_intel_refresh_accepts_https(tmp_path: Path, monkeypatch) -> None:
    """The guard rejects the scheme, not the feed."""
    import autosiem.update_job as update_job

    class _Response:
        def __enter__(self):
            return self

        def __exit__(self, *args):
            return False

        def read(self):
            return json.dumps({"type": "bundle", "objects": []}).encode()

    monkeypatch.setattr(update_job.urllib.request, "urlopen", lambda url, timeout=0: _Response())
    job = UpdateJob(db_path=tmp_path / "a.db", intel_url="https://feed.test/bundle.json")
    report = job.run_once()
    assert not any("non-HTTPS" in message for message in report.messages)


# --------------------------------------------------------------------------
# ATT&CK refresh
# --------------------------------------------------------------------------


def test_attack_refresh_refuses_a_plaintext_bundle_url(tmp_path: Path) -> None:
    index = {
        "collections": [
            {
                "name": "Enterprise ATT&CK",
                "versions": [{"version": "19.2", "url": "http://mirror.test/e.json", "modified": ""}],
            }
        ]
    }

    def fetch(url: str) -> bytes:
        if url == ATTACK_INDEX_URL:
            return json.dumps(index).encode()
        raise AssertionError("must not fetch the bundle over http")

    with pytest.raises(InsecureURLError):
        refresh_index(tmp_path / "attack.json", fetch=fetch)


# --------------------------------------------------------------------------
# LLM endpoint
# --------------------------------------------------------------------------


def test_local_model_servers_still_work() -> None:
    """LM Studio and Ollama on loopback are the documented defaults."""
    assert make_backend(LLMConfig(backend="openai_compat")) is not None
    assert make_backend(LLMConfig(backend="ollama")) is not None
    assert make_backend(LLMConfig(backend="openai_compat", base_url="http://localhost:1234/v1")) is not None


def test_remote_plaintext_llm_endpoint_is_refused_at_construction() -> None:
    """Fail at startup, not silently per incident.

    Prompts carry incident detail. Falling back quietly would hide that the
    operator pointed AutoSIEM at a cleartext remote endpoint.
    """
    with pytest.raises(LLMError, match="non-HTTPS"):
        make_backend(LLMConfig(backend="openai_compat", base_url="http://llm.example.test/v1"))


def test_remote_https_llm_endpoint_is_accepted() -> None:
    backend = make_backend(LLMConfig(backend="openai_compat", base_url="https://llm.example.test/v1"))
    assert backend is not None
    assert backend.base_url == "https://llm.example.test/v1"


def test_disabled_backend_needs_no_url() -> None:
    assert make_backend(LLMConfig(backend="none")) is None
