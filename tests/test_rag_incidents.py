"""Tests for RAG over historical incidents.

`RagEngine` always accepted an `incidents` list, but `default_rag_engine()`
never supplied one, so in practice the index held runbooks only.
"""

from __future__ import annotations

import json

from autosiem.rag import DEFAULT_INCIDENT_LIMIT, default_rag_engine, incident_doc
from autosiem.storage import DEFAULT_TENANT, AutoSIEMStorage

EVENTS = [
    {"timestamp": "2026-08-04T10:12:00Z", "category": "process", "action": "process_start", "user": "alice", "host": "ws-7", "process_name": "LockBit.exe", "command_line": "LockBit.exe -encrypt C:\\docs\\q3.xlsx"},
]


class BrokenStore:
    def list_incidents(self, limit: int = 50, tenant_id: str | None = None):
        raise RuntimeError("database is locked")


# --- document rendering ----------------------------------------------------


def test_incident_doc_is_labelled_and_carries_the_resolution() -> None:
    """"We closed this as a false positive" is the useful part of history."""
    doc = incident_doc(
        {
            "title": "Suspicious activity involving user:alice",
            "status": "resolved",
            "resolution": "false positive, sanctioned admin tooling",
            "data": {"summary": "3 findings", "mitre_attack": ["T1003"], "entities": ["user:alice"]},
        }
    )
    assert doc.startswith("[past incident] Suspicious activity involving user:alice")
    assert "status=resolved" in doc
    assert "false positive, sanctioned admin tooling" in doc
    assert "T1003" in doc
    assert "user:alice" in doc


def test_incident_doc_reads_top_level_fields_too() -> None:
    doc = incident_doc({"title": "T", "mitre_attack": ["T1486"], "summary": "s"})
    assert "T1486" in doc and "s" in doc


def test_incident_doc_tolerates_a_sparse_row() -> None:
    assert incident_doc({}).startswith("[past incident]")


# --- engine construction ---------------------------------------------------


def test_without_a_store_the_index_is_runbooks_only() -> None:
    engine = default_rag_engine()
    assert engine.retriever.documents
    assert all(doc.startswith("[runbook]") for doc in engine.retriever.documents)


def test_runbooks_are_labelled() -> None:
    engine = default_rag_engine()
    assert any("credential-dumping" in doc for doc in engine.retriever.documents)


def test_a_store_adds_past_incidents_to_the_index(tmp_path) -> None:
    db = tmp_path / "rag.db"
    store = AutoSIEMStorage(db)
    runbooks_only = len(default_rag_engine().retriever.documents)

    _seed(store)
    engine = default_rag_engine(store, tenant_id=DEFAULT_TENANT)

    assert len(engine.retriever.documents) == runbooks_only + 1
    assert any(doc.startswith("[past incident]") for doc in engine.retriever.documents)


def test_a_resolved_incident_is_retrievable_by_its_techniques(tmp_path) -> None:
    store = AutoSIEMStorage(tmp_path / "rag.db")
    incident_id = _seed(store)
    store.update_incident(
        incident_id, status="resolved", resolution="confirmed ransomware, host reimaged", actor="analyst"
    )

    engine = default_rag_engine(store, tenant_id=DEFAULT_TENANT)
    context = engine.build_prompt(
        {"title": "ransomware on a workstation", "mitre_attack": ["T1486"], "summary": "encryption"},
        top_k=5,
    )
    assert "[past incident]" in context
    assert "confirmed ransomware, host reimaged" in context


def test_incidents_are_tenant_scoped(tmp_path) -> None:
    store = AutoSIEMStorage(tmp_path / "rag.db")
    _seed(store)  # written under DEFAULT_TENANT

    other = default_rag_engine(store, tenant_id="someone-else")
    assert not any(doc.startswith("[past incident]") for doc in other.retriever.documents)


def test_the_incident_limit_is_respected(tmp_path) -> None:
    store = AutoSIEMStorage(tmp_path / "rag.db")
    _seed(store)
    engine = default_rag_engine(store, tenant_id=DEFAULT_TENANT, incident_limit=0)
    assert not any(doc.startswith("[past incident]") for doc in engine.retriever.documents)


def test_a_broken_store_degrades_to_runbooks_only() -> None:
    """A failing store must not stop an investigation from running."""
    engine = default_rag_engine(BrokenStore())
    assert engine.retriever.documents
    assert all(doc.startswith("[runbook]") for doc in engine.retriever.documents)


def test_default_incident_limit_is_sane() -> None:
    assert 0 < DEFAULT_INCIDENT_LIMIT <= 500


# --- bulk indexing ---------------------------------------------------------


def test_add_docs_indexes_everything_in_one_rebuild() -> None:
    engine = default_rag_engine()
    before = len(engine.retriever.documents)
    engine.retriever.add_docs(["alpha beta", "gamma delta"])
    assert len(engine.retriever.documents) == before + 2
    assert engine.retriever.retrieve("gamma", top_k=1)


def test_add_docs_with_nothing_is_a_no_op() -> None:
    engine = default_rag_engine()
    before = len(engine.retriever.documents)
    engine.retriever.add_docs([])
    assert len(engine.retriever.documents) == before


def _seed(store: AutoSIEMStorage) -> str:
    """Run one pipeline pass so the store holds a real incident."""
    from autosiem.pipeline import AutoSIEMPipeline
    from autosiem.rules import load_rules
    from pathlib import Path

    root = Path(__file__).resolve().parents[1]
    result = AutoSIEMPipeline(load_rules(root / "rules")).process_lines([json.dumps(EVENTS[0])])
    store.save_pipeline_result(result)
    return result.incidents[0].incident_id
