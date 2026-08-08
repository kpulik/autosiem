from __future__ import annotations

from autosiem.rag import (
    KeywordRetriever,
    RagEngine,
    Runbook,
    RunbookIndex,
    augment_prompt,
)
from autosiem.schemas import Incident, Severity


def _incident() -> Incident:
    return Incident(
        incident_id="inc-1",
        title="PowerShell credential dumping",
        severity=Severity.CRITICAL,
        risk_score=500,
        entities=["host:workstation-01"],
        finding_ids=["f1"],
        mitre_attack=["T1059.001"],
        summary="Suspicious encoded PowerShell executing dump of credentials.",
    )


def test_retriever_ranks_relevant_doc_above_unrelated() -> None:
    retriever = KeywordRetriever(
        [
            "Runbook for credential dumping with mimikatz, lsass, sekurlsa.",
            "Runbook for phishing email delivery and spam quarantine.",
        ]
    )
    hits = retriever.retrieve("lsass credentials dump", top_k=2)
    assert hits
    assert "credential dumping" in hits[0][1]


def test_build_context_includes_relevant_source() -> None:
    retriever = KeywordRetriever(["Credential dumping uses lsass and mimikatz."])
    context = retriever.build_context("lsass dump", top_k=1)
    assert "mimikatz" in context.lower() or "lsass" in context.lower()


def test_ragengine_prompt_includes_matching_runbook(tmp_path) -> None:
    runbook = tmp_path / "runbooks"
    runbook.mkdir()
    (runbook / "cred-dump.md").write_text(
        "# techniques: T1059.001\n\nPowerShell execution: check hidden commands and encoded payloads.\n",
        encoding="utf-8",
    )
    index = RunbookIndex.from_dir(runbook)
    engine = RagEngine(retriever=KeywordRetriever([d.content for d in index.docs]))
    prompt = engine.build_prompt(_incident(), top_k=2)
    assert "PowerShell" in prompt or "encoded" in prompt


def test_augment_prompt_references_runbook_content() -> None:
    retriever = KeywordRetriever(["Exactly how to handle T1059 encoded PowerShell execution."])
    engine = RagEngine(retriever=retriever)
    prompt = augment_prompt(engine, _incident())
    assert prompt
    assert "## Relevant runbooks" in prompt


def test_runbook_dataclass(tmp_path) -> None:
    rb = Runbook(name="x", content="T1110 brute force login attempts", path="a.md")
    assert "T1110" in rb.techniques