"""RAG over runbooks and historical incidents (zero runtime dependencies).

A lightweight, deterministic retrieval layer: runbook documents (plain Markdown
under ``docs/runbooks/``) and past incident summaries are indexed, then a
TF-IDF-lite keyword scorer retrieves the most relevant context to feed an LLM
(or the local ``Investigator``) with evidence for a given incident/technique.
"""

from __future__ import annotations

import math
import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from .schemas import Incident
from .storage_ports import IncidentQueryStore

_STOPWORDS = frozenset(
    {
        "the", "a", "an", "and", "or", "of", "to", "in", "for", "on", "with",
        "as", "by", "at", "from", "this", "that", "these", "those", "is", "are",
        "was", "were", "be", "been",
    }
)

# Default location for the markdown runbooks RAG indexes. Relative to the
# package (src/autosiem/rag.py -> project root) so it works from any CWD.
DEFAULT_RUNBOOKS_DIR = Path(__file__).resolve().parents[2] / "docs" / "runbooks"


#: Past incidents pulled into the index when a store is supplied.
DEFAULT_INCIDENT_LIMIT = 50


def _runbook_doc(doc: "Runbook") -> str:
    """Label a runbook so retrieved context says what it is."""
    return f"[runbook] {doc.name}\n{doc.content}"


def incident_doc(row: dict[str, Any]) -> str:
    """Render a stored incident row as an indexable, self-describing document.

    Includes status and resolution: "we saw this before and closed it as a false
    positive" is the single most useful thing history can tell an analyst.
    """
    raw_data = row.get("data")
    data: dict[str, Any] = raw_data if isinstance(raw_data, dict) else {}
    title = row.get("title") or data.get("title") or ""
    summary = data.get("summary") or row.get("summary") or ""
    techniques = data.get("mitre_attack") or row.get("mitre_attack") or []
    entities = data.get("entities") or row.get("entities") or []
    parts = [f"[past incident] {title}"]
    status = row.get("status")
    resolution = row.get("resolution")
    if status:
        parts.append(f"status={status}")
    if resolution:
        parts.append(f"resolution={resolution}")
    if techniques:
        parts.append(" ".join(str(item) for item in techniques))
    if entities:
        parts.append(" ".join(str(item) for item in entities))
    if summary:
        parts.append(str(summary))
    return " | ".join(parts)


def default_rag_engine(
    store: IncidentQueryStore | None = None,
    tenant_id: str | None = None,
    incident_limit: int = DEFAULT_INCIDENT_LIMIT,
) -> "RagEngine":
    """RAG over the bundled runbooks, plus past incidents when a store is given.

    Without ``store`` this is runbook-only, which is what library callers and
    tests get. The CLI and API pass their storage so an investigation can be
    informed by how similar incidents were previously resolved.
    """
    runbooks = RunbookIndex.from_dir(DEFAULT_RUNBOOKS_DIR)
    documents = [_runbook_doc(doc) for doc in runbooks.docs]
    if store is not None:
        try:
            rows = store.list_incidents(limit=incident_limit, tenant_id=tenant_id)
        except Exception:
            rows = []
        documents.extend(incident_doc(row) for row in rows)
    return RagEngine(KeywordRetriever(documents))


def _tokenize(text: str) -> list[str]:
    return [token for token in re.findall(r"[a-z0-9]+", (text or "").lower()) if token not in _STOPWORDS]


def _parse_techniques(text: str) -> list[str]:
    """Extract ATT&CK technique codes (``T1059``, ``T1059.001``, ...)."""
    found: list[str] = []
    for match in re.finditer(r"\bT\d{3,5}(?:\.\d+)?\b", text):
        code = match.group(0)
        if code not in found:
            found.append(code)
    return found


@dataclass(slots=True)
class Runbook:
    """One indexed runbook document."""

    name: str
    content: str
    path: str = ""
    techniques: list[str] = field(default_factory=list)

    def __post_init__(self) -> None:
        if not self.techniques:
            self.techniques = _parse_techniques(self.content)


class RunbookIndex:
    """Collects runbook documents for retrieval."""

    def __init__(self, docs: list[Runbook] | None = None) -> None:
        self.docs: list[Runbook] = list(docs or [])

    def add_doc(self, text: str, name: str | None = None, path: str = "") -> Runbook:
        doc = Runbook(name=name or path or f"doc-{len(self.docs) + 1}", content=text, path=path, techniques=_parse_techniques(text))
        self.docs.append(doc)
        return doc

    @classmethod
    def from_dir(cls, docs_dir: str | Path) -> "RunbookIndex":
        index = cls()
        root = Path(docs_dir)
        for md_path in sorted(root.rglob("*.md")):
            try:
                content = md_path.read_text(encoding="utf-8")
            except OSError:
                continue
            index.add_doc(content, name=md_path.stem, path=str(md_path))
        return index


class KeywordRetriever:
    """TF-IDF-lite keyword retrieval over a set of documents."""

    def __init__(self, documents: list[str] | None = None) -> None:
        self.documents: list[str] = list(documents or [])
        self._doc_terms: list[dict[str, int]] = []
        self._term_index: dict[str, set[int]] = {}
        self._rebuild()

    def _rebuild(self) -> None:
        self._term_index = {}
        self._doc_terms = []
        for doc_index, doc in enumerate(self.documents):
            terms: dict[str, int] = {}
            for token in _tokenize(doc):
                terms[token] = terms.get(token, 0) + 1
                self._term_index.setdefault(token, set()).add(doc_index)
            self._doc_terms.append(terms)

    def add_doc(self, text: str) -> None:
        self.documents.append(text)
        self._rebuild()

    def add_docs(self, texts: list[str]) -> None:
        """Bulk add with a single rebuild (add_doc rebuilds per document)."""
        if not texts:
            return
        self.documents.extend(texts)
        self._rebuild()

    def _idf(self, term: str) -> float:
        n = max(len(self.documents), 1)
        df = len(self._term_index.get(term, ()))
        return math.log((1 + n) / (1 + df)) + 1.0

    def score_doc(self, doc_index: int, query: str) -> float:
        terms = self._doc_terms[doc_index] if doc_index < len(self._doc_terms) else {}
        return sum(terms.get(token, 0) * self._idf(token) for token in _tokenize(query))

    def retrieve(self, query: str, top_k: int = 5, docs: list[str] | None = None) -> list[tuple[float, str]]:
        if docs is not None:
            return self._retrieve_subset(query, top_k, docs)
        scored = [(self.score_doc(i, query), self.documents[i]) for i in range(len(self.documents)) if self.score_doc(i, query) > 0]
        scored.sort(key=lambda item: item[0], reverse=True)
        return scored[:top_k]

    def _retrieve_subset(self, query: str, top_k: int, docs: list[str]) -> list[tuple[float, str]]:
        offsets = [self.documents.index(doc) for doc in docs if doc in self.documents]
        scored = [(self.score_doc(i, query), self.documents[i]) for i in offsets if self.score_doc(i, query) > 0]
        scored.sort(key=lambda item: item[0], reverse=True)
        return scored[:top_k]

    def build_context(self, query: str, top_k: int = 5) -> str:
        hits = self.retrieve(query, top_k=top_k)
        sections = [f"-- source (score={score:.3f}) --\n{doc.strip()[:1500]}" for score, doc in hits]
        return "\n\n".join(sections)


class RagEngine:
    """Indexes runbooks + historical incidents and builds LLM context."""

    def __init__(self, retriever: KeywordRetriever | None = None, incidents: list[dict[str, Any]] | None = None) -> None:
        self.retriever = retriever or KeywordRetriever()
        self.incidents = list(incidents or [])
        self._index_incidents()

    def _index_incidents(self) -> None:
        self.retriever.add_docs([incident_doc(inc) for inc in self.incidents])

    @staticmethod
    def _query(incident: Incident | dict[str, Any]) -> str:
        if isinstance(incident, Incident):
            return f"{incident.title} {' '.join(incident.mitre_attack)} {incident.summary}"
        return f"{incident.get('title', '')} {' '.join(incident.get('mitre_attack') or [])} {incident.get('summary', '')}"

    def retrieve(self, incident: Incident | dict[str, Any], top_k: int = 5) -> list[tuple[float, str]]:
        return self.retriever.retrieve(self._query(incident), top_k=top_k)

    def build_prompt(self, incident: Incident | dict[str, Any], top_k: int = 5) -> str:
        context = self.retriever.build_context(self._query(incident), top_k=top_k)
        if not context:
            return ""
        return f"## Relevant runbooks / historical context\n\n{context}"


def augment_prompt(engine: RagEngine, incident: Incident | dict[str, Any], top_k: int = 5) -> str:
    """Return RAG context for an incident to append to an LLM prompt."""
    return engine.build_prompt(incident, top_k=top_k)
