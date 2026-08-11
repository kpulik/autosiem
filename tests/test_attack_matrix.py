"""The vendored ATT&CK Enterprise matrix (attack_matrix.py).

Offline by construction: every test reads the index shipped inside the package,
so none of this needs a network call.
"""
from __future__ import annotations

import json
from pathlib import Path

import pytest

from autosiem.attack_matrix import (
    INDEX_PATH,
    AttackMatrix,
    AttackMatrixUnavailable,
    Technique,
    load_matrix,
    load_matrix_file,
)
from autosiem.coverage import tactic_for


def test_vendored_index_loads() -> None:
    matrix = load_matrix()
    assert isinstance(matrix, AttackMatrix)
    assert matrix.attack_version
    assert matrix.source_url.startswith("https://")
    # A real matrix, not a stub: Enterprise has hundreds of techniques.
    assert len(matrix) > 400
    assert len(matrix.tactics) > 10


def test_index_is_internally_consistent() -> None:
    """Counts in the file match the data in the file."""
    payload = json.loads(INDEX_PATH.read_text(encoding="utf-8"))
    techniques = payload["techniques"]
    assert payload["technique_count"] == len(techniques)
    parents = [t for t in techniques.values() if not t["sub"]]
    assert payload["parent_technique_count"] == len(parents)
    assert payload["sub_technique_count"] == len(techniques) - len(parents)
    used = {tactic for entry in techniques.values() for tactic in entry["tactics"]}
    assert set(payload["tactics"]) == used


def test_known_technique_lookup() -> None:
    matrix = load_matrix()
    technique = matrix.get("T1059")
    assert technique is not None
    assert technique.name == "Command and Scripting Interpreter"
    assert "execution" in technique.tactics
    assert technique.is_subtechnique is False


def test_subtechnique_knows_its_parent() -> None:
    matrix = load_matrix()
    technique = matrix.get("T1059.001")
    assert technique is not None
    assert technique.is_subtechnique is True
    assert technique.parent_id == "T1059"


def test_lookup_is_case_insensitive_and_whitespace_tolerant() -> None:
    matrix = load_matrix()
    assert matrix.get("  t1059.001 ") == matrix.get("T1059.001")
    assert "t1059" in matrix


def test_resolve_falls_back_to_parent() -> None:
    """A sub-technique MITRE has not published still resolves to its parent."""
    matrix = load_matrix()
    assert matrix.get("T1059.999") is None
    resolved = matrix.resolve("T1059.999")
    assert resolved is not None and resolved.technique_id == "T1059"
    assert matrix.tactics_for("T1059.999") == matrix.tactics_for("T1059")


def test_unknown_technique_resolves_to_nothing() -> None:
    matrix = load_matrix()
    assert matrix.get("T9999") is None
    assert matrix.resolve("T9999") is None
    assert matrix.tactics_for("T9999") == ()


def test_parent_ids_excludes_subtechniques() -> None:
    matrix = load_matrix()
    parents = matrix.parent_ids()
    assert "T1059" in parents
    assert "T1059.001" not in parents
    assert len(parents) < len(matrix)


def test_missing_index_raises_rather_than_reporting_an_empty_matrix() -> None:
    """An empty matrix would report 0% coverage, a wrong number, not a missing one."""
    with pytest.raises(AttackMatrixUnavailable) as excinfo:
        load_matrix_file("/nonexistent/attack_index.json")
    assert "build_attack_index.py" in str(excinfo.value)


def test_corrupt_index_raises(tmp_path: Path) -> None:
    broken = tmp_path / "broken.json"
    broken.write_text("{not json", encoding="utf-8")
    with pytest.raises(AttackMatrixUnavailable):
        load_matrix_file(broken)


def test_matrix_can_be_loaded_from_an_explicit_path(tmp_path: Path) -> None:
    """Pinning an older ATT&CK release is a supported thing to do."""
    index = tmp_path / "mini.json"
    index.write_text(
        json.dumps(
            {
                "attack_version": "0.1-test",
                "source_url": "https://example.invalid/bundle.json",
                "source_modified": "2026-01-01T00:00:00.000Z",
                "tactics": ["execution"],
                "techniques": {"T0001": {"name": "Test", "tactics": ["execution"], "sub": False}},
            }
        ),
        encoding="utf-8",
    )
    matrix = load_matrix_file(index)
    assert matrix.attack_version == "0.1-test"
    assert len(matrix) == 1
    assert matrix.get("T0001") == Technique("T0001", "Test", ("execution",), False)


def test_tactic_for_only_returns_tactics_the_matrix_publishes() -> None:
    """The drift guard.

    coverage.py used to carry a hand-written technique -> tactic table that fell
    out of date with ATT&CK (it still said `defense-evasion` after MITRE had
    reorganised those techniques). Deriving tactics from the published matrix is
    what stops that recurring, so assert the invariant rather than a specific
    tactic name that MITRE may rename again.
    """
    matrix = load_matrix()
    published = set(matrix.tactics)
    checked = 0
    for technique_id in list(matrix.techniques)[:200]:
        tactic = tactic_for(technique_id)
        if tactic is not None:
            assert tactic in published, f"{technique_id} -> {tactic!r} is not a published tactic"
            checked += 1
    assert checked > 100


def test_tactic_for_unknown_technique_is_none() -> None:
    assert tactic_for("T9999") is None
