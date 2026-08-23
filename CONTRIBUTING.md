# Contributing to AutoSIEM

## Setup

```bash
git clone https://github.com/kpulik/autosiem.git
cd autosiem
pip install -e '.[api,dev]'
```

Everything runs from source with `PYTHONPATH=src`. No database server, message
broker, or cloud account is needed.

## The one rule that matters: zero runtime dependencies

`src/autosiem/**` imports **only the Python standard library**. Network calls go
through `urllib`. The Sigma/YAML parser in `sigma.py` is a deliberate subset
written by hand — **do not add PyYAML**, and do not add any other third-party
package to the core.

Third-party packages are allowed only in optional extras declared in
`pyproject.toml`:

- `api` — `fastapi`, `uvicorn` (the optional web UI/API)
- `dev` — `pytest`, `httpx` (tests)

Optional integrations that need a real driver (Kafka via `kafka-python`) must
degrade gracefully when the package is absent — see `KafkaBus` in `bus.py` for
the pattern: construct in an `available=False` state, raise a helpful
`RuntimeError` only when actually used.

## Before you open a PR

1. **Tests pass.**
   ```bash
   PYTHONPATH=src python3 -m pytest tests/ -q
   ```
2. **Type check is clean.**
   ```bash
   pyright
   ```
3. **Coverage smoke test runs.**
   ```bash
   PYTHONPATH=src python3 -m autosiem.cli coverage --rules rules
   ```

CI (`.github/workflows/ci.yml`) runs all three on Python 3.10 and 3.12. All
three must pass.

## Refreshing the ATT&CK matrix

Coverage is measured against a distilled copy of MITRE's published ATT&CK
Enterprise bundle, vendored at `src/autosiem/attack_enterprise_index.json` so
the report works offline. After an ATT&CK release:

```bash
python3 scripts/build_attack_index.py          # latest released version
python3 scripts/build_attack_index.py --version 19.1   # or pin one
```

Operators do not need this script: `cli update --refresh-attack` performs the
same refresh at runtime, writing beside the database rather than into the
package. Both call `autosiem.attack_matrix.distill_bundle`, so they produce
byte-identical output for the same ATT&CK release. Output is fully determined by
the upstream bundle, with no timestamps or machine-local values. Commit the regenerated index with the ATT&CK
version in the commit message, and re-run the suite: a tactic rename will change
incident kill-chain summaries.

## Adding a detection rule

New rules ship tested or the suite fails — `tests/test_rules.py` asserts that
every rule in `rules/` has at least one positive and one negative case.

1. Add `rules/<name>.json` (or a Sigma `.yaml`). See `docs/tutorial.md` §6 for
   the schema and `rules/failed_login.json` for a minimal example.
2. Add positive + negative cases to `tests/test_rules.py`.
3. Run `PYTHONPATH=src python3 -m autosiem.cli coverage --rules rules` and
   confirm the technique count moved as you expect. Check
   `matrix.unknown_technique_ids` is empty — a technique ID MITRE does not
   publish is a typo or a revoked technique, and the suite fails on it.

Rule JSON files may begin with `//` or `#` comment lines — the loader strips
them. Your editor will flag those as JSON syntax errors; that is expected, do
not "fix" it by quoting the comments.

Available selection operators are defined by `_match_operator` in
`detection.py`: plain equality, list membership, `contains`, `contains_any`,
`contains_all`, `startswith`, `endswith`, their `*_any`/`*_all` variants,
`regex`, `in`, `not_in`, `not_equals`, `exists`, and their exact negative
string variants. Recursive `any_of`, `all_of`, and `not` nodes represent
Boolean conditions. Numeric comparison is not implemented.

## Adding a connector

1. Subclass `BaseConnector` (or `FilePollerConnector`) in `connectors.py`.
2. Write a `<vendor>_to_raw()` mapping function that emits the normalized field
   names — see `okta_to_raw` for the shape.
3. Register it in the module-level `registry`.
4. Add a test in `tests/test_connectors.py` using a realistic sample record.
5. Confirm the events it produces actually fire a rule; a connector that
   normalizes into fields no rule reads is not finished.

## Code conventions

- Python 3.10+, `from __future__ import annotations` at the top of every module.
- Type hints on every public function. `pyrightconfig.json` runs `basic` mode.
- Docstrings on public classes and functions; explain *why*, not *what*.
- Dataclasses for data, plain classes for behaviour.
- Keep modules single-purpose. `cli.py`, `storage.py`, and `web/api.py` are the
  shared integration points — change them surgically.

## Security changes

Read [`SECURITY.md`](SECURITY.md) first. Anything touching authentication,
the RBAC model, the ingest surface, or the audit chain needs a test that proves
the control actually blocks the thing it claims to block — see
`tests/test_security_fixes.py`. Report vulnerabilities privately rather than
opening a public issue.

## Things not to change

- `data/autosiem.db` is local dev data. Tests use temp databases; never commit
  changes to it.
- The audit log is a hash chain. Any new column or write path must preserve
  `verify_audit_chain()` returning empty.
