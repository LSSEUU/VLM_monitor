# LabCourt repository cleanup inventory

Audit date: 2026-09-02  
Baseline commit: `dc09dedc4fbfb28ceecc102bcdd2470d9ae76b1d`  
Backup tag: `pre-cleanup-v0.1.0`  
Cleanup branch: `chore/repository-cleanup`

This report was created before any cleanup deletion. It covers all 2,033 files
tracked at the baseline commit. Existing user changes in
`src/labcourt/m8_ui_web/app.{css,html,js}` and the untracked
`tests/unit/test_m8_ui_case_detail_loading.py` are user-owned and excluded from
cleanup edits. The untracked `prompt.md` is the task brief, not a product
artifact, and is also excluded.

## Method

Candidates were checked against Python imports, package exports, the
`labcourt` console script, Typer command registration, configuration and
dynamic resource paths, schema generation, both migration chains, tests and
fixtures, documentation links, the Makefile, Windows launchers, and Git ignore
rules. File names such as `legacy`, `m3`, `m4`, `m5`, `demo`, and `test` were
never treated as deletion evidence.

The baseline has no Dockerfile or CI workflow. `pyproject.toml` is the package
and dependency authority; `requirements/perception-worker.txt` intentionally
describes the isolated GPU worker environment.

## Complete classification

The rows below are mutually exclusive. Their counts sum to the 2,033 tracked
files at the baseline commit.

| Class | Count | Paths | Decision |
|---|---:|---|---|
| KEEP | 1,938 | package metadata; `.labcourt-local/feishu-secrets.example.json`; `configs/pilot.yaml`; `configs/policies/**`; current and specialist docs; `docs/architecture-decisions/**`; the two current specs; `inputs/.gitkeep`; current and M8 v2 prompts; `requirements/perception-worker.txt`; `runs/.gitkeep`; `schemas/**`; retained build/demo/operations scripts; `src/**` except the item under REVIEW; `tests/**` except the item under REVIEW | Required by install, runtime, replay, contracts, tests, operations, or current documentation. |
| CONSOLIDATE | 42 | all 26 baseline root `*.cmd` wrappers and 16 single-operation `scripts/windows/labcourt-demo-*.ps1` files | Replace duplicate wrappers with one root Windows launcher and one demo dispatcher; preserve the Python CLI as the command authority and publish a migration table. |
| ARCHIVE | 46 | `docs/milestones/**` (8), `docs/progress/**` (8), `docs/spec/labcourt-v0.2-fast-pilot-spec.md` (1), eight historical runtime prompt files, and the 21 non-duplicate files in `previews/labcourt-ops-ui/**` | Preserve history or design/replay value outside the current documentation/runtime-default path. Historical prompt bytes remain loadable by their frozen bundle hashes. |
| DELETE | 3 | the three timestamp-named MP4 files listed below | Exact byte duplicates of named design assets, with no runtime/test reference. |
| REVIEW | 4 | `configs/default.yaml`, `configs/demo.yaml`, `src/labcourt/m8_feishu_webhook_server.py`, `tests/integration/test_m8_feishu_webhook_server.py` | Config copies have frozen hashes and the webhook module retains a tested loopback challenge contract. Keep until a separate contract migration proves safe replacement. |

## Architecture and entrypoint findings

The current architecture is the frozen M0-M6 contract-first core plus the
additive M8 campus-operations platform. The authoritative specifications are:

- `docs/spec/labcourt-vibe-coding-spec.md` for M0-M6;
- `docs/spec/labcourt-campus-operations-spec.md` for M8;
- generated Pydantic schemas, migrations, prompts, manifests, tests, and the
  current code when an old progress document lags behind HEAD.

`docs/milestones/M8.md` stops at an older M8.7 sub-slice while HEAD includes
later Agent, Feishu live, evaluation, prehearing, calibration, and platform
integration. It is therefore historical progress, not the current executable
specification.

The only installed console entrypoint is
`labcourt = "labcourt.cli:app"`. The formal M8 web UI is
`src/labcourt/m8_ui_web/`, served by `labcourt demo platform`. The Pilot UI is
a separate retained workflow. `previews/labcourt-ops-ui/` is design-only and
has no backend, authority, authentication, or runtime import.

## Deletion evidence

The timestamp MP4 files duplicate the canonical named assets byte for byte:

| Delete | Keep | SHA-256 |
|---|---|---|
| `previews/labcourt-ops-ui/1786190627618...mp4` | `previews/labcourt-ops-ui/assets/feed-301a.mp4` | `a3dae5a59000d12fdcadf068af2b4cb2cf6bdcae755f240bfdc6ce95ba47707d` |
| `previews/labcourt-ops-ui/1786190630676...mp4` | `previews/labcourt-ops-ui/assets/feed-301b.mp4` | `774e04b2a9f03135eecc5983454b8f006b891d829d29f0a7c1fef7bcf2d69726` |
| `previews/labcourt-ops-ui/1786193409682...mp4` | `previews/labcourt-ops-ui/assets/feed-302a.mp4` | `4bd6c5939c4cbb9e48b1856582ad754c4b42107a2078bccd324536b546632fef` |

Reference search found the timestamp names only in the design handoff and
manifest; runtime HTML uses the named `assets/feed-*.mp4` files. The manifest
and handoff will be updated before deletion.

Ignored caches, `dist/`, `runs/`, `.labcourt-local/`, and local `inputs/*` are
not tracked repository content. They are not cleanup patch targets because
they may contain a developer's local evaluation artifacts or credentials.

## Prompt inventory

| Role | Version/path | Caller | Default? |
|---|---|---|---|
| M3 screening and structure repair | `prompts/screening_*_v1.jinja` | `services/m3.py` through `JinjaPromptCatalog` | Yes |
| M4 prosecutor/defender/judge | `prompts/hearing_*_v1.jinja` | `services/m4_operations.py` | Yes |
| M8 hearing v2 | `prompts/m8_v2/hearing_*_v1.jinja` | M8 hearing runtime and Qwen demo | Explicit M8/Qwen profile |
| Frozen M3/M4 replay | historical prompt bundle (to move under `prompts/archive/`) | bundle-hash selection in M3/M4 composition | No; replay only |
| Citation-required M3 replay | historical citation-required bundle | bundle-hash selection in M3 composition | No; replay only |

Historical prompt contents are unique and referenced by frozen bundle hashes;
they are archive candidates, never deletion candidates.

## Baseline execution record

Environment:

- host Python: 3.14.3 (outside the supported range);
- fresh uv environment: CPython 3.11.15;
- uv: 0.11.16;
- install: `uv sync --all-groups --locked` succeeded with 39 packages;
- Windows host: `make` unavailable, so the exact Makefile recipes were run
  directly with `uv run --locked`.

Quality baseline before cleanup:

| Gate | Result |
|---|---|
| Ruff format check | Failed: 84 files would be reformatted; 1,175 already formatted |
| Ruff lint | Passed |
| Mypy | Failed: 23 errors in 6 files (725 source files checked) |
| Pytest | Collection stopped: 6,107 items found; optional `cv2` was imported by an unguarded video test; 2 optional-provider tests skipped |
| Schema check | Passed: 471 models / 472 files including `index.json` |
| M4 branch coverage | Passed: 129 tests, 100% |
| M5 branch coverage | Passed: 52 tests, 100% |
| M6 offline demo | Passed: all 16 deterministic scenarios |
| M8 personal bootstrap/API check | Passed |
| Formal M8 platform/UI preflight | Passed |

These failures predate cleanup and will not be represented as cleanup
regressions. The formatting and typing repairs are behavior-neutral. The
real-video integration test will remain active with the `video` extra and skip
cleanly in the documented default offline environment.

## Items retained despite suspicion

- No Python module has sufficient no-reference evidence for deletion.
- All 471 registered contract models and all 472 generated schema files match
  the schema registry; no schema is orphaned.
- Main and M8 migrations are continuous through their current versions and
  checksum guarded; old migrations cannot be removed.
- Versioned M3-M6 modules remain imported by compatibility, replay, migration,
  or regression paths.
- The apparent duplicate configs are retained because YAML aliases/merge keys
  are deliberately rejected and their canonical bytes participate in frozen
  authorities.
- The legacy loopback webhook module remains tested; deletion needs a separate
  public-API deprecation decision.
- The wheel must be checked for `adapters/storage/m8_migrations/*.sql`; the
  current build configuration does not make that inclusion explicit.

## Planned verification

After cleanup: recursive package import; all public CLI `--help` paths; schema
regeneration with no diff; wheel content and isolated install smoke; formal
platform/API/offline demo smoke; the focused launcher/prompt/package tests;
then one complete quality gate in a clean checkout. Docker is not presently a
supported artifact because the repository has no Dockerfile; the deployment
document will record that real blocker rather than invent an unverified image.
