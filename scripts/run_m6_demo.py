"""Run, assemble, atomically publish, and verify the complete offline M6 demo."""

from __future__ import annotations

import argparse
import hashlib
import importlib
import os
import subprocess
import sys
import tempfile
import xml.etree.ElementTree as ET
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parents[1]
SRC_ROOT = PROJECT_ROOT / "src"
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))
if str(SRC_ROOT) not in sys.path:
    sys.path.insert(0, str(SRC_ROOT))

from labcourt.adapters.storage.m6_demo_store import (  # noqa: E402
    M6OfflineDemoPublisher,
    ReadonlyM6OfflineDemoStore,
)
from labcourt.adapters.storage.m6_regression_execution_source_catalog_store import (  # noqa: E402
    M6RegressionExecutionSourceCatalogPublisher,
    ReadonlyM6RegressionExecutionSourceCatalogStore,
)
from labcourt.adapters.storage.m6_replay_locked_closed_policy_regression_store import (  # noqa: E402
    M6ReplayLockedClosedPolicyRegressionPublisher,
)
from labcourt.adapters.storage.m6_static_report_store import (  # noqa: E402
    M6PrivacySafeStaticReportPublisher,
    ReadonlyM6PrivacySafeStaticReportStore,
)
from labcourt.application.m6_demo import (  # noqa: E402
    M6OfflineDemoScenarioResultDocument,
    build_m6_offline_demo_publication,
)
from labcourt.application.m6_replay_locked_closed_policy_publication import (  # noqa: E402
    M6ReplayLockedClosedPolicyPublicationBundle,
)
from labcourt.application.m6_static_report import (  # noqa: E402
    M6PrivacySafeStaticReportBundle,
    build_m6_privacy_safe_static_report,
)
from labcourt.contracts.canonical import canonical_json  # noqa: E402
from labcourt.contracts.m6_demo import (  # noqa: E402
    M6OfflineDemoScenarioName,
    M6OfflineDemoScenarioResultAuthorityV1,
)
from labcourt.contracts.m6_static_report import (  # noqa: E402
    M6StaticReportEvidenceDisposition,
    M6StaticReportEvidenceItem,
)
from labcourt.contracts.m6_static_report_publication import (  # noqa: E402
    M6PrivacySafeStaticReportPublicationSealAuthorityV1,
)
from labcourt.exceptions import LabCourtError  # noqa: E402

_SCENARIO_FILE = "tests/e2e/test_m6_demo_scenarios.py"
_SCENARIO_NODE_IDS = tuple(
    f"{_SCENARIO_FILE}::test_{name.value}" for name in M6OfflineDemoScenarioName
)
_SCENARIO_TEST_NAMES = tuple(f"test_{name.value}" for name in M6OfflineDemoScenarioName)
_SCENARIO_TEST_CLASSNAME = "tests.e2e.test_m6_demo_scenarios"


class _M6DemoInvariantError(RuntimeError):
    pass


class _NoEvidenceProvider:
    def load(self, artifact_relative_path: str, content_sha256: str) -> object:
        raise RuntimeError("demo evidence provider must not be called")


def _precomputed_closed_publication() -> M6ReplayLockedClosedPolicyPublicationBundle:
    """Load the frozen synthetic evaluator fixture without making tests a typed dependency."""

    try:
        module = importlib.import_module(
            "tests.unit.test_m6_replay_locked_closed_policy_publication"
        )
    except ImportError as exc:
        raise _M6DemoInvariantError(
            "precomputed CLOSED publication fixture module is unavailable"
        ) from exc
    factory = getattr(module, "_publication", None)
    if not callable(factory):
        raise _M6DemoInvariantError("precomputed CLOSED publication fixture is unavailable")
    try:
        publication = factory()
    except Exception as exc:
        raise _M6DemoInvariantError(
            "precomputed CLOSED publication fixture factory failed"
        ) from exc
    if not isinstance(publication, M6ReplayLockedClosedPolicyPublicationBundle):
        raise _M6DemoInvariantError("precomputed CLOSED publication fixture has the wrong type")
    return publication


def _scenario_test_environment() -> dict[str, str]:
    environment = os.environ.copy()
    environment.pop("PYTEST_ADDOPTS", None)
    environment.pop("PYTEST_PLUGINS", None)
    environment["PYTEST_DISABLE_PLUGIN_AUTOLOAD"] = "1"
    return environment


def _verify_scenario_receipt(receipt_path: Path) -> None:
    try:
        root = ET.parse(receipt_path).getroot()
    except (OSError, ET.ParseError):
        raise _M6DemoInvariantError("scenario gate receipt is unavailable or malformed") from None

    testcases = tuple(root.iter("testcase"))
    actual_names = tuple(testcase.get("name") for testcase in testcases)
    actual_classnames = tuple(testcase.get("classname") for testcase in testcases)
    if actual_names != _SCENARIO_TEST_NAMES or actual_classnames != (
        _SCENARIO_TEST_CLASSNAME,
    ) * len(_SCENARIO_TEST_NAMES):
        raise _M6DemoInvariantError(
            "scenario gate receipt does not contain the exact ordered scenario inventory"
        )
    failed_outcomes = {"error", "failure", "skipped"}
    if any(
        child.tag.rsplit("}", maxsplit=1)[-1] in failed_outcomes
        for testcase in testcases
        for child in testcase
    ):
        raise _M6DemoInvariantError("scenario gate receipt contains a non-passing outcome")


def _run_scenarios() -> bool:
    with tempfile.TemporaryDirectory(prefix="labcourt-m6-demo-") as temporary_directory:
        receipt_path = Path(temporary_directory) / "scenario-receipt.xml"
        completed = subprocess.run(
            [
                sys.executable,
                "-m",
                "pytest",
                "-o",
                "addopts=",
                "-p",
                "pytest_socket",
                "--disable-socket",
                "--strict-config",
                "--strict-markers",
                *_SCENARIO_NODE_IDS,
                "-q",
                f"--junitxml={receipt_path}",
            ],
            cwd=PROJECT_ROOT,
            check=False,
            env=_scenario_test_environment(),
        )
        if completed.returncode != 0:
            return False
        _verify_scenario_receipt(receipt_path)
        return True


def _scenario_documents() -> tuple[M6OfflineDemoScenarioResultDocument, ...]:
    documents: list[M6OfflineDemoScenarioResultDocument] = []
    for name in M6OfflineDemoScenarioName:
        result = M6OfflineDemoScenarioResultAuthorityV1(
            scenario_name=name,
            verification_target=f"{_SCENARIO_FILE}::test_{name.value}",
        )
        documents.append(
            M6OfflineDemoScenarioResultDocument(
                result=result,
                canonical_document=canonical_json(result.model_dump(mode="json")),
            )
        )
    return tuple(documents)


def _evidence_inventory(
    publication: M6ReplayLockedClosedPolicyPublicationBundle,
) -> tuple[M6StaticReportEvidenceItem, ...]:
    sample_ids = tuple(
        sorted(result.sample_id for result in publication.report_bundle.report.results)
    )
    return tuple(
        M6StaticReportEvidenceItem(
            sample_id=sample_id,
            disposition=(
                M6StaticReportEvidenceDisposition.RETENTION_PURGED
                if index == 0
                else M6StaticReportEvidenceDisposition.NOT_PUBLISHED
            ),
            deletion_audit_id="m6-demo-retention-audit" if index == 0 else None,
            retention_reason_code="retention-window-expired" if index == 0 else None,
        )
        for index, sample_id in enumerate(sample_ids)
    )


def _static_seal(
    publication: M6ReplayLockedClosedPolicyPublicationBundle,
    static_bundle: M6PrivacySafeStaticReportBundle,
) -> tuple[M6PrivacySafeStaticReportPublicationSealAuthorityV1, str]:
    manifest_payload = canonical_json(static_bundle.manifest.model_dump(mode="json")).encode(
        "utf-8"
    )
    html_payload = static_bundle.html_document.encode("utf-8")
    seal = M6PrivacySafeStaticReportPublicationSealAuthorityV1(
        candidate_run_id=publication.seal.candidate_run_id,
        report_id=publication.report_bundle.report.report_id,
        regression_publication_seal_id=publication.seal.seal_id,
        static_report_manifest_id=static_bundle.manifest.manifest_id,
        static_report_manifest_content_sha256=hashlib.sha256(manifest_payload).hexdigest(),
        static_report_manifest_size_bytes=len(manifest_payload),
        html_content_sha256=hashlib.sha256(html_payload).hexdigest(),
        html_size_bytes=len(html_payload),
        evidence_inventory_root_sha256=(static_bundle.manifest.evidence_inventory_root_sha256),
    )
    return seal, canonical_json(seal.model_dump(mode="json"))


def _publish(output_root: Path) -> Path:
    publication = _precomputed_closed_publication()
    static_bundle = build_m6_privacy_safe_static_report(
        publication,
        _evidence_inventory(publication),
    )
    static_seal, static_seal_document = _static_seal(publication, static_bundle)
    demo_bundle = build_m6_offline_demo_publication(
        publication,
        static_bundle,
        static_seal,
        static_seal_document,
        _scenario_documents(),
    )
    generation_root = output_root / "generations" / demo_bundle.seal.seal_id
    stored_catalog = publication.report_bundle.stored_source_catalog
    M6RegressionExecutionSourceCatalogPublisher(generation_root).publish(
        stored_catalog.source_catalog,
        stored_catalog.canonical_document,
    )
    catalog_provider = ReadonlyM6RegressionExecutionSourceCatalogStore(generation_root)
    M6ReplayLockedClosedPolicyRegressionPublisher(
        generation_root,
        source_catalog_provider=catalog_provider,
    ).publish(publication)
    M6PrivacySafeStaticReportPublisher(
        generation_root,
        evidence_provider=_NoEvidenceProvider(),
    ).publish(publication, static_bundle)
    stored_static = ReadonlyM6PrivacySafeStaticReportStore(generation_root).load(
        publication.seal.candidate_run_id
    )
    if stored_static.seal != static_seal or stored_static.seal_document != static_seal_document:
        raise _M6DemoInvariantError(
            "published static report differs from its precomputed authority"
        )
    result = M6OfflineDemoPublisher(
        generation_root,
        source_catalog_provider=catalog_provider,
    ).publish(demo_bundle)
    stored = ReadonlyM6OfflineDemoStore(
        generation_root,
        source_catalog_provider=catalog_provider,
    ).load(publication.seal.candidate_run_id)
    if stored.publication_bundle != demo_bundle:
        raise _M6DemoInvariantError("published demo differs from its precomputed authority")
    print(
        canonical_json(
            {
                "classification": demo_bundle.manifest_bundle.manifest.classification,
                "demo_manifest_id": demo_bundle.manifest_bundle.manifest.demo_manifest_id,
                "index_path": str(result.index_path),
                "scenario_count": demo_bundle.manifest_bundle.manifest.scenario_count,
                "seal_id": result.seal_id,
                "status": "PASSED",
            }
        )
    )
    return result.index_path


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--output-root",
        type=Path,
        default=PROJECT_ROOT / "runs" / "m6-demo",
        help="generation parent (default: runs/m6-demo)",
    )
    return parser


def main() -> int:
    args = _parser().parse_args()
    print("Running 16 deterministic offline M6 acceptance scenarios...", flush=True)
    try:
        scenarios_passed = _run_scenarios()
    except OSError:
        print(canonical_json({"reason_code": "SCENARIO_GATE_EXECUTION_FAILED", "status": "FAILED"}))
        return 2
    except _M6DemoInvariantError:
        print(canonical_json({"reason_code": "SCENARIO_GATE_RECEIPT_INVALID", "status": "FAILED"}))
        return 2
    if not scenarios_passed:
        print(canonical_json({"reason_code": "SCENARIO_GATE_FAILED", "status": "FAILED"}))
        return 2
    try:
        _publish(args.output_root.resolve())
    except LabCourtError as exc:
        reason = getattr(getattr(exc, "code", None), "value", "TYPED_LABCOURT_FAILURE")
        print(canonical_json({"reason_code": reason, "status": "FAILED"}))
        return 3
    except OSError:
        print(canonical_json({"reason_code": "FILESYSTEM_FAILURE", "status": "FAILED"}))
        return 4
    except _M6DemoInvariantError:
        print(canonical_json({"reason_code": "DEMO_INVARIANT_FAILURE", "status": "FAILED"}))
        return 5
    except Exception:
        print(canonical_json({"reason_code": "DEMO_INVARIANT_FAILURE", "status": "FAILED"}))
        return 5
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
