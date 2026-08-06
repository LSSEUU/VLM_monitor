import hashlib
import sqlite3
from concurrent.futures import ThreadPoolExecutor
from datetime import UTC, datetime, timedelta
from pathlib import Path

import pytest
from pydantic import ValidationError

from labcourt.adapters.fake_precedent_embeddings import (
    DeterministicFakePrecedentEmbeddingProvider,
)
from labcourt.adapters.storage.readonly_m5_artifacts import ReadonlyM5ArtifactRepository
from labcourt.adapters.storage.sqlite_m5_repository import (
    SQLiteM5Repository as _SQLiteM5Repository,
)
from labcourt.adapters.storage.sqlite_repository import (
    MigrationIntegrityError,
    MigrationRunner,
    RepositoryIntegrityError,
    SQLiteEvidenceRepository,
)
from labcourt.application.m5_embedding_integrity import build_m5_controlled_fake_embedding
from labcourt.application.m5_precedent_policy_verifier import (
    ConfiguredM5PrecedentPolicyVerifier,
)
from labcourt.application.m5_precedents import (
    ExactM5PrecedentRetrievalService,
    create_m5_precedent_authority,
    evaluate_m5_automatic_activation,
    m5_precedent_policy_from_config,
    record_m5_precedent_citation,
    resolve_m5_precedent_conflict,
    resolve_m5_precedent_conflict_batch,
    revoke_m5_precedent,
)
from labcourt.config_loader import load_config
from labcourt.contracts.audit import AuditEntry, AuditEntryDraft
from labcourt.contracts.canonical import canonical_json
from labcourt.contracts.enums import (
    EvidenceClass,
    PrecedentSource,
    PrecedentStatus,
    RunMode,
    VerdictDecision,
    ViolationType,
)
from labcourt.contracts.events import CandidateEvent
from labcourt.contracts.m5_artifact_validation import M5ActivationAuthorityReasonCode
from labcourt.contracts.m5_precedents import (
    M5AppealWindowSnapshot,
    M5EmbeddingChannel,
    M5EmbeddingVector,
    M5PrecedentActivationOutcome,
    M5PrecedentActivationReceipt,
    M5PrecedentAuthority,
    M5PrecedentCitationSnapshot,
    M5PrecedentConflictResolution,
    M5PrecedentPolicy,
    M5PrecedentRetrievalQuery,
    M5PrecedentRevocationResult,
)
from labcourt.contracts.m5_projection import M5AuthorityKind
from labcourt.contracts.manifests import RunManifest
from labcourt.exceptions import ConcurrentModification, ContractViolation, ManifestMismatch

ROOT = Path(__file__).parents[2]
FIXTURES = ROOT / "tests" / "fixtures" / "m2"
MIGRATIONS = ROOT / "src" / "labcourt" / "adapters" / "storage" / "migrations"
RUN_ID = "run-01"
BUSY_TIMEOUT_MS = 5_000
NOW = datetime(2026, 8, 2, 6, 7, 8, 123456, tzinfo=UTC)


def _clock() -> datetime:
    return NOW


def _manifest() -> RunManifest:
    return RunManifest.model_validate_json(
        (FIXTURES / "run-manifest-fake.json").read_text(encoding="utf-8")
    )


def _event() -> CandidateEvent:
    return CandidateEvent.model_validate_json(
        (FIXTURES / "candidate-event-presence.json").read_text(encoding="utf-8")
    )


def _install(tmp_path: Path) -> tuple[Path, str, RunManifest]:
    database = tmp_path / "labcourt.sqlite3"
    MigrationRunner(database, BUSY_TIMEOUT_MS, MIGRATIONS, _clock).apply_all()
    manifest = _manifest()
    base = SQLiteEvidenceRepository(database, BUSY_TIMEOUT_MS, clock=_clock)
    base.register_run(RUN_ID, manifest)
    case = base.create_or_get_case(RUN_ID, _event()).case
    return database, case.case_id, manifest


def _config():  # type: ignore[no-untyped-def]
    return load_config(ROOT / "configs/demo.yaml")


def _policy(*, activation_delay_seconds: int | None = None) -> M5PrecedentPolicy:
    policy = m5_precedent_policy_from_config(_config())
    if activation_delay_seconds is not None:
        policy = policy.model_copy(
            update={"automatic_activation_delay_seconds": activation_delay_seconds}
        )
    return policy


class SQLiteM5Repository(_SQLiteM5Repository):
    def __init__(self, *args, m5_precedent_policy_verifier=None, **kwargs) -> None:  # type: ignore[no-untyped-def]
        super().__init__(
            *args,
            m5_precedent_policy_verifier=(
                m5_precedent_policy_verifier or ConfiguredM5PrecedentPolicyVerifier(_config())
            ),
            **kwargs,
        )


def _foreign_valid_config():  # type: ignore[no-untyped-def]
    config = load_config(ROOT / "configs/demo.yaml")
    assert config.config_sha256 == _manifest().config_sha256
    precedents = config.precedents.model_copy(
        update={"conflict_similarity": config.precedents.conflict_similarity - 0.01}
    )
    foreign = config.model_copy(update={"precedents": precedents})
    assert foreign.config_sha256 != config.config_sha256
    return foreign


def _rewrite_activation_context(
    database: Path,
    *,
    original_receipt_id: str,
    original_receipt: M5PrecedentActivationReceipt,
    forged_snapshot: M5AppealWindowSnapshot,
) -> M5PrecedentActivationReceipt:
    forged_receipt = M5PrecedentActivationReceipt.model_validate(
        {
            **original_receipt.model_dump(mode="python", exclude={"receipt_id"}),
            "appeal_snapshot_id": forged_snapshot.snapshot_id,
        }
    )
    receipt_json = canonical_json(forged_receipt.model_dump(mode="json"))
    context_json = canonical_json(forged_snapshot.model_dump(mode="json"))
    with sqlite3.connect(database) as connection:
        trigger = connection.execute(
            """
            SELECT sql FROM sqlite_master
            WHERE type = 'trigger' AND name = 'precedent_lifecycle_receipts_no_update'
            """
        ).fetchone()
        assert trigger is not None and isinstance(trigger[0], str)
        connection.execute("DROP TRIGGER precedent_lifecycle_receipts_no_update")
        cursor = connection.execute(
            """
            UPDATE precedent_lifecycle_receipts
            SET receipt_id = ?, receipt_json = ?, context_json = ?,
                context_sha256 = ?, document_sha256 = ?
            WHERE run_id = ? AND receipt_id = ?
            """,
            (
                forged_receipt.receipt_id,
                receipt_json,
                context_json,
                hashlib.sha256(context_json.encode("utf-8")).hexdigest(),
                hashlib.sha256(receipt_json.encode("utf-8")).hexdigest(),
                original_receipt.run_id,
                original_receipt_id,
            ),
        )
        assert cursor.rowcount == 1
        connection.execute(trigger[0])
    return forged_receipt


def _embedding(
    manifest: RunManifest,
    situation_text: str,
    *,
    channel: M5EmbeddingChannel = M5EmbeddingChannel.TEXT,
    ordinal: int = 0,
) -> M5EmbeddingVector:
    model_key = "text_embedding" if channel == M5EmbeddingChannel.TEXT else "visual_embedding"
    return build_m5_controlled_fake_embedding(
        channel=channel,
        situation_text=situation_text,
        model_manifest=manifest.models[model_key],
        embedding_provider=DeterministicFakePrecedentEmbeddingProvider(),
        ordinal=ordinal,
    )


def _authority(
    manifest: RunManifest,
    precedent_id: str,
    *,
    source: PrecedentSource = PrecedentSource.PRESET,
    source_case_id: str | None = None,
    direction: VerdictDecision = VerdictDecision.ESTABLISHED,
    activation_delay_seconds: int | None = None,
    evidence_class: EvidenceClass = EvidenceClass.PRESENCE,
    violation_type: ViolationType = ViolationType.REAGENT_CONTAINER_OPEN,
    situation_text: str = "Controlled M5 precedent situation.",
    policy: M5PrecedentPolicy | None = None,
    created_at: datetime = NOW,
) -> M5PrecedentAuthority:
    return create_m5_precedent_authority(
        run_id=RUN_ID,
        precedent_id=precedent_id,
        situation_text=situation_text,
        decision_direction=direction,
        source=source,
        evidence_class=evidence_class,
        violation_type=violation_type,
        rule_version=manifest.rule_version,
        source_case_id=source_case_id,
        created_at=created_at,
        policy=(policy or _policy(activation_delay_seconds=activation_delay_seconds)),
        text_embedding=_embedding(manifest, situation_text),
    )


def _query(
    manifest: RunManifest,
    case_id: str,
    *,
    policy: M5PrecedentPolicy | None = None,
) -> M5PrecedentRetrievalQuery:
    situation_text = "Controlled M5 precedent situation."
    return M5PrecedentRetrievalQuery(
        run_id=RUN_ID,
        case_id=case_id,
        evidence_class=EvidenceClass.PRESENCE,
        rule_version=manifest.rule_version,
        situation_text=situation_text,
        text_embedding_model_manifest_id=manifest.models["text_embedding"].model_manifest_id,
        visual_embedding_model_manifest_id=manifest.models["visual_embedding"].model_manifest_id,
        text_embedding=_embedding(manifest, situation_text),
        policy=policy or _policy(),
        top_k=10,
    )


def test_precedent_append_retrieval_citation_snapshot_and_replay(tmp_path: Path) -> None:
    database, case_id, manifest = _install(tmp_path)
    repository = SQLiteM5Repository(database, BUSY_TIMEOUT_MS, _clock)
    initial = _authority(manifest, "precedent-alpha")

    assert repository.append_authority(initial, None) == initial
    assert repository.append_authority(initial, None) == initial
    assert repository.get(RUN_ID, initial.precedent.precedent_id) == initial
    assert repository.get_precedent(RUN_ID, initial.precedent.precedent_id) == initial

    query = _query(manifest, case_id)
    candidates = repository.list_for_retrieval(query)
    result = ExactM5PrecedentRetrievalService().retrieve(query, candidates)
    commit = record_m5_precedent_citation(
        result=result,
        precedent_id=initial.precedent.precedent_id,
        cited_at=NOW,
    )
    assert repository.commit_citation(commit) == commit
    assert repository.commit_citation(commit) == commit
    current = repository.get_precedent(RUN_ID, initial.precedent.precedent_id)
    assert current == initial
    assert current.precedent.citation_count == 0
    snapshot = repository.citation_snapshot(RUN_ID, initial.precedent.precedent_id)
    assert snapshot.complete
    assert snapshot.observed_citation_count == 1
    assert snapshot.citations == (commit.citation,)
    assert repository.list_conflicts(RUN_ID, 10) == ()


def test_concurrent_independent_citations_append_without_authority_cas(tmp_path: Path) -> None:
    database, first_case_id, manifest = _install(tmp_path)
    evidence = SQLiteEvidenceRepository(database, BUSY_TIMEOUT_MS, clock=_clock)
    event_payload = _event().model_dump(mode="json", exclude={"event_id"})
    event_payload.update({"start_frame": 500, "end_frame_exclusive": 591, "trigger_frame": 590})
    second_case_id = evidence.create_or_get_case(
        RUN_ID,
        CandidateEvent.model_validate(event_payload),
    ).case.case_id
    repository = SQLiteM5Repository(database, BUSY_TIMEOUT_MS, _clock)
    authority = _authority(manifest, "precedent-concurrent-citation")
    repository.append_authority(authority, None)

    commits = tuple(
        record_m5_precedent_citation(
            result=ExactM5PrecedentRetrievalService().retrieve(
                query,
                repository.list_for_retrieval(query),
            ),
            precedent_id=authority.precedent.precedent_id,
            cited_at=NOW,
        )
        for query in (
            _query(manifest, first_case_id),
            _query(manifest, second_case_id),
        )
    )

    with ThreadPoolExecutor(max_workers=2) as executor:
        durable = tuple(
            executor.map(
                lambda item: SQLiteM5Repository(
                    database,
                    BUSY_TIMEOUT_MS,
                    _clock,
                ).commit_citation(item),
                commits,
            )
        )

    assert durable == commits
    assert repository.get_precedent(RUN_ID, authority.precedent.precedent_id) == authority
    snapshot = repository.citation_snapshot(RUN_ID, authority.precedent.precedent_id)
    assert snapshot.observed_citation_count == 2
    assert {item.case_id for item in snapshot.citations} == {first_case_id, second_case_id}


def test_citation_inventory_rejects_missing_and_extra_candidate_identity(
    tmp_path: Path,
) -> None:
    database, case_id, manifest = _install(tmp_path)
    repository = SQLiteM5Repository(database, BUSY_TIMEOUT_MS, _clock)
    first = _authority(manifest, "precedent-inventory-a")
    second = _authority(manifest, "precedent-inventory-b")
    repository.append_authority(first, None)
    repository.append_authority(second, None)
    query = _query(manifest, case_id)
    complete = ExactM5PrecedentRetrievalService().retrieve(
        query,
        repository.list_for_retrieval(query),
    )
    selected = complete.candidate_evaluations[0]
    missing = complete.model_copy(
        update={
            "candidate_evaluations": (selected,),
            "scored_precedents": (selected.as_scored_precedent(),),
        }
    )
    missing_commit = record_m5_precedent_citation(
        result=missing,
        precedent_id=selected.authority.precedent.precedent_id,
        cited_at=NOW,
    )
    with pytest.raises(ContractViolation, match="missing or adds"):
        repository.commit_citation(missing_commit)

    phantom = _authority(manifest, "precedent-inventory-phantom")
    extra = ExactM5PrecedentRetrievalService().retrieve(
        query,
        (*repository.list_for_retrieval(query), phantom),
    )
    extra_commit = record_m5_precedent_citation(
        result=extra,
        precedent_id=first.precedent.precedent_id,
        cited_at=NOW,
    )
    with pytest.raises(ContractViolation, match="missing or adds"):
        repository.commit_citation(extra_commit)
    assert repository.citation_snapshot(RUN_ID, first.precedent.precedent_id).citations == ()


def test_same_citation_identity_rejects_different_content(tmp_path: Path) -> None:
    database, case_id, manifest = _install(tmp_path)
    repository = SQLiteM5Repository(database, BUSY_TIMEOUT_MS, _clock)
    authority = _authority(manifest, "precedent-citation-identity")
    repository.append_authority(authority, None)
    query = _query(manifest, case_id)
    result = ExactM5PrecedentRetrievalService().retrieve(
        query,
        repository.list_for_retrieval(query),
    )
    first = record_m5_precedent_citation(
        result=result,
        precedent_id=authority.precedent.precedent_id,
        cited_at=NOW,
    )
    different = record_m5_precedent_citation(
        result=result,
        precedent_id=authority.precedent.precedent_id,
        cited_at=NOW + timedelta(microseconds=1),
    )
    assert repository.commit_citation(first) == first
    with pytest.raises(ConcurrentModification, match="identity collision"):
        repository.commit_citation(different)


def test_precedent_import_batch_is_atomic_fault_safe_and_exactly_replayable(
    tmp_path: Path,
) -> None:
    database, _case_id, manifest = _install(tmp_path)
    first = _authority(manifest, "precedent-import-a")
    second = _authority(manifest, "precedent-import-b")

    def fail_after_first(phase: str) -> None:
        if phase == "precedent.import.after_authority":
            raise RuntimeError("injected import failure")

    faulted = SQLiteM5Repository(
        database,
        BUSY_TIMEOUT_MS,
        _clock,
        fault_injector=fail_after_first,
    )
    with pytest.raises(RuntimeError, match="injected import failure"):
        faulted.append_authorities(RUN_ID, (second, first))

    with sqlite3.connect(database) as connection:
        assert connection.execute("SELECT COUNT(*) FROM precedents").fetchone() == (0,)
        assert connection.execute("SELECT COUNT(*) FROM precedent_embeddings").fetchone() == (0,)

    restarted = SQLiteM5Repository(database, BUSY_TIMEOUT_MS, _clock)
    expected = (first, second)
    assert restarted.append_authorities(RUN_ID, (second, first)) == expected
    replayed = SQLiteM5Repository(database, BUSY_TIMEOUT_MS, _clock)
    assert replayed.append_authorities(RUN_ID, (second, first)) == expected
    with sqlite3.connect(database) as connection:
        assert connection.execute("SELECT COUNT(*) FROM precedents").fetchone() == (2,)


def test_precedent_import_tail_conflict_rolls_back_the_entire_batch(tmp_path: Path) -> None:
    database, _case_id, manifest = _install(tmp_path)
    repository = SQLiteM5Repository(database, BUSY_TIMEOUT_MS, _clock)
    durable_tail = _authority(
        manifest,
        "precedent-import-tail",
        situation_text="Durable tail authority.",
    )
    repository.append_authority(durable_tail, None)
    new_head = _authority(manifest, "precedent-import-head")
    conflicting_tail = _authority(
        manifest,
        "precedent-import-tail",
        situation_text="Different requested tail authority.",
    )

    with pytest.raises(ConcurrentModification, match="partially present"):
        repository.append_authorities(RUN_ID, (new_head, conflicting_tail))

    assert repository.get_precedent(RUN_ID, new_head.precedent.precedent_id) is None
    assert repository.get_precedent(RUN_ID, durable_tail.precedent.precedent_id) == durable_tail
    with sqlite3.connect(database) as connection:
        assert connection.execute("SELECT COUNT(*) FROM precedents").fetchone() == (1,)


def test_public_append_accepts_only_initial_active_preset_authority(tmp_path: Path) -> None:
    database, case_id, manifest = _install(tmp_path)
    repository = SQLiteM5Repository(database, BUSY_TIMEOUT_MS, _clock)
    preset = _authority(manifest, "precedent-public-preset")
    automatic = _authority(
        manifest,
        "precedent-public-automatic",
        source=PrecedentSource.AUTOMATIC,
        source_case_id=case_id,
    )
    non_preset = tuple(
        preset.model_copy(
            update={
                "precedent": preset.precedent.model_copy(
                    update={
                        "precedent_id": f"precedent-public-{source.value.lower()}",
                        "source": source,
                    }
                )
            }
        )
        for source in (PrecedentSource.HUMAN_REVIEW, PrecedentSource.APPEAL_OVERTURN)
    )

    for authority in (automatic, *non_preset):
        with pytest.raises(ContractViolation, match="initial active PRESET"):
            repository.append_authority(authority, None)
    assert repository.append_authority(preset, None) == preset


def test_sensitive_precedent_paths_fail_closed_without_trusted_policy_verifier(
    tmp_path: Path,
) -> None:
    database, case_id, manifest = _install(tmp_path)
    untrusted = _SQLiteM5Repository(database, BUSY_TIMEOUT_MS, _clock)
    authority = _authority(manifest, "precedent-missing-verifier")

    with pytest.raises(ContractViolation, match="policy verifier is required"):
        untrusted.append_authority(authority, None)
    with pytest.raises(ContractViolation, match="policy verifier is required"):
        untrusted.list_for_retrieval(_query(manifest, case_id))
    with sqlite3.connect(database) as connection:
        assert connection.execute("SELECT COUNT(*) FROM precedents").fetchone() == (0,)


def test_retrieval_rejects_forged_weights_priorities_threshold_and_offline_mode(
    tmp_path: Path,
) -> None:
    database, case_id, manifest = _install(tmp_path)
    repository = SQLiteM5Repository(database, BUSY_TIMEOUT_MS, _clock)
    repository.append_authority(_authority(manifest, "precedent-trusted-policy"), None)
    policy = _policy()
    source_weights = dict(policy.source_weights)
    source_weights[PrecedentSource.PRESET] = 1.01
    source_priorities = dict(policy.source_priorities)
    source_priorities[PrecedentSource.PRESET] += 1
    forged_policies = (
        policy.model_copy(update={"text_weight": 0.6, "visual_weight": 0.4}),
        policy.model_copy(update={"source_weights": source_weights}),
        policy.model_copy(update={"source_priorities": source_priorities}),
        policy.model_copy(update={"conflict_similarity": 0.56}),
    )

    for forged_policy in forged_policies:
        with pytest.raises(ManifestMismatch, match="trusted AppConfig"):
            repository.list_for_retrieval(_query(manifest, case_id, policy=forged_policy))

    forged_offline = _query(manifest, case_id).model_copy(
        update={
            "run_mode": RunMode.OFFLINE_EXPERIMENT,
            "include_provisional_experiment": True,
        }
    )
    with pytest.raises(ManifestMismatch, match="mode and provisional visibility"):
        repository.list_for_retrieval(forged_offline)


def test_offline_experiment_precedent_access_is_strictly_read_only(tmp_path: Path) -> None:
    config = _config()
    offline_config = config.model_copy(
        update={"run": config.run.model_copy(update={"mode": RunMode.OFFLINE_EXPERIMENT})}
    )
    manifest = _manifest().model_copy(update={"config_sha256": offline_config.config_sha256})
    database = tmp_path / "labcourt.sqlite3"
    MigrationRunner(database, BUSY_TIMEOUT_MS, MIGRATIONS, _clock).apply_all()
    base = SQLiteEvidenceRepository(database, BUSY_TIMEOUT_MS, clock=_clock)
    base.register_run(RUN_ID, manifest)
    event = _event().model_copy(update={"manifest_id": manifest.manifest_id})
    case_id = base.create_or_get_case(RUN_ID, event).case.case_id
    repository = SQLiteM5Repository(
        database,
        BUSY_TIMEOUT_MS,
        _clock,
        m5_precedent_policy_verifier=ConfiguredM5PrecedentPolicyVerifier(offline_config),
    )
    policy = m5_precedent_policy_from_config(offline_config)
    preset = _authority(manifest, "precedent-offline-preset", policy=policy)

    with pytest.raises(ContractViolation, match="read-only"):
        repository.append_authority(preset, None)

    provisional = _authority(
        manifest,
        "precedent-offline-provisional",
        source=PrecedentSource.AUTOMATIC,
        source_case_id=case_id,
        policy=policy,
    )
    with repository._immediate() as connection:
        repository._insert_m5_precedent_authority(
            connection,
            provisional,
            None,
            causal_fault_scope="test.offline_provisional_authority",
        )
    query = _query(manifest, case_id, policy=policy).model_copy(
        update={
            "run_mode": RunMode.OFFLINE_EXPERIMENT,
            "include_provisional_experiment": True,
        }
    )
    candidates = repository.list_for_retrieval(query)
    assert candidates == (provisional,)
    result = ExactM5PrecedentRetrievalService().retrieve(query, candidates)
    citation = record_m5_precedent_citation(
        result=result,
        precedent_id=provisional.precedent.precedent_id,
        cited_at=NOW,
    )
    with pytest.raises(ContractViolation, match="read-only"):
        repository.commit_citation(citation)
    with pytest.raises(ContractViolation, match="read-only"):
        repository.list_activation_candidates(RUN_ID, provisional.activation_not_before, 10)  # type: ignore[arg-type]


def test_precedent_append_rejects_cross_channel_manifest_and_claimed_vector(
    tmp_path: Path,
) -> None:
    database, _case_id, manifest = _install(tmp_path)
    repository = SQLiteM5Repository(database, BUSY_TIMEOUT_MS, _clock)
    situation_text = "Controlled forged preset situation."
    payload = situation_text.encode("utf-8")

    text = _embedding(manifest, situation_text)
    wrong_text_request = text.request.model_copy(
        update={"model_manifest_id": manifest.models["detector"].model_manifest_id}
    )
    wrong_text = DeterministicFakePrecedentEmbeddingProvider().embed(
        wrong_text_request,
        payload,
    )
    wrong_text_authority = create_m5_precedent_authority(
        run_id=RUN_ID,
        precedent_id="precedent-wrong-text-model",
        situation_text=situation_text,
        decision_direction=VerdictDecision.ESTABLISHED,
        source=PrecedentSource.PRESET,
        evidence_class=EvidenceClass.PRESENCE,
        violation_type=ViolationType.REAGENT_CONTAINER_OPEN,
        rule_version=manifest.rule_version,
        source_case_id=None,
        created_at=NOW,
        policy=_policy(),
        text_embedding=wrong_text,
    )
    with pytest.raises(ManifestMismatch, match="TEXT embedding"):
        repository.append_authority(wrong_text_authority, None)

    visual = _embedding(
        manifest,
        situation_text,
        channel=M5EmbeddingChannel.VISUAL,
    )
    wrong_visual_request = visual.request.model_copy(
        update={"model_manifest_id": manifest.models["text_embedding"].model_manifest_id}
    )
    wrong_visual = DeterministicFakePrecedentEmbeddingProvider().embed(
        wrong_visual_request,
        payload,
    )
    wrong_visual_authority = create_m5_precedent_authority(
        run_id=RUN_ID,
        precedent_id="precedent-wrong-visual-model",
        situation_text=situation_text,
        decision_direction=VerdictDecision.ESTABLISHED,
        source=PrecedentSource.PRESET,
        evidence_class=EvidenceClass.PRESENCE,
        violation_type=ViolationType.REAGENT_CONTAINER_OPEN,
        rule_version=manifest.rule_version,
        source_case_id=None,
        created_at=NOW,
        policy=_policy(),
        visual_embeddings=(wrong_visual,),
    )
    with pytest.raises(ManifestMismatch, match="VISUAL embedding"):
        repository.append_authority(wrong_visual_authority, None)

    uncontrolled_request = text.request.model_copy(update={"input_ref": "forged-preset-input"})
    uncontrolled_text = DeterministicFakePrecedentEmbeddingProvider().embed(
        uncontrolled_request,
        payload,
    )
    uncontrolled_authority = create_m5_precedent_authority(
        run_id=RUN_ID,
        precedent_id="precedent-uncontrolled-input",
        situation_text=situation_text,
        decision_direction=VerdictDecision.ESTABLISHED,
        source=PrecedentSource.PRESET,
        evidence_class=EvidenceClass.PRESENCE,
        violation_type=ViolationType.REAGENT_CONTAINER_OPEN,
        rule_version=manifest.rule_version,
        source_case_id=None,
        created_at=NOW,
        policy=_policy(),
        text_embedding=uncontrolled_text,
    )
    with pytest.raises(ContractViolation, match="controlled fake reconstruction"):
        repository.append_authority(uncontrolled_authority, None)

    forged_values = tuple(-value for value in text.values)
    forged_text = M5EmbeddingVector(request=text.request, values=forged_values)
    forged_authority = create_m5_precedent_authority(
        run_id=RUN_ID,
        precedent_id="precedent-forged-vector",
        situation_text=situation_text,
        decision_direction=VerdictDecision.ESTABLISHED,
        source=PrecedentSource.PRESET,
        evidence_class=EvidenceClass.PRESENCE,
        violation_type=ViolationType.REAGENT_CONTAINER_OPEN,
        rule_version=manifest.rule_version,
        source_case_id=None,
        created_at=NOW,
        policy=_policy(),
        text_embedding=forged_text,
    )
    with pytest.raises(ContractViolation, match="controlled fake reconstruction"):
        repository.append_authority(forged_authority, None)

    with sqlite3.connect(database) as connection:
        assert connection.execute("SELECT COUNT(*) FROM precedents").fetchone() == (0,)
        assert connection.execute("SELECT COUNT(*) FROM precedent_embeddings").fetchone() == (0,)


def test_visual_only_precedent_and_query_use_visual_manifest_and_controlled_input(
    tmp_path: Path,
) -> None:
    database, case_id, manifest = _install(tmp_path)
    repository = SQLiteM5Repository(database, BUSY_TIMEOUT_MS, _clock)
    situation_text = "Controlled visual-only M5 precedent situation."
    visual = _embedding(
        manifest,
        situation_text,
        channel=M5EmbeddingChannel.VISUAL,
    )
    visual_policy = _policy()
    authority = create_m5_precedent_authority(
        run_id=RUN_ID,
        precedent_id="precedent-visual-only",
        situation_text=situation_text,
        decision_direction=VerdictDecision.ESTABLISHED,
        source=PrecedentSource.PRESET,
        evidence_class=EvidenceClass.PRESENCE,
        violation_type=ViolationType.REAGENT_CONTAINER_OPEN,
        rule_version=manifest.rule_version,
        source_case_id=None,
        created_at=NOW,
        policy=visual_policy,
        visual_embeddings=(visual,),
    )
    assert repository.append_authority(authority, None) == authority

    query = M5PrecedentRetrievalQuery(
        run_id=RUN_ID,
        case_id=case_id,
        evidence_class=EvidenceClass.PRESENCE,
        rule_version=manifest.rule_version,
        situation_text=situation_text,
        text_embedding_model_manifest_id=manifest.models["text_embedding"].model_manifest_id,
        visual_embedding_model_manifest_id=manifest.models["visual_embedding"].model_manifest_id,
        visual_embeddings=(visual,),
        policy=visual_policy,
        top_k=1,
    )
    candidates = repository.list_for_retrieval(query)
    result = ExactM5PrecedentRetrievalService().retrieve(query, candidates)
    assert candidates == (authority,)
    assert result.scored_precedents[0].visual_similarity == pytest.approx(1.0)


def test_retrieval_and_citation_reject_forged_query_embedding_at_trust_boundary(
    tmp_path: Path,
) -> None:
    database, case_id, manifest = _install(tmp_path)
    repository = SQLiteM5Repository(database, BUSY_TIMEOUT_MS, _clock)
    initial = _authority(manifest, "precedent-query-integrity")
    repository.append_authority(initial, None)
    trusted_query = _query(manifest, case_id)
    candidates = repository.list_for_retrieval(trusted_query)
    assert candidates == (initial,)
    assert trusted_query.text_embedding is not None

    forged_embedding = M5EmbeddingVector(
        request=trusted_query.text_embedding.request,
        values=tuple(-value for value in trusted_query.text_embedding.values),
    )
    forged_query = trusted_query.model_copy(update={"text_embedding": forged_embedding})
    with pytest.raises(ContractViolation, match="controlled fake reconstruction"):
        repository.list_for_retrieval(forged_query)

    forged_result = ExactM5PrecedentRetrievalService().retrieve(forged_query, candidates)
    forged_commit = record_m5_precedent_citation(
        result=forged_result,
        precedent_id=initial.precedent.precedent_id,
        cited_at=NOW,
    )
    with pytest.raises(ContractViolation, match="controlled fake reconstruction"):
        repository.commit_citation(forged_commit)
    assert repository.get_precedent(RUN_ID, initial.precedent.precedent_id) == initial
    assert repository.citation_snapshot(RUN_ID, initial.precedent.precedent_id).citations == ()

    wrong_request = trusted_query.text_embedding.request.model_copy(
        update={
            "model_manifest_id": manifest.models["visual_embedding"].model_manifest_id,
        }
    )
    wrong_embedding = DeterministicFakePrecedentEmbeddingProvider().embed(
        wrong_request,
        trusted_query.situation_text.encode("utf-8"),
    )
    with pytest.raises(ValidationError, match="bound model manifest"):
        trusted_query.model_copy(update={"text_embedding": wrong_embedding})
    wrong_query = trusted_query.model_copy(
        update={"visual_embedding_model_manifest_id": manifest.models["detector"].model_manifest_id}
    )
    with pytest.raises(ManifestMismatch, match="model manifest bindings"):
        repository.list_for_retrieval(wrong_query)


def test_citation_commit_rejects_contract_valid_but_forged_similarity(
    tmp_path: Path,
) -> None:
    database, case_id, manifest = _install(tmp_path)
    repository = SQLiteM5Repository(database, BUSY_TIMEOUT_MS, _clock)
    initial = _authority(manifest, "precedent-forged-score")
    repository.append_authority(initial, None)
    query = _query(manifest, case_id)
    result = ExactM5PrecedentRetrievalService().retrieve(
        query,
        repository.list_for_retrieval(query),
    )
    evaluation = result.candidate_evaluations[0]
    assert evaluation.source_weight is not None
    forged_evaluation = evaluation.model_copy(
        update={
            "text_similarity": 0.25,
            "base_similarity": 0.25,
            "score": 0.25 * evaluation.source_weight,
        }
    )
    forged_result = result.model_copy(
        update={
            "candidate_evaluations": (forged_evaluation,),
            "scored_precedents": (forged_evaluation.as_scored_precedent(),),
        }
    )
    forged_commit = record_m5_precedent_citation(
        result=forged_result,
        precedent_id=initial.precedent.precedent_id,
        cited_at=NOW,
    )

    with pytest.raises(ContractViolation, match="historical retrieval"):
        repository.commit_citation(forged_commit)
    assert repository.get_precedent(RUN_ID, initial.precedent.precedent_id) == initial
    assert repository.citation_snapshot(RUN_ID, initial.precedent.precedent_id).citations == ()


def test_activation_receipt_and_revision_commit_atomically(tmp_path: Path) -> None:
    from tests.integration.test_m5_sqlite_appeals import _prepare_closed_case

    database, repository, closed, _, _, initial = _prepare_closed_case(tmp_path)
    assert initial.activation_not_before is not None
    eligible_at = initial.activation_not_before
    appeal_snapshot = repository.load_appeal_window_snapshot(
        initial.run_id,
        closed.case.case_id,
        eligible_at,
    )
    result = evaluate_m5_automatic_activation(
        authority=initial,
        appeal_snapshot=appeal_snapshot,
        evaluated_at=eligible_at,
    )

    assert repository.commit_activation(result) == result
    from tests.integration.test_m5_sqlite_appeals import _append_review

    _append_review(repository, closed.case.case_id)
    assert repository.commit_activation(result) == result
    assert (
        repository.get_precedent(initial.run_id, initial.precedent.precedent_id) == result.authority
    )
    with sqlite3.connect(database) as connection:
        assert connection.execute("SELECT COUNT(*) FROM precedents").fetchone() == (2,)
        assert connection.execute(
            "SELECT COUNT(*) FROM precedent_lifecycle_receipts"
        ).fetchone() == (1,)
        assert connection.execute("SELECT COUNT(*) FROM m5_precedent_causal_events").fetchone() == (
            2,
        )


def test_activation_candidate_scan_is_bounded_eligible_and_stably_ordered(
    tmp_path: Path,
) -> None:
    _database, case_id, manifest = _install(tmp_path)
    repository = SQLiteM5Repository(_database, BUSY_TIMEOUT_MS, _clock)
    base_repository = SQLiteEvidenceRepository(_database, BUSY_TIMEOUT_MS, clock=_clock)
    case_ids = [case_id]
    for offset in (100, 200):
        event_payload = _event().model_dump(mode="json", exclude={"event_id"})
        event_payload.update(
            {
                "start_frame": offset,
                "end_frame_exclusive": offset + 91,
                "trigger_frame": offset + 90,
            }
        )
        case_ids.append(
            base_repository.create_or_get_case(
                RUN_ID,
                CandidateEvent.model_validate(event_payload),
            ).case.case_id
        )
    authorities = (
        _authority(
            manifest,
            "precedent-candidate-b",
            source=PrecedentSource.AUTOMATIC,
            source_case_id=case_ids[0],
        ),
        _authority(
            manifest,
            "precedent-candidate-a",
            source=PrecedentSource.AUTOMATIC,
            source_case_id=case_ids[1],
        ),
        _authority(
            manifest,
            "precedent-candidate-later",
            source=PrecedentSource.AUTOMATIC,
            source_case_id=case_ids[2],
            created_at=NOW + timedelta(hours=1),
        ),
    )
    with repository._immediate() as connection:
        for authority in authorities:
            repository._insert_m5_precedent_authority(
                connection,
                authority,
                None,
                causal_fault_scope="test.controlled_embedding_authority",
            )

    eligible_at = NOW + timedelta(days=7)
    candidates = repository.list_activation_candidates(RUN_ID, eligible_at, 10)
    assert tuple(item.precedent.precedent_id for item in candidates) == (
        "precedent-candidate-a",
        "precedent-candidate-b",
    )
    assert all(item.precedent.status == PrecedentStatus.PROVISIONAL for item in candidates)
    assert repository.list_activation_candidates(RUN_ID, eligible_at, 1) == (candidates[0],)
    assert repository.list_activation_candidates(RUN_ID, NOW, 10) == ()

    with pytest.raises(ContractViolation, match="timezone-aware UTC"):
        repository.list_activation_candidates(RUN_ID, NOW.replace(tzinfo=None), 10)
    with pytest.raises(ContractViolation, match="limit"):
        repository.list_activation_candidates(RUN_ID, eligible_at, 0)


def test_appeal_window_snapshot_is_repository_derived_and_closes_activation_race(
    tmp_path: Path,
) -> None:
    from tests.integration.test_m5_sqlite_appeals import (
        _append_review,
        _prepare_closed_case,
    )
    from tests.integration.test_m5_sqlite_appeals import _clock as appeal_clock

    _database, repository, closed, _manifest_value, _config, automatic = _prepare_closed_case(
        tmp_path
    )
    source, submitted, _reviewed = _append_review(repository, closed.case.case_id)
    assert automatic.activation_not_before is not None
    eligible_at = appeal_clock()

    trusted = repository.load_appeal_window_snapshot(
        source.run_id,
        source.case_id,
        eligible_at,
    )
    assert trusted.complete
    assert trusted.appeal_ids == (submitted.appeal.appeal_id,)

    forged_result = evaluate_m5_automatic_activation(
        authority=automatic,
        appeal_snapshot=trusted.model_copy(update={"appeal_ids": ()}),
        evaluated_at=eligible_at,
    )
    with pytest.raises(ContractViolation, match="appeal inventory is not exact"):
        repository.commit_activation(forged_result)
    assert repository.get_precedent(source.run_id, automatic.precedent.precedent_id) == automatic


def test_activation_cas_rejects_appeal_committed_after_evaluation_clock(
    tmp_path: Path,
) -> None:
    from tests.integration.test_m5_sqlite_appeals import (
        _append_review,
        _prepare_closed_case,
    )

    database, repository, closed, _, _, automatic = _prepare_closed_case(tmp_path)
    assert automatic.activation_not_before is not None
    evaluated_at = automatic.activation_not_before
    stale_snapshot = repository.load_appeal_window_snapshot(
        automatic.run_id,
        closed.case.case_id,
        evaluated_at,
    )
    assert stale_snapshot.appeal_ids == ()

    late_repository = SQLiteM5Repository(
        database,
        BUSY_TIMEOUT_MS,
        lambda: evaluated_at + timedelta(seconds=1),
    )
    _append_review(late_repository, closed.case.case_id)
    stale_result = evaluate_m5_automatic_activation(
        authority=automatic,
        appeal_snapshot=stale_snapshot,
        evaluated_at=evaluated_at,
    )

    with pytest.raises(ConcurrentModification, match="source Case causal cut changed"):
        repository.commit_activation(stale_result)
    assert (
        repository.get_precedent(
            automatic.run_id,
            automatic.precedent.precedent_id,
        )
        == automatic
    )


def test_appeal_present_activation_receipt_suppresses_only_its_exact_authority(
    tmp_path: Path,
) -> None:
    from labcourt.contracts.m5_appeals import (
        AppealReviewCommand,
        AppealSubmissionCommand,
    )
    from labcourt.domain.appeal_fsm import begin_appeal_review, submit_appeal
    from tests.integration.test_m5_sqlite_appeals import _clock as appeal_clock
    from tests.integration.test_m5_sqlite_appeals import _prepare_closed_case

    database, repository, closed, _manifest_value, _config_value, automatic = _prepare_closed_case(
        tmp_path
    )
    assert automatic.activation_not_before is not None
    early_at = automatic.activation_not_before - timedelta(seconds=1)
    early_snapshot = repository.load_appeal_window_snapshot(
        RUN_ID,
        closed.case.case_id,
        early_at,
    )
    early = evaluate_m5_automatic_activation(
        authority=automatic,
        appeal_snapshot=early_snapshot,
        evaluated_at=early_at,
    )
    assert early.receipt.outcome == M5PrecedentActivationOutcome.TOO_EARLY
    assert repository.commit_activation(early) == early

    source = repository.load_closed_case_authority(RUN_ID, closed.case.case_id)
    submitted = submit_appeal(
        source,
        AppealSubmissionCommand(
            run_id=source.run_id,
            case_id=source.case_id,
            appeal_id="appeal-activation-history",
            expected_case_revision=source.case_revision,
            expected_case_authority_sha256=source.authority_sha256,
            reason="The adjudication conflicts with the reviewed evidence.",
            submitted_by="subject-activation-history",
        ),
        None,
    )
    assert repository.append_appeal_version(submitted, None) == submitted
    eligible_at = appeal_clock()
    assert repository.list_activation_candidates(RUN_ID, eligible_at, 10) == (automatic,)

    snapshot = repository.load_appeal_window_snapshot(
        RUN_ID,
        closed.case.case_id,
        eligible_at,
    )
    first = evaluate_m5_automatic_activation(
        authority=automatic,
        appeal_snapshot=snapshot,
        evaluated_at=eligible_at,
    )
    assert first.receipt.outcome == M5PrecedentActivationOutcome.APPEAL_PRESENT
    assert repository.commit_activation(first) == first

    reviewed = begin_appeal_review(
        submitted,
        AppealReviewCommand(
            run_id=source.run_id,
            case_id=source.case_id,
            appeal_id=submitted.appeal.appeal_id,
            expected_appeal_authority_sha256=submitted.authority_sha256,
            reviewer_id="reviewer-activation-history",
        ),
    )
    assert repository.append_appeal_version(reviewed, submitted.authority_sha256) == reviewed
    assert repository.commit_activation(early) == early
    assert repository.commit_activation(first) == first
    assert repository.get_precedent(RUN_ID, automatic.precedent.precedent_id) == automatic
    assert repository.list_activation_candidates(RUN_ID, eligible_at, 10) == ()

    reevaluated_at = eligible_at + timedelta(seconds=1)
    second_snapshot = repository.load_appeal_window_snapshot(
        RUN_ID,
        closed.case.case_id,
        reevaluated_at,
    )
    second = evaluate_m5_automatic_activation(
        authority=automatic,
        appeal_snapshot=second_snapshot,
        evaluated_at=reevaluated_at,
    )
    assert second.receipt.outcome == M5PrecedentActivationOutcome.APPEAL_PRESENT
    assert second.receipt.receipt_id != first.receipt.receipt_id
    with pytest.raises(ConcurrentModification, match="lifecycle receipt identity collision"):
        repository.commit_activation(second)

    assert ReadonlyM5ArtifactRepository(database, config=_config()).scan(RUN_ID).failures == ()

    restarted = SQLiteM5Repository(database, BUSY_TIMEOUT_MS, _clock)
    assert restarted.list_activation_candidates(RUN_ID, eligible_at, 10) == ()
    with sqlite3.connect(database) as connection:
        assert connection.execute(
            "SELECT COUNT(*) FROM precedent_lifecycle_receipts "
            "WHERE receipt_kind = 'ACTIVATION' AND outcome = 'APPEAL_PRESENT'"
        ).fetchone() == (1,)


def test_too_early_receipt_does_not_block_later_activation_of_same_prior(
    tmp_path: Path,
) -> None:
    from tests.integration.test_m5_sqlite_appeals import _prepare_closed_case

    database, repository, closed, _, _, automatic = _prepare_closed_case(tmp_path)
    assert automatic.activation_not_before is not None
    early_at = automatic.activation_not_before - timedelta(seconds=1)
    early_snapshot = repository.load_appeal_window_snapshot(
        automatic.run_id,
        closed.case.case_id,
        early_at,
    )
    early = evaluate_m5_automatic_activation(
        authority=automatic,
        appeal_snapshot=early_snapshot,
        evaluated_at=early_at,
    )
    assert early.receipt.outcome == M5PrecedentActivationOutcome.TOO_EARLY
    assert repository.commit_activation(early) == early

    eligible_snapshot = repository.load_appeal_window_snapshot(
        automatic.run_id,
        closed.case.case_id,
        automatic.activation_not_before,
    )
    activated = evaluate_m5_automatic_activation(
        authority=automatic,
        appeal_snapshot=eligible_snapshot,
        evaluated_at=automatic.activation_not_before,
    )
    assert activated.receipt.outcome == M5PrecedentActivationOutcome.ACTIVATED
    assert repository.commit_activation(activated) == activated
    with sqlite3.connect(database) as connection:
        assert connection.execute(
            "SELECT COUNT(*) FROM precedent_lifecycle_receipts WHERE receipt_kind = 'ACTIVATION'"
        ).fetchone() == (2,)


@pytest.mark.parametrize(
    ("tamper", "expected_reason"),
    [
        (
            "case_hash",
            M5ActivationAuthorityReasonCode.ACTIVATION_SOURCE_CASE_CUT_INVALID,
        ),
        (
            "case_revision",
            M5ActivationAuthorityReasonCode.ACTIVATION_SOURCE_CASE_CUT_INVALID,
        ),
        (
            "appeal_inventory",
            M5ActivationAuthorityReasonCode.ACTIVATION_APPEAL_INVENTORY_MISMATCH,
        ),
    ],
)
def test_readonly_activation_rejects_self_consistent_case_cut_tamper(
    tmp_path: Path,
    tamper: str,
    expected_reason: M5ActivationAuthorityReasonCode,
) -> None:
    from tests.integration.test_m5_sqlite_appeals import _prepare_closed_case

    database, repository, closed, _, _, automatic = _prepare_closed_case(tmp_path)
    assert automatic.activation_not_before is not None
    snapshot = repository.load_appeal_window_snapshot(
        automatic.run_id,
        closed.case.case_id,
        automatic.activation_not_before,
    )
    activation = evaluate_m5_automatic_activation(
        authority=automatic,
        appeal_snapshot=snapshot,
        evaluated_at=automatic.activation_not_before,
    )
    assert repository.commit_activation(activation) == activation
    if tamper == "case_hash":
        forged_snapshot = snapshot.model_copy(update={"source_case_document_sha256": "f" * 64})
    elif tamper == "case_revision":
        forged_snapshot = snapshot.model_copy(
            update={"source_case_revision": snapshot.source_case_revision + 1}
        )
    else:
        forged_snapshot = snapshot.model_copy(update={"appeal_ids": ("appeal-forged",)})
    _rewrite_activation_context(
        database,
        original_receipt_id=activation.receipt.receipt_id,
        original_receipt=activation.receipt,
        forged_snapshot=forged_snapshot,
    )

    readonly = ReadonlyM5ArtifactRepository(database, config=_config()).scan(RUN_ID)
    assert expected_reason.value in {failure.reason_code for failure in readonly.failures}


def test_readonly_activation_rejects_self_consistent_appeal_audit_tamper(
    tmp_path: Path,
) -> None:
    from tests.integration.test_m5_sqlite_appeals import _append_review, _prepare_closed_case
    from tests.integration.test_m5_sqlite_appeals import _clock as appeal_clock

    database, repository, closed, _, _, automatic = _prepare_closed_case(tmp_path)
    _append_review(repository, closed.case.case_id)
    evaluated_at = appeal_clock()
    snapshot = repository.load_appeal_window_snapshot(
        RUN_ID,
        closed.case.case_id,
        evaluated_at,
    )
    activation = evaluate_m5_automatic_activation(
        authority=automatic,
        appeal_snapshot=snapshot,
        evaluated_at=evaluated_at,
    )
    assert activation.receipt.outcome == M5PrecedentActivationOutcome.APPEAL_PRESENT
    assert repository.commit_activation(activation) == activation

    with sqlite3.connect(database) as connection:
        row = connection.execute(
            """
            SELECT ae.entry_json
            FROM case_versions AS cv
            JOIN audit_entries AS ae
              ON ae.run_id = cv.run_id AND ae.sequence = cv.audit_sequence
            WHERE cv.run_id = ? AND cv.case_id = ? AND cv.revision = ?
            """,
            (RUN_ID, closed.case.case_id, snapshot.source_case_revision),
        ).fetchone()
        assert row is not None and isinstance(row[0], str)
        audit = AuditEntry.model_validate_json(row[0])
        forged_before = "f" * 64
        assert forged_before not in {audit.before_sha256, audit.after_sha256}
        forged_audit = AuditEntryDraft.model_validate(
            {
                **audit.model_dump(mode="python", exclude={"entry_hash"}),
                "before_sha256": forged_before,
            }
        ).seal()
        entry_json = canonical_json(forged_audit.model_dump(mode="json"))
        trigger = connection.execute(
            """
            SELECT sql FROM sqlite_master
            WHERE type = 'trigger' AND name = 'audit_entries_no_update'
            """
        ).fetchone()
        assert trigger is not None and isinstance(trigger[0], str)
        connection.execute("DROP TRIGGER audit_entries_no_update")
        cursor = connection.execute(
            """
            UPDATE audit_entries
            SET before_sha256 = ?, entry_hash = ?, entry_json = ?, document_sha256 = ?
            WHERE run_id = ? AND sequence = ?
            """,
            (
                forged_audit.before_sha256,
                forged_audit.entry_hash,
                entry_json,
                hashlib.sha256(entry_json.encode("utf-8")).hexdigest(),
                forged_audit.run_id,
                forged_audit.sequence,
            ),
        )
        assert cursor.rowcount == 1
        connection.execute(trigger[0])

    readonly = ReadonlyM5ArtifactRepository(database, config=_config()).scan(RUN_ID)
    assert M5ActivationAuthorityReasonCode.ACTIVATION_APPEAL_INVENTORY_MISMATCH.value in {
        failure.reason_code for failure in readonly.failures
    }


def test_readonly_activation_rejects_duplicate_appeal_present_semantic_decision(
    tmp_path: Path,
) -> None:
    from tests.integration.test_m5_sqlite_appeals import _append_review, _prepare_closed_case
    from tests.integration.test_m5_sqlite_appeals import _clock as appeal_clock

    database, repository, closed, manifest, _, automatic = _prepare_closed_case(tmp_path)
    _append_review(repository, closed.case.case_id)
    evaluated_at = appeal_clock()
    first_snapshot = repository.load_appeal_window_snapshot(
        RUN_ID,
        closed.case.case_id,
        evaluated_at,
    )
    first = evaluate_m5_automatic_activation(
        authority=automatic,
        appeal_snapshot=first_snapshot,
        evaluated_at=evaluated_at,
    )
    assert first.receipt.outcome == M5PrecedentActivationOutcome.APPEAL_PRESENT
    assert repository.commit_activation(first) == first
    second_at = evaluated_at + timedelta(seconds=1)
    second_snapshot = repository.load_appeal_window_snapshot(
        RUN_ID,
        closed.case.case_id,
        second_at,
    )
    second = evaluate_m5_automatic_activation(
        authority=automatic,
        appeal_snapshot=second_snapshot,
        evaluated_at=second_at,
    )
    receipt_json = canonical_json(second.receipt.model_dump(mode="json"))
    context_json = canonical_json(second_snapshot.model_dump(mode="json"))
    with sqlite3.connect(database) as connection:
        connection.execute("DROP INDEX uq_precedent_lifecycle_appeal_present_prior")
        connection.execute(
            """
            INSERT INTO precedent_lifecycle_receipts(
                run_id, receipt_id, receipt_kind, outcome,
                primary_precedent_id, primary_prior_authority_id,
                primary_prior_revision, primary_resulting_authority_id,
                primary_resulting_revision, secondary_precedent_id,
                secondary_prior_authority_id, secondary_prior_revision,
                secondary_resulting_authority_id, secondary_resulting_revision,
                manifest_id, receipt_json, context_json, context_sha256,
                document_sha256
            ) VALUES (?, ?, 'ACTIVATION', ?, ?, ?, ?, ?, ?, NULL, NULL, NULL, NULL, NULL,
                      ?, ?, ?, ?, ?)
            """,
            (
                second.receipt.run_id,
                second.receipt.receipt_id,
                second.receipt.outcome.value,
                second.receipt.precedent_id,
                second.receipt.prior_authority_id,
                second.receipt.prior_revision,
                second.receipt.resulting_authority_id,
                second.receipt.resulting_revision,
                manifest.manifest_id,
                receipt_json,
                context_json,
                hashlib.sha256(context_json.encode("utf-8")).hexdigest(),
                hashlib.sha256(receipt_json.encode("utf-8")).hexdigest(),
            ),
        )
        connection.execute(
            """
            CREATE INDEX uq_precedent_lifecycle_appeal_present_prior
            ON precedent_lifecycle_receipts(run_id, receipt_id)
            """
        )

    readonly = ReadonlyM5ArtifactRepository(database, config=_config()).scan(RUN_ID)
    assert M5ActivationAuthorityReasonCode.ACTIVATION_REPLAY_MISMATCH.value in {
        failure.reason_code for failure in readonly.failures
    }


def test_conflict_listing_and_revocation_preserve_historical_authority(tmp_path: Path) -> None:
    database, case_id, manifest = _install(tmp_path)
    repository = SQLiteM5Repository(database, BUSY_TIMEOUT_MS, _clock)
    first = _authority(manifest, "precedent-a", direction=VerdictDecision.ESTABLISHED)
    second = _authority(manifest, "precedent-b", direction=VerdictDecision.NOT_ESTABLISHED)
    repository.append_authority(first, None)
    repository.append_authority(second, None)
    query = _query(manifest, case_id)
    historical_result = ExactM5PrecedentRetrievalService().retrieve(
        query,
        repository.list_for_retrieval(query),
    )
    conflict_snapshot = repository.load_conflict_snapshot(RUN_ID, 10)
    resolution = resolve_m5_precedent_conflict_batch(
        snapshot=conflict_snapshot,
        policy=_policy(),
        scan_limit=10,
    )
    assert repository.commit_conflict_batch(resolution) == resolution
    assert tuple(
        authority.precedent.precedent_id for authority in repository.list_conflicts(RUN_ID, 10)
    ) == ("precedent-a", "precedent-b")

    snapshot = repository.citation_snapshot(RUN_ID, "precedent-a")
    first_result = next(
        authority
        for authority in resolution.resulting_authorities
        if authority.precedent.precedent_id == first.precedent.precedent_id
    )
    revocation = revoke_m5_precedent(
        authority=first_result,
        citation_snapshot=snapshot,
        revoked_by_ref="appeal-m5-test",
        revoked_at=NOW,
    )
    assert repository.commit_revocation(revocation) == revocation
    assert repository.commit_revocation(revocation) == revocation
    citation = record_m5_precedent_citation(
        result=historical_result,
        precedent_id=first.precedent.precedent_id,
        cited_at=NOW,
    )
    assert repository.commit_citation(citation) == citation
    assert repository.get_precedent(RUN_ID, "precedent-a") == revocation.authority
    assert repository.citation_snapshot(RUN_ID, "precedent-a").citations == (citation.citation,)
    assert tuple(
        authority.precedent.precedent_id for authority in repository.list_conflicts(RUN_ID, 10)
    ) == ("precedent-b",)
    with sqlite3.connect(database) as connection:
        assert connection.execute(
            """
            SELECT event_kind, COUNT(*)
            FROM m5_precedent_causal_events
            GROUP BY event_kind ORDER BY event_kind
            """
        ).fetchall() == [
            ("PRECEDENT_AUTHORITY_APPENDED", 5),
            ("PRECEDENT_CITATION_APPENDED", 1),
            ("PRECEDENT_CONFLICT_BATCH_COMMITTED", 1),
            ("PRECEDENT_REVOCATION_COMMITTED", 1),
        ]


def test_already_revoked_appends_one_marker_without_another_authority(
    tmp_path: Path,
) -> None:
    database, _case_id, manifest = _install(tmp_path)
    repository = SQLiteM5Repository(database, BUSY_TIMEOUT_MS, _clock)
    initial = _authority(manifest, "precedent-already-revoked")
    repository.append_authority(initial, None)
    first_snapshot = repository.citation_snapshot(
        RUN_ID,
        initial.precedent.precedent_id,
    )
    first = revoke_m5_precedent(
        authority=initial,
        citation_snapshot=first_snapshot,
        revoked_by_ref="appeal-already-revoked",
        revoked_at=NOW,
    )
    repository.commit_revocation(first)
    second_snapshot = repository.citation_snapshot(
        RUN_ID,
        initial.precedent.precedent_id,
    )
    second = revoke_m5_precedent(
        authority=first.authority,
        citation_snapshot=second_snapshot,
        revoked_by_ref="appeal-already-revoked",
        revoked_at=NOW,
    )
    assert second.receipt.outcome.value == "ALREADY_REVOKED"
    assert repository.commit_revocation(second) == second
    assert repository.commit_revocation(second) == second

    with sqlite3.connect(database) as connection:
        assert connection.execute("SELECT COUNT(*) FROM precedents").fetchone() == (2,)
        assert connection.execute(
            """
            SELECT outcome FROM precedent_lifecycle_receipts
            WHERE receipt_kind = 'REVOCATION' ORDER BY primary_prior_revision
            """
        ).fetchall() == [("REVOKED",), ("ALREADY_REVOKED",)]
        markers = connection.execute(
            """
            SELECT sequence FROM m5_precedent_causal_events
            WHERE event_kind = 'PRECEDENT_REVOCATION_COMMITTED'
            ORDER BY sequence
            """
        ).fetchall()
        assert len(markers) == 2
        assert markers[1][0] == markers[0][0] + 1


def test_conflict_candidate_scan_returns_only_active_heads_in_stable_order(
    tmp_path: Path,
) -> None:
    database, _case_id, manifest = _install(tmp_path)
    repository = SQLiteM5Repository(database, BUSY_TIMEOUT_MS, _clock)
    presence_b = _authority(
        manifest,
        "precedent-active-b",
        direction=VerdictDecision.ESTABLISHED,
    )
    presence_a = _authority(
        manifest,
        "precedent-active-a",
        direction=VerdictDecision.NOT_ESTABLISHED,
    )
    absence_z = _authority(
        manifest,
        "precedent-active-z",
        evidence_class=EvidenceClass.ABSENCE,
        violation_type=ViolationType.PPE_GOGGLES_MISSING,
    )
    for authority in (presence_b, presence_a, absence_z):
        repository.append_authority(authority, None)

    snapshot = repository.load_conflict_snapshot(RUN_ID, 10)
    candidates = snapshot.authorities
    assert tuple(item.precedent.precedent_id for item in candidates) == (
        "precedent-active-a",
        "precedent-active-b",
        "precedent-active-z",
    )
    with pytest.raises(ContractViolation, match="complete snapshot budget"):
        repository.load_conflict_snapshot(RUN_ID, 2)
    restarted = SQLiteM5Repository(database, BUSY_TIMEOUT_MS, _clock)
    with pytest.raises(ContractViolation, match="complete snapshot budget"):
        restarted.load_conflict_snapshot(RUN_ID, 2)
    assert restarted.load_conflict_snapshot(RUN_ID, 3) == snapshot

    resolution = resolve_m5_precedent_conflict_batch(
        snapshot=snapshot,
        policy=_policy(),
        scan_limit=10,
    )
    repository.commit_conflict_batch(resolution)
    assert repository.load_conflict_snapshot(RUN_ID, 10).authorities == (absence_z,)

    with pytest.raises(ContractViolation, match="limit"):
        repository.load_conflict_snapshot(RUN_ID, 0)


def test_conflict_batch_commits_complete_three_node_graph_and_exactly_replays(
    tmp_path: Path,
) -> None:
    database, _case_id, manifest = _install(tmp_path)
    repository = SQLiteM5Repository(database, BUSY_TIMEOUT_MS, _clock)
    authorities = (
        _authority(
            manifest,
            "precedent-graph-a",
            direction=VerdictDecision.ESTABLISHED,
        ),
        _authority(
            manifest,
            "precedent-graph-b",
            direction=VerdictDecision.NOT_ESTABLISHED,
        ),
        _authority(
            manifest,
            "precedent-graph-c",
            direction=VerdictDecision.ESTABLISHED,
        ),
    )
    for authority in authorities:
        repository.append_authority(authority, None)
    resolution = resolve_m5_precedent_conflict_batch(
        snapshot=repository.load_conflict_snapshot(RUN_ID, 3),
        policy=_policy(),
        scan_limit=3,
    )

    assert repository.commit_conflict_batch(resolution) == resolution
    assert repository.commit_conflict_batch(resolution) == resolution
    restarted = SQLiteM5Repository(database, BUSY_TIMEOUT_MS, _clock)
    assert restarted.commit_conflict_batch(resolution) == resolution
    assert tuple(item.precedent.precedent_id for item in restarted.list_conflicts(RUN_ID, 10)) == (
        "precedent-graph-a",
        "precedent-graph-b",
        "precedent-graph-c",
    )
    with sqlite3.connect(database) as connection:
        assert connection.execute("SELECT COUNT(*) FROM precedents").fetchone() == (6,)
        assert connection.execute("SELECT COUNT(*) FROM precedent_conflict_batches").fetchone() == (
            1,
        )
        assert connection.execute(
            "SELECT COUNT(*) FROM precedent_conflict_batch_receipts"
        ).fetchone() == (1,)
        assert connection.execute(
            "SELECT COUNT(*) FROM precedent_lifecycle_receipts WHERE receipt_kind = 'CONFLICT'"
        ).fetchone() == (0,)
        assert connection.execute("SELECT COUNT(*) FROM m5_precedent_causal_events").fetchone() == (
            7,
        )
    readonly = ReadonlyM5ArtifactRepository(database, config=_config()).scan(RUN_ID)
    assert readonly.failures == ()
    counts = {item.authority_kind: item.count for item in readonly.traversed}
    assert counts[M5AuthorityKind.PRECEDENT_CONFLICT_BATCH] == 1
    assert counts[M5AuthorityKind.PRECEDENT_CONFLICT_BATCH_RECEIPT] == 1


def test_historical_citation_after_conflict_does_not_change_head(tmp_path: Path) -> None:
    database, case_id, manifest = _install(tmp_path)
    repository = SQLiteM5Repository(database, BUSY_TIMEOUT_MS, _clock)
    first = _authority(
        manifest,
        "precedent-stale-a",
        direction=VerdictDecision.ESTABLISHED,
    )
    second = _authority(
        manifest,
        "precedent-stale-b",
        direction=VerdictDecision.NOT_ESTABLISHED,
    )
    repository.append_authority(first, None)
    repository.append_authority(second, None)
    stale = resolve_m5_precedent_conflict_batch(
        snapshot=repository.load_conflict_snapshot(RUN_ID, 3),
        policy=_policy(),
        scan_limit=3,
    )
    retrieval = ExactM5PrecedentRetrievalService().retrieve(
        _query(manifest, case_id),
        repository.list_for_retrieval(_query(manifest, case_id)),
    )
    citation = record_m5_precedent_citation(
        result=retrieval,
        precedent_id=first.precedent.precedent_id,
        cited_at=NOW,
    )
    assert repository.commit_conflict_batch(stale) == stale
    assert repository.commit_citation(citation) == citation
    assert (
        repository.get_precedent(RUN_ID, first.precedent.precedent_id)
        == (stale.resulting_authorities[0])
    )
    assert (
        repository.get_precedent(RUN_ID, second.precedent.precedent_id)
        == (stale.resulting_authorities[1])
    )
    assert repository.citation_snapshot(RUN_ID, first.precedent.precedent_id).citations == (
        citation.citation,
    )
    with sqlite3.connect(database) as connection:
        assert connection.execute("SELECT COUNT(*) FROM precedent_conflict_batches").fetchone() == (
            1,
        )
        assert connection.execute(
            "SELECT COUNT(*) FROM precedent_conflict_batch_receipts"
        ).fetchone() == (1,)


def test_readonly_validation_rejects_conflict_batch_without_its_receipt(tmp_path: Path) -> None:
    database, _case_id, manifest = _install(tmp_path)
    repository = SQLiteM5Repository(database, BUSY_TIMEOUT_MS, _clock)
    authorities = (
        _authority(manifest, "precedent-closure-a", direction=VerdictDecision.ESTABLISHED),
        _authority(
            manifest,
            "precedent-closure-b",
            direction=VerdictDecision.NOT_ESTABLISHED,
        ),
    )
    for authority in authorities:
        repository.append_authority(authority, None)
    resolution = resolve_m5_precedent_conflict_batch(
        snapshot=repository.load_conflict_snapshot(RUN_ID, 2),
        policy=_policy(),
        scan_limit=2,
    )
    repository.commit_conflict_batch(resolution)

    with sqlite3.connect(database) as connection:
        connection.execute("DROP TRIGGER precedent_conflict_batch_receipts_no_delete")
        connection.execute(
            "DELETE FROM precedent_conflict_batch_receipts WHERE run_id = ?",
            (RUN_ID,),
        )
        connection.execute(
            """
            CREATE TRIGGER precedent_conflict_batch_receipts_no_delete
            BEFORE DELETE ON precedent_conflict_batch_receipts
            BEGIN
                SELECT RAISE(ABORT, 'precedent_conflict_batch_receipts is append-only');
            END
            """
        )

    snapshot = ReadonlyM5ArtifactRepository(database, config=_config()).scan(RUN_ID)
    assert "CONFLICT_BATCH_RECEIPT_CLOSURE_INVALID" in {
        failure.reason_code for failure in snapshot.failures
    }


@pytest.mark.parametrize(
    "fault_phase",
    (
        "precedent.conflict_batch.before_authorities",
        "precedent.conflict_batch.resulting_authority.2.before_causal_event",
        "precedent.conflict_batch.resulting_authority.2.after_causal_event",
        "precedent.conflict_batch.after_authority",
        "precedent.conflict_batch.after_authorities",
        "precedent.conflict_batch.after_batch_authority",
        "precedent.conflict_batch.after_batch_receipt",
    ),
)
def test_conflict_batch_faults_roll_back_every_successor_and_batch_root(
    tmp_path: Path,
    fault_phase: str,
) -> None:
    database, _case_id, manifest = _install(tmp_path)
    repository = SQLiteM5Repository(database, BUSY_TIMEOUT_MS, _clock)
    authorities = (
        _authority(manifest, "precedent-fault-a", direction=VerdictDecision.ESTABLISHED),
        _authority(manifest, "precedent-fault-b", direction=VerdictDecision.NOT_ESTABLISHED),
        _authority(manifest, "precedent-fault-c", direction=VerdictDecision.ESTABLISHED),
    )
    for authority in authorities:
        repository.append_authority(authority, None)
    resolution = resolve_m5_precedent_conflict_batch(
        snapshot=repository.load_conflict_snapshot(RUN_ID, 3),
        policy=_policy(),
        scan_limit=3,
    )

    def fail_at(phase: str) -> None:
        if phase == fault_phase:
            raise RuntimeError("injected M5 conflict batch fault")

    faulted = SQLiteM5Repository(
        database,
        BUSY_TIMEOUT_MS,
        _clock,
        fault_injector=fail_at,
    )
    with pytest.raises(RuntimeError, match="injected M5 conflict batch fault"):
        faulted.commit_conflict_batch(resolution)

    with sqlite3.connect(database) as connection:
        assert connection.execute("SELECT COUNT(*) FROM precedents").fetchone() == (3,)
        assert connection.execute("SELECT COUNT(*) FROM precedent_conflict_batches").fetchone() == (
            0,
        )
        assert connection.execute(
            "SELECT COUNT(*) FROM precedent_conflict_batch_receipts"
        ).fetchone() == (0,)
        assert connection.execute("SELECT COUNT(*) FROM m5_precedent_causal_events").fetchone() == (
            3,
        )
    recovered = SQLiteM5Repository(database, BUSY_TIMEOUT_MS, _clock)
    assert recovered.commit_conflict_batch(resolution) == resolution


def test_conflict_commit_rejects_receipt_forged_for_embedded_policy(tmp_path: Path) -> None:
    database, _case_id, manifest = _install(tmp_path)
    repository = SQLiteM5Repository(database, BUSY_TIMEOUT_MS, _clock)
    first = _authority(
        manifest,
        "precedent-policy-a",
        direction=VerdictDecision.ESTABLISHED,
    )
    second = _authority(
        manifest,
        "precedent-policy-b",
        direction=VerdictDecision.NOT_ESTABLISHED,
    )
    repository.append_authority(first, None)
    repository.append_authority(second, None)
    baseline_policy = _policy()
    baseline = resolve_m5_precedent_conflict(
        existing=first,
        new=second,
        policy=baseline_policy,
    )
    forged_policy = baseline_policy.model_copy(update={"conflict_similarity": 0.75})
    forged_receipt = baseline.receipt.model_copy(update={"policy_id": forged_policy.policy_id})
    forged = M5PrecedentConflictResolution(
        policy=forged_policy,
        receipt=forged_receipt,
        existing_authority=baseline.existing_authority,
        new_authority=baseline.new_authority,
    )

    with pytest.raises(ContractViolation, match="pair-wise M5 conflict writes are disabled"):
        repository.commit_conflict(forged)
    assert repository.get_precedent(RUN_ID, first.precedent.precedent_id) == first
    assert repository.get_precedent(RUN_ID, second.precedent.precedent_id) == second


def test_foreign_valid_config_cannot_control_precedent_storage_retrieval_or_conflict(
    tmp_path: Path,
) -> None:
    database, case_id, manifest = _install(tmp_path)
    repository = SQLiteM5Repository(database, BUSY_TIMEOUT_MS, _clock)
    foreign_policy = m5_precedent_policy_from_config(_foreign_valid_config())

    foreign = _authority(
        manifest,
        "precedent-foreign-config",
        policy=foreign_policy,
    )
    with pytest.raises(ManifestMismatch, match="config"):
        repository.append_authority(foreign, None)

    first = _authority(
        manifest,
        "precedent-config-a",
        direction=VerdictDecision.ESTABLISHED,
    )
    second = _authority(
        manifest,
        "precedent-config-b",
        direction=VerdictDecision.NOT_ESTABLISHED,
    )
    repository.append_authority(first, None)
    repository.append_authority(second, None)

    foreign_query = _query(manifest, case_id, policy=foreign_policy)
    with pytest.raises(ManifestMismatch, match="policy"):
        repository.list_for_retrieval(foreign_query)

    baseline = resolve_m5_precedent_conflict(
        existing=first,
        new=second,
        policy=_policy(),
    )
    forged_receipt = baseline.receipt.model_copy(update={"policy_id": foreign_policy.policy_id})
    forged = M5PrecedentConflictResolution(
        policy=foreign_policy,
        receipt=forged_receipt,
        existing_authority=baseline.existing_authority,
        new_authority=baseline.new_authority,
    )
    with pytest.raises(ContractViolation, match="pair-wise M5 conflict writes are disabled"):
        repository.commit_conflict(forged)

    assert repository.get_precedent(RUN_ID, first.precedent.precedent_id) == first
    assert repository.get_precedent(RUN_ID, second.precedent.precedent_id) == second


def test_revocation_commit_rejects_incomplete_embedded_citation_snapshot(
    tmp_path: Path,
) -> None:
    database, case_id, manifest = _install(tmp_path)
    repository = SQLiteM5Repository(database, BUSY_TIMEOUT_MS, _clock)
    initial = _authority(manifest, "precedent-incomplete-revocation")
    repository.append_authority(initial, None)
    query = _query(manifest, case_id)
    retrieval = ExactM5PrecedentRetrievalService().retrieve(
        query,
        repository.list_for_retrieval(query),
    )
    citation = record_m5_precedent_citation(
        result=retrieval,
        precedent_id=initial.precedent.precedent_id,
        cited_at=NOW,
    )
    repository.commit_citation(citation)
    cited = initial
    complete = repository.citation_snapshot(RUN_ID, initial.precedent.precedent_id)
    exact = revoke_m5_precedent(
        authority=cited,
        citation_snapshot=complete,
        revoked_by_ref="appeal-forged-snapshot",
        revoked_at=NOW,
    )
    incomplete = M5PrecedentCitationSnapshot(
        run_id=RUN_ID,
        precedent_id=initial.precedent.precedent_id,
        captured_at=NOW,
    )
    forged_receipt = exact.receipt.model_copy(
        update={
            "citation_snapshot_id": incomplete.snapshot_id,
            "historical_case_ids": (),
            "historical_citation_ids": (),
        }
    )
    forged = M5PrecedentRevocationResult(
        citation_snapshot=incomplete,
        receipt=forged_receipt,
        authority=exact.authority,
    )

    with pytest.raises(ContractViolation, match="citation snapshot is not complete"):
        repository.commit_revocation(forged)
    assert repository.get_precedent(RUN_ID, initial.precedent.precedent_id) == cited


@pytest.mark.parametrize(
    "fault_phase",
    (
        "precedent.revocation.resulting_authority.before_causal_event",
        "precedent.revocation.resulting_authority.after_causal_event",
        "precedent.revocation.after_authority",
        "precedent.revocation.receipt.after_source",
        "precedent.revocation.receipt.before_causal_event",
        "precedent.revocation.receipt.after_causal_event",
        "precedent.revocation.after_receipt",
    ),
)
def test_revocation_fault_rolls_back_authority_receipt_and_marker(
    tmp_path: Path,
    fault_phase: str,
) -> None:
    database, _case_id, manifest = _install(tmp_path)
    clean = SQLiteM5Repository(database, BUSY_TIMEOUT_MS, _clock)
    initial = _authority(manifest, "precedent-revocation-fault")
    clean.append_authority(initial, None)
    snapshot = clean.citation_snapshot(RUN_ID, initial.precedent.precedent_id)
    revocation = revoke_m5_precedent(
        authority=initial,
        citation_snapshot=snapshot,
        revoked_by_ref="appeal-revocation-fault",
        revoked_at=NOW,
    )

    def fault(phase: str) -> None:
        if phase == fault_phase:
            raise RuntimeError("injected M5 revocation fault")

    faulty = SQLiteM5Repository(
        database,
        BUSY_TIMEOUT_MS,
        _clock,
        fault_injector=fault,
    )
    with pytest.raises(RuntimeError, match="injected M5 revocation fault"):
        faulty.commit_revocation(revocation)
    assert clean.get_precedent(RUN_ID, initial.precedent.precedent_id) == initial
    with sqlite3.connect(database) as connection:
        assert connection.execute("SELECT COUNT(*) FROM precedents").fetchone() == (1,)
        assert connection.execute(
            "SELECT COUNT(*) FROM precedent_lifecycle_receipts"
        ).fetchone() == (0,)
        assert connection.execute("SELECT COUNT(*) FROM m5_precedent_causal_events").fetchone() == (
            1,
        )
    assert clean.commit_revocation(revocation) == revocation


@pytest.mark.parametrize(
    "fault_phase",
    (
        "precedent.citation.direct.before_causal_event",
        "precedent.citation.direct.after_causal_event",
        "precedent.citation.after_append",
    ),
)
def test_fault_after_citation_authority_rolls_back_every_root(
    tmp_path: Path,
    fault_phase: str,
) -> None:
    database, case_id, manifest = _install(tmp_path)
    clean = SQLiteM5Repository(database, BUSY_TIMEOUT_MS, _clock)
    initial = _authority(manifest, "precedent-fault")
    clean.append_authority(initial, None)
    query = _query(manifest, case_id)
    result = ExactM5PrecedentRetrievalService().retrieve(
        query,
        clean.list_for_retrieval(query),
    )
    commit = record_m5_precedent_citation(
        result=result,
        precedent_id=initial.precedent.precedent_id,
        cited_at=NOW,
    )

    def fault(phase: str) -> None:
        if phase == fault_phase:
            raise RuntimeError("injected M5 citation fault")

    faulty = SQLiteM5Repository(
        database,
        BUSY_TIMEOUT_MS,
        _clock,
        fault_injector=fault,
    )
    with pytest.raises(RuntimeError, match="injected"):
        faulty.commit_citation(commit)
    assert clean.get_precedent(RUN_ID, initial.precedent.precedent_id) == initial
    with sqlite3.connect(database) as connection:
        assert connection.execute("SELECT COUNT(*) FROM precedents").fetchone() == (1,)
        assert connection.execute("SELECT COUNT(*) FROM precedent_citations").fetchone() == (0,)
        assert connection.execute("SELECT COUNT(*) FROM m5_precedent_causal_events").fetchone() == (
            1,
        )


def test_guard_and_canonical_index_tamper_fail_closed(tmp_path: Path) -> None:
    database, _case_id, manifest = _install(tmp_path)
    repository = SQLiteM5Repository(database, BUSY_TIMEOUT_MS, _clock)
    authority = _authority(manifest, "precedent-tamper")
    repository.append_authority(authority, None)

    connection = sqlite3.connect(database)
    try:
        trigger_sql = connection.execute(
            "SELECT sql FROM sqlite_master WHERE type = 'trigger' AND name = 'precedents_no_update'"
        ).fetchone()
        assert trigger_sql is not None and isinstance(trigger_sql[0], str)
        connection.execute("DROP TRIGGER precedents_no_update")
        connection.execute(
            "UPDATE precedents SET source = 'HUMAN_REVIEW' WHERE run_id = ? AND precedent_id = ?",
            (RUN_ID, authority.precedent.precedent_id),
        )
        connection.execute(str(trigger_sql[0]))
        connection.commit()
    finally:
        connection.close()
    with pytest.raises(RepositoryIntegrityError, match="index columns"):
        repository.get_precedent(RUN_ID, authority.precedent.precedent_id)

    connection = sqlite3.connect(database)
    try:
        connection.execute("DROP INDEX uq_alert_dispatch_receipts_success_outbox")
        connection.commit()
    finally:
        connection.close()
    with pytest.raises(MigrationIntegrityError, match="0009"):
        repository.get_precedent(RUN_ID, authority.precedent.precedent_id)


def test_canonical_database_rewrite_cannot_turn_a_claimed_vector_into_authority(
    tmp_path: Path,
) -> None:
    database, _case_id, manifest = _install(tmp_path)
    repository = SQLiteM5Repository(database, BUSY_TIMEOUT_MS, _clock)
    authority = _authority(manifest, "precedent-vector-rewrite")
    repository.append_authority(authority, None)
    assert authority.text_embedding is not None

    forged_embedding = M5EmbeddingVector(
        request=authority.text_embedding.request,
        values=tuple(-value for value in authority.text_embedding.values),
    )
    forged_precedent = authority.precedent.model_copy(
        update={"text_embedding_ref": forged_embedding.embedding_id}
    )
    forged_authority = authority.model_copy(
        update={
            "precedent": forged_precedent,
            "text_embedding": forged_embedding,
        }
    )
    embedding_document = canonical_json(forged_embedding.model_dump(mode="json"))
    authority_document = canonical_json(forged_authority.model_dump(mode="json"))

    connection = sqlite3.connect(database)
    try:
        embedding_trigger = connection.execute(
            """
            SELECT sql FROM sqlite_master
            WHERE type = 'trigger' AND name = 'precedent_embeddings_no_update'
            """
        ).fetchone()
        precedent_trigger = connection.execute(
            "SELECT sql FROM sqlite_master WHERE type = 'trigger' AND name = 'precedents_no_update'"
        ).fetchone()
        assert embedding_trigger is not None and isinstance(embedding_trigger[0], str)
        assert precedent_trigger is not None and isinstance(precedent_trigger[0], str)
        connection.execute("DROP TRIGGER precedent_embeddings_no_update")
        connection.execute("DROP TRIGGER precedents_no_update")
        connection.execute(
            """
            UPDATE precedent_embeddings
            SET embedding_id = ?, embedding_json = ?, document_sha256 = ?
            WHERE run_id = ? AND embedding_id = ?
            """,
            (
                forged_embedding.embedding_id,
                embedding_document,
                hashlib.sha256(embedding_document.encode("utf-8")).hexdigest(),
                RUN_ID,
                authority.text_embedding.embedding_id,
            ),
        )
        connection.execute(
            """
            UPDATE precedents
            SET authority_id = ?, text_embedding_id = ?, authority_json = ?, document_sha256 = ?
            WHERE run_id = ? AND precedent_id = ? AND revision = 1
            """,
            (
                forged_authority.authority_id,
                forged_embedding.embedding_id,
                authority_document,
                hashlib.sha256(authority_document.encode("utf-8")).hexdigest(),
                RUN_ID,
                authority.precedent.precedent_id,
            ),
        )
        connection.execute(str(embedding_trigger[0]))
        connection.execute(str(precedent_trigger[0]))
        connection.commit()
    finally:
        connection.close()

    with pytest.raises(RepositoryIntegrityError, match="controlled fake reconstruction"):
        repository.get_precedent(RUN_ID, authority.precedent.precedent_id)


def test_constructor_rejects_untrusted_optional_collaborators(tmp_path: Path) -> None:
    database, _case_id, _manifest_value = _install(tmp_path)
    with pytest.raises(TypeError, match="alert_policy_verifier"):
        SQLiteM5Repository(
            database,
            BUSY_TIMEOUT_MS,
            _clock,
            alert_policy_verifier=object(),  # type: ignore[arg-type]
        )
    with pytest.raises(TypeError, match="fault_injector"):
        SQLiteM5Repository(
            database,
            BUSY_TIMEOUT_MS,
            _clock,
            fault_injector=object(),  # type: ignore[arg-type]
        )
