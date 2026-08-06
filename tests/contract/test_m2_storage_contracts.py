import pytest
from pydantic import ValidationError

from labcourt.contracts.audit import AuditChainReport, AuditEntry, AuditEntryDraft
from labcourt.contracts.base import FrozenContractModel
from labcourt.contracts.enums import (
    ArtifactKind,
    ClosureDefectCode,
    MediaAvailability,
    MediaType,
    PurgeDisposition,
    PurgeReasonCode,
    RetentionHoldKind,
    VerificationStatus,
)
from labcourt.contracts.storage import (
    CLOSURE_VALIDATOR_VERSION,
    ArtifactRef,
    ArtifactVerification,
    ClosureDefect,
    ClosureReport,
    PurgeItemResult,
    RetentionHold,
    ScopedArtifactRef,
)

SHA_A = "a" * 64
SHA_B = "b" * 64
SHA_C = "c" * 64
CASE_ID = "d5dc6bd1-9bc7-5cc6-a9b1-ecba4cadd617"
EVENT_ID = "8e8fe3bd-71d7-5b33-a8e3-1b4057586427"
RUN_ID = "run-01"


def _crop_ref(digest: str = SHA_A) -> ArtifactRef:
    return ArtifactRef(kind=ArtifactKind.CROP, artifact_id=digest)


def _media_ref(digest: str = SHA_C) -> ArtifactRef:
    return ArtifactRef(kind=ArtifactKind.MEDIA, artifact_id=digest)


def _frame_ref(index: int = 7) -> ArtifactRef:
    return ArtifactRef(
        kind=ArtifactKind.FRAME,
        artifact_id=f"cam-01:stream-01:{index}",
    )


def _case_ref(case_id: str = CASE_ID) -> ArtifactRef:
    return ArtifactRef(kind=ArtifactKind.CASE, artifact_id=case_id)


def _scoped(ref: ArtifactRef, run_id: str = RUN_ID) -> ScopedArtifactRef:
    return ScopedArtifactRef(run_id=run_id, ref=ref)


def _closure_payload() -> dict[str, object]:
    return {
        "run_id": RUN_ID,
        "root_ref": _case_ref(),
        "manifest_id": SHA_B,
        "input_sha256": SHA_C,
        "checked_refs": (_case_ref(), _crop_ref(), _frame_ref()),
    }


def _verified_payload(
    artifact_ref: ArtifactRef | None = None,
) -> dict[str, object]:
    return {
        "artifact_ref": artifact_ref or _crop_ref(),
        "status": VerificationStatus.VERIFIED,
        "availability": MediaAvailability.AVAILABLE,
        "media_type": MediaType.IMAGE_PNG,
        "expected_source_pixel_sha256": SHA_A,
        "actual_source_pixel_sha256": SHA_A,
        "expected_output_pixel_sha256": SHA_B,
        "actual_output_pixel_sha256": SHA_B,
        "expected_media_sha256": SHA_C,
        "actual_media_sha256": SHA_C,
        "expected_width": 32,
        "actual_width": 32,
        "expected_height": 24,
        "actual_height": 24,
        "expected_size_bytes": 128,
        "actual_size_bytes": 128,
    }


def _without_actuals(payload: dict[str, object]) -> dict[str, object]:
    result = dict(payload)
    for key in tuple(result):
        if key.startswith("actual_"):
            result[key] = None
    return result


def test_m2_value_contracts_are_frozen_contract_models() -> None:
    for model in (
        ArtifactRef,
        ScopedArtifactRef,
        ClosureDefect,
        ClosureReport,
        ArtifactVerification,
        RetentionHold,
        AuditEntryDraft,
        AuditEntry,
        AuditChainReport,
    ):
        assert issubclass(model, FrozenContractModel)


@pytest.mark.parametrize(
    ("kind", "artifact_id"),
    [
        (ArtifactKind.FRAME, "cam-01:stream-01:7"),
        (ArtifactKind.CROP, SHA_A),
        (ArtifactKind.MEDIA, SHA_A),
        (ArtifactKind.EVIDENCE_PACK, SHA_A),
        (ArtifactKind.MANIFEST, SHA_A),
        (ArtifactKind.CASE, CASE_ID),
        (ArtifactKind.EVENT, EVENT_ID),
        (ArtifactKind.OBJECTIVE_FACT, "fact-01"),
    ],
)
def test_artifact_ref_uses_kind_specific_identifier_syntax(
    kind: ArtifactKind,
    artifact_id: str,
) -> None:
    ref = ArtifactRef(kind=kind, artifact_id=artifact_id)
    assert ref.artifact_id == artifact_id


@pytest.mark.parametrize(
    ("kind", "artifact_id"),
    [
        (ArtifactKind.FRAME, "frame-01"),
        (ArtifactKind.FRAME, "cam-01:stream-01:007"),
        (ArtifactKind.CROP, "crop-01"),
        (ArtifactKind.MEDIA, "A" * 64),
        (ArtifactKind.CASE, "case-01"),
        (ArtifactKind.CASE, CASE_ID.upper()),
        (ArtifactKind.EVENT, "alice@example.com"),
        (ArtifactKind.RUN, "x" * 65),
    ],
)
def test_artifact_ref_rejects_invalid_identifiers(
    kind: ArtifactKind,
    artifact_id: str,
) -> None:
    with pytest.raises(ValidationError):
        ArtifactRef(kind=kind, artifact_id=artifact_id)


def test_closure_report_is_bound_to_run_root_manifest_and_input() -> None:
    report = ClosureReport(**_closure_payload())

    assert report.validator_version == CLOSURE_VALIDATOR_VERSION
    assert report.run_id == RUN_ID
    assert report.root_ref == _case_ref()
    assert report.manifest_id == SHA_B
    assert report.input_sha256 == SHA_C
    assert report.passed is True
    assert (
        ClosureReport.model_json_schema(mode="serialization")["properties"]["passed"]["readOnly"]
        is True
    )
    assert ClosureReport.model_validate(report.model_dump(mode="json")) == report

    forged = report.model_dump(mode="json")
    forged["passed"] = False
    with pytest.raises(ValidationError, match="passed does not match"):
        ClosureReport.model_validate(forged)


def test_closure_root_is_typed_and_must_be_checked() -> None:
    payload = _closure_payload()
    payload["root_ref"] = _frame_ref()
    with pytest.raises(ValidationError, match="case or evidence pack"):
        ClosureReport(**payload)

    payload = _closure_payload()
    payload["checked_refs"] = (_crop_ref(), _frame_ref())
    with pytest.raises(ValidationError, match="include root_ref"):
        ClosureReport(**payload)


def test_failing_closure_report_cannot_claim_success() -> None:
    defect = ClosureDefect(
        code=ClosureDefectCode.MEDIA_MISSING,
        artifact_ref=_crop_ref(),
        reason_code="NOT_FOUND",
    )
    report = ClosureReport(**_closure_payload(), defects=(defect,))
    assert report.passed is False

    forged = report.model_dump(mode="json")
    forged["passed"] = True
    with pytest.raises(ValidationError, match="passed does not match"):
        ClosureReport.model_validate(forged)


def test_closure_references_and_defects_require_unique_stable_order() -> None:
    payload = _closure_payload()
    payload["checked_refs"] = (_case_ref(), _crop_ref(), _crop_ref())
    with pytest.raises(ValidationError, match="checked_refs must be unique"):
        ClosureReport(**payload)

    payload = _closure_payload()
    payload["checked_refs"] = (_frame_ref(), _case_ref(), _crop_ref())
    with pytest.raises(ValidationError, match="stable artifact order"):
        ClosureReport(**payload)

    missing = ClosureDefect(
        code=ClosureDefectCode.MEDIA_MISSING,
        artifact_ref=_crop_ref(),
    )
    track = ClosureDefect(
        code=ClosureDefectCode.TRACK_MISMATCH,
        artifact_ref=_frame_ref(),
    )
    with pytest.raises(ValidationError, match="defects must be unique"):
        ClosureReport(**_closure_payload(), defects=(missing, missing))
    with pytest.raises(ValidationError, match="stable defect order"):
        ClosureReport(**_closure_payload(), defects=(track, missing))


def test_closure_defect_uses_explicit_typed_context() -> None:
    with pytest.raises(ValidationError, match="Extra inputs"):
        ClosureDefect.model_validate(
            {
                "code": ClosureDefectCode.MEDIA_MISSING,
                "artifact_ref": _crop_ref().model_dump(mode="json"),
                "details": {"message": "free-form"},
            }
        )
    with pytest.raises(ValidationError, match="different hashes"):
        ClosureDefect(
            code=ClosureDefectCode.MEDIA_HASH_MISMATCH,
            artifact_ref=_crop_ref(),
            expected_sha256=SHA_A,
            actual_sha256=SHA_A,
        )
    with pytest.raises(ValidationError, match="expected and actual dimensions"):
        ClosureDefect(
            code=ClosureDefectCode.MEDIA_DIMENSION_MISMATCH,
            artifact_ref=_crop_ref(),
        )
    with pytest.raises(ValidationError, match="expected and actual sizes"):
        ClosureDefect(
            code=ClosureDefectCode.MEDIA_SIZE_MISMATCH,
            artifact_ref=_crop_ref(),
        )
    with pytest.raises(ValidationError, match="different sizes"):
        ClosureDefect(
            code=ClosureDefectCode.MEDIA_SIZE_MISMATCH,
            artifact_ref=_crop_ref(),
            expected_size_bytes=128,
            actual_size_bytes=128,
        )


def test_legal_retention_uses_a_distinct_current_closure_defect() -> None:
    defect = ClosureDefect(
        code=ClosureDefectCode.MEDIA_PURGED_BY_RETENTION,
        artifact_ref=_crop_ref(),
        reason_code="PURGED_BY_RETENTION",
    )

    assert defect.code == ClosureDefectCode.MEDIA_PURGED_BY_RETENTION
    assert defect.reason_code == "PURGED_BY_RETENTION"


def test_artifact_verification_requires_complete_matching_matrix() -> None:
    verified = ArtifactVerification(**_verified_payload())
    assert verified.status == VerificationStatus.VERIFIED

    payload = _verified_payload()
    payload["actual_output_pixel_sha256"] = SHA_A
    with pytest.raises(ValidationError, match="every expected and actual value"):
        ArtifactVerification(**payload)

    payload = _verified_payload()
    payload["actual_width"] = None
    with pytest.raises(ValidationError, match="complete actual field matrix"):
        ArtifactVerification(**payload)

    payload = _verified_payload()
    payload.pop("media_type")
    with pytest.raises(ValidationError, match="Field required"):
        ArtifactVerification(**payload)


def test_current_media_verification_forbids_forged_source_replay() -> None:
    payload = _verified_payload()
    payload["status"] = VerificationStatus.CURRENT_MEDIA_VERIFIED
    payload["actual_source_pixel_sha256"] = None
    current = ArtifactVerification(**payload)
    assert current.status == VerificationStatus.CURRENT_MEDIA_VERIFIED
    assert current.actual_source_pixel_sha256 is None

    forged = dict(payload)
    forged["actual_source_pixel_sha256"] = SHA_A
    with pytest.raises(ValidationError, match="without source replay"):
        ArtifactVerification(**forged)

    mismatched = dict(payload)
    mismatched["actual_output_pixel_sha256"] = SHA_A
    with pytest.raises(ValidationError, match="every current value to match"):
        ArtifactVerification(**mismatched)


def test_media_ref_binds_expected_encoded_media_hash() -> None:
    ArtifactVerification(**_verified_payload(_media_ref()))

    payload = _verified_payload(_media_ref(SHA_A))
    with pytest.raises(ValidationError, match="artifact_id must equal"):
        ArtifactVerification(**payload)


@pytest.mark.parametrize(
    ("status", "field", "value"),
    [
        (VerificationStatus.SOURCE_HASH_MISMATCH, "actual_source_pixel_sha256", SHA_B),
        (VerificationStatus.PIXEL_HASH_MISMATCH, "actual_output_pixel_sha256", SHA_A),
        (VerificationStatus.MEDIA_HASH_MISMATCH, "actual_media_sha256", SHA_A),
        (VerificationStatus.SIZE_MISMATCH, "actual_size_bytes", 129),
        (VerificationStatus.DIMENSION_MISMATCH, "actual_width", 33),
    ],
)
def test_artifact_verification_requires_the_selected_mismatch(
    status: VerificationStatus,
    field: str,
    value: str | int,
) -> None:
    payload = _verified_payload()
    payload["status"] = status
    payload[field] = value
    assert ArtifactVerification(**payload).status == status

    matching = _verified_payload()
    matching["status"] = status
    with pytest.raises(ValidationError, match="mismatch requires different"):
        ArtifactVerification(**matching)


def test_purged_verification_retains_expected_facts_and_clears_actuals() -> None:
    payload = _without_actuals(_verified_payload())
    payload["status"] = VerificationStatus.PURGED_BY_RETENTION
    payload["availability"] = MediaAvailability.PURGED_BY_RETENTION
    purged = ArtifactVerification(**payload)
    assert purged.expected_media_sha256 == SHA_C
    assert purged.actual_media_sha256 is None

    payload["actual_size_bytes"] = 128
    with pytest.raises(ValidationError, match="clear all actual facts"):
        ArtifactVerification(**payload)

    missing_expected = _without_actuals(_verified_payload())
    missing_expected["status"] = VerificationStatus.PURGED_BY_RETENTION
    missing_expected["availability"] = MediaAvailability.PURGED_BY_RETENTION
    missing_expected.pop("expected_media_sha256")
    with pytest.raises(ValidationError, match="Field required"):
        ArtifactVerification(**missing_expected)


@pytest.mark.parametrize(
    "status",
    [
        VerificationStatus.MISSING,
        VerificationStatus.PATH_BOUNDARY_VIOLATION,
        VerificationStatus.UNSAFE_LINK,
        VerificationStatus.NOT_REGULAR_FILE,
    ],
)
def test_unavailable_file_statuses_cannot_claim_actual_facts(
    status: VerificationStatus,
) -> None:
    payload = _without_actuals(_verified_payload())
    payload["status"] = status
    assert ArtifactVerification(**payload).status == status

    payload["actual_media_sha256"] = SHA_C
    with pytest.raises(ValidationError, match="cannot carry actual media facts"):
        ArtifactVerification(**payload)


def test_invalid_media_has_only_byte_level_actual_facts() -> None:
    payload = _without_actuals(_verified_payload())
    payload["status"] = VerificationStatus.INVALID_MEDIA
    payload["actual_media_sha256"] = SHA_C
    payload["actual_size_bytes"] = 128
    invalid = ArtifactVerification(**payload)
    assert invalid.actual_output_pixel_sha256 is None

    payload["actual_width"] = 32
    with pytest.raises(ValidationError, match="cannot claim decoded"):
        ArtifactVerification(**payload)


def test_privacy_policy_verification_requires_reason_and_complete_or_no_actuals() -> None:
    no_actuals = _without_actuals(_verified_payload())
    no_actuals["status"] = VerificationStatus.PRIVACY_POLICY_VIOLATION
    no_actuals["reason_code"] = "NONCANONICAL_MEDIA_LOCATOR"
    locator_failure = ArtifactVerification(**no_actuals)
    assert locator_failure.actual_media_sha256 is None

    full_actuals = _verified_payload()
    full_actuals["status"] = VerificationStatus.PRIVACY_POLICY_VIOLATION
    full_actuals["reason_code"] = "PRIVACY_TRANSFORM_REPLAY_MISMATCH"
    replay_failure = ArtifactVerification(**full_actuals)
    assert replay_failure.actual_media_sha256 == replay_failure.expected_media_sha256

    no_reason = dict(no_actuals)
    no_reason["reason_code"] = None
    with pytest.raises(ValidationError, match="typed reason"):
        ArtifactVerification(**no_reason)

    partial = dict(no_actuals)
    partial["actual_media_sha256"] = SHA_C
    with pytest.raises(ValidationError, match="either all or no actual"):
        ArtifactVerification(**partial)


def test_retention_hold_is_scoped_active_and_owner_typed() -> None:
    hold = RetentionHold(
        run_id=RUN_ID,
        hold_id="hold-01",
        target_ref=_scoped(_crop_ref()),
        kind=RetentionHoldKind.APPEAL,
        owner_ref=_scoped(ArtifactRef(kind=ArtifactKind.APPEAL, artifact_id="appeal-01")),
        manifest_id=SHA_C,
        policy_version="retention-v1",
    )
    assert hold.active is True

    with pytest.raises(ValidationError):
        RetentionHold.model_validate({**hold.model_dump(mode="json"), "active": False})

    cross_run = hold.model_dump(mode="json")
    cross_run["target_ref"]["run_id"] = "run-02"
    with pytest.raises(ValidationError, match="belong to the hold run"):
        RetentionHold.model_validate(cross_run)

    wrong_owner = hold.model_dump(mode="json")
    wrong_owner["owner_ref"] = _scoped(_case_ref()).model_dump(mode="json")
    with pytest.raises(ValidationError, match="retention owner"):
        RetentionHold.model_validate(wrong_owner)

    wrong_target = hold.model_dump(mode="json")
    wrong_target["target_ref"] = _scoped(_case_ref()).model_dump(mode="json")
    with pytest.raises(ValidationError, match="only crop or media"):
        RetentionHold.model_validate(wrong_target)


def test_purge_item_result_enforces_typed_state_reason_and_audit_matrix() -> None:
    purged = PurgeItemResult(
        run_id=RUN_ID,
        media_ref=_media_ref(),
        crop_refs=(_crop_ref(),),
        disposition=PurgeDisposition.PURGED,
        reason_code=PurgeReasonCode.EXPIRED_AND_PURGED,
        previous_availability=MediaAvailability.AVAILABLE,
        current_availability=MediaAvailability.PURGED_BY_RETENTION,
        audit_sequences=(4, 5),
    )
    retained = PurgeItemResult(
        run_id=RUN_ID,
        media_ref=_media_ref(),
        crop_refs=(_crop_ref(),),
        disposition=PurgeDisposition.RETAINED,
        reason_code=PurgeReasonCode.ACTIVE_RETENTION_HOLD,
        previous_availability=MediaAvailability.AVAILABLE,
        current_availability=MediaAvailability.AVAILABLE,
        hold_kinds=(RetentionHoldKind.APPEAL,),
    )
    cleanup_failed = PurgeItemResult(
        run_id=RUN_ID,
        media_ref=_media_ref(),
        crop_refs=(_crop_ref(),),
        disposition=PurgeDisposition.RECOVERY_REQUIRED,
        reason_code=PurgeReasonCode.TRASH_CLEANUP_FAILED,
        previous_availability=MediaAvailability.PURGED_BY_RETENTION,
        current_availability=MediaAvailability.PURGED_BY_RETENTION,
        audit_sequences=(4, 5),
    )

    assert purged.audit_sequences == (4, 5)
    assert retained.hold_kinds == (RetentionHoldKind.APPEAL,)
    assert cleanup_failed.reason_code == PurgeReasonCode.TRASH_CLEANUP_FAILED

    with pytest.raises(ValidationError, match="PURGING"):
        PurgeItemResult.model_validate(
            {
                **purged.model_dump(mode="json"),
                "disposition": PurgeDisposition.RECOVERY_REQUIRED,
                "reason_code": PurgeReasonCode.MEDIA_FILE_MISSING,
                "current_availability": MediaAvailability.AVAILABLE,
            }
        )
    with pytest.raises(ValidationError, match="intent audit"):
        PurgeItemResult(
            run_id=RUN_ID,
            media_ref=_media_ref(),
            crop_refs=(_crop_ref(),),
            disposition=PurgeDisposition.RECOVERY_REQUIRED,
            reason_code=PurgeReasonCode.MEDIA_FILE_MISSING,
            previous_availability=MediaAvailability.AVAILABLE,
            current_availability=MediaAvailability.PURGING,
        )
    with pytest.raises(ValidationError, match="both purge audits"):
        PurgeItemResult.model_validate(
            {
                **cleanup_failed.model_dump(mode="json"),
                "audit_sequences": [4],
            }
        )
    with pytest.raises(ValidationError, match="keep purged state"):
        PurgeItemResult.model_validate(
            {
                **cleanup_failed.model_dump(mode="json"),
                "current_availability": MediaAvailability.PURGING,
            }
        )
    with pytest.raises(ValidationError, match="hold kinds"):
        PurgeItemResult.model_validate(
            {
                **retained.model_dump(mode="json"),
                "hold_kinds": [],
            }
        )
    with pytest.raises(ValidationError, match="invalid reason, state, hold, or audit"):
        PurgeItemResult.model_validate(
            {
                **purged.model_dump(mode="json"),
                "audit_sequences": [4],
            }
        )
    with pytest.raises(ValidationError, match="invalid reason, state, hold, or audit"):
        PurgeItemResult.model_validate(
            {
                **purged.model_dump(mode="json"),
                "reason_code": PurgeReasonCode.RECOVERED_PURGE_COMPLETED,
            }
        )
    with pytest.raises(ValidationError, match="active-hold retention"):
        PurgeItemResult.model_validate(
            {
                **retained.model_dump(mode="json"),
                "audit_sequences": [1],
            }
        )
