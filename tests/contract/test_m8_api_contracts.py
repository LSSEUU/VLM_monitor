from __future__ import annotations

import hashlib

import pytest
from jsonschema import Draft202012Validator
from pydantic import BaseModel, ValidationError

from labcourt.contracts.m8_access_cases import (
    M8AuthorityReference,
    M8AuthorityReferenceKind,
    M8OperationalCaseAction,
    M8OperationalCaseReasonCode,
    M8OperationalCaseStatus,
)
from labcourt.contracts.m8_api import (
    M8ApiCaseTransitionRequestV1,
    M8ApiCredentialAuthorityV1,
    M8ApiCredentialCatalogAuthorityV1,
    M8ApiErrorResponseV1,
    M8ApiPrincipalV1,
)

SHA_A = "a" * 64
SHA_B = "b" * 64
SHA_C = "c" * 64


def _credential(
    credential_id: str = "credential-safety-01",
    actor_id: str = "safety-officer-01",
    token: bytes = b"labcourt-test-credential-safety-01",
) -> M8ApiCredentialAuthorityV1:
    return M8ApiCredentialAuthorityV1(
        credential_id=credential_id,
        actor_id=actor_id,
        bearer_token_sha256=hashlib.sha256(token).hexdigest(),
        active=True,
        manifest_id=SHA_A,
    )


def _catalog() -> M8ApiCredentialCatalogAuthorityV1:
    return M8ApiCredentialCatalogAuthorityV1(
        revision=1,
        credentials=(_credential(),),
        authentication_manifest_id=SHA_B,
    )


def _transition_request() -> M8ApiCaseTransitionRequestV1:
    return M8ApiCaseTransitionRequestV1(
        source_case_version=1,
        source_case_authority_sha256=SHA_A,
        source_status=M8OperationalCaseStatus.PENDING_VERIFICATION,
        case_location_id="room-chem-301",
        subject_actor_id="student-01",
        action=M8OperationalCaseAction.CONFIRM,
        reason_code=M8OperationalCaseReasonCode.VERIFIED_VIOLATION,
        reason_summary="安全负责人已核实现场说明。",
        supporting_authorities=(
            M8AuthorityReference(
                kind=M8AuthorityReferenceKind.USER_STATEMENT,
                authority_id="statement-01",
                document_sha256=SHA_C,
            ),
        ),
        explicit_human_confirmation=True,
        command_manifest_id=SHA_B,
    )


def test_credential_maps_only_actor_id_and_derives_content_identity() -> None:
    credential = _credential()
    assert "role" not in credential.model_dump(mode="json")
    assert "capabilities" not in credential.model_dump(mode="json")
    assert len(credential.credential_authority_id) == 64

    forged = credential.model_dump(mode="json")
    forged["credential_authority_id"] = "0" * 64
    with pytest.raises(ValidationError, match="credential_authority_id"):
        M8ApiCredentialAuthorityV1.model_validate(forged)


def test_credential_catalog_is_complete_stable_and_rejects_token_hash_aliases() -> None:
    catalog = _catalog()
    assert len(catalog.credential_inventory_sha256) == 64
    assert len(catalog.credential_catalog_id) == 64

    duplicate_hash = _credential(credential_id="credential-safety-02")
    with pytest.raises(ValidationError, match="token hashes"):
        catalog.model_copy(update={"credentials": (catalog.credentials[0], duplicate_hash)})
    with pytest.raises(ValidationError, match="stable"):
        catalog.model_copy(
            update={
                "credentials": (
                    _credential("credential-z", "actor-z", b"token-z"),
                    _credential("credential-a", "actor-a", b"token-a"),
                )
            }
        )


def test_principal_contains_no_role_and_binds_exact_credential_catalog() -> None:
    credential = _credential()
    catalog = _catalog()
    principal = M8ApiPrincipalV1(
        actor_id=credential.actor_id,
        credential_id=credential.credential_id,
        credential_authority_id=credential.credential_authority_id,
        credential_catalog_id=catalog.credential_catalog_id,
        authentication_manifest_id=catalog.authentication_manifest_id,
    )
    assert "role" not in principal.model_dump(mode="json")
    assert "capabilities" not in principal.model_dump(mode="json")
    assert len(principal.authentication_context_id) == 64


def test_transition_request_excludes_actor_authority_and_forbids_implicit_confirmation() -> None:
    request = _transition_request()
    payload = request.model_dump(mode="json")
    assert "actor_authority" not in payload
    assert "role" not in payload
    assert request.direct_disciplinary_action_permitted is False

    payload["actor_authority"] = {"role": "SAFETY_OFFICER"}
    with pytest.raises(ValidationError, match="Extra inputs"):
        M8ApiCaseTransitionRequestV1.model_validate(payload)
    with pytest.raises(ValidationError, match="explicit human confirmation"):
        request.model_copy(update={"explicit_human_confirmation": False})


def test_transition_request_rejects_unstable_authorities_and_appeal_graft() -> None:
    request = _transition_request()
    second = M8AuthorityReference(
        kind=M8AuthorityReferenceKind.EVIDENCE_PACK,
        authority_id="evidence-01",
        document_sha256=SHA_B,
    )
    with pytest.raises(ValidationError, match="unique and stable"):
        request.model_copy(
            update={"supporting_authorities": (request.supporting_authorities[0], second)}
        )
    with pytest.raises(ValidationError, match="only valid"):
        request.model_copy(update={"appeal_resolution": "UPHELD"})


@pytest.mark.parametrize(
    "model",
    (_catalog(), _transition_request()),
)
def test_m8_api_contracts_validate_as_serialization_schemas(model: BaseModel) -> None:
    schema = type(model).model_json_schema(mode="serialization")
    Draft202012Validator(schema).validate(model.model_dump(mode="json"))


def test_m8_api_schemas_are_registered_serialization_roots() -> None:
    from labcourt.schema_registry import SCHEMA_MODELS, SCHEMA_VALIDATION_MODELS

    expected = {
        "m8-api-case-transition-request-v1": M8ApiCaseTransitionRequestV1,
        "m8-api-credential-authority-v1": M8ApiCredentialAuthorityV1,
        "m8-api-credential-catalog-authority-v1": M8ApiCredentialCatalogAuthorityV1,
        "m8-api-error-response-v1": M8ApiErrorResponseV1,
        "m8-api-principal-v1": M8ApiPrincipalV1,
    }
    assert {name: SCHEMA_MODELS[name] for name in expected} == expected
    assert expected.keys().isdisjoint(SCHEMA_VALIDATION_MODELS)
