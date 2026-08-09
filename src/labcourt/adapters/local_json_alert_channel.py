"""Idempotent local JSON alert channel for the bounded pilot."""

from __future__ import annotations

import os
from pathlib import Path
from uuid import uuid4

from labcourt.contracts.alert_policy import (
    AlertChannelCapabilityAuthority,
    AlertChannelIdempotencyGuarantee,
)
from labcourt.contracts.alerts import AlertDecision, DeliveryReceipt
from labcourt.contracts.canonical import canonical_json
from labcourt.contracts.cases import Case
from labcourt.contracts.enums import CaseStatus
from labcourt.contracts.frames import Sha256Hex
from labcourt.contracts.pilot_report import PilotLocalAlertDocument
from labcourt.contracts.references import require_portable_run_id
from labcourt.ports.alerts import (
    AlertChannelDeliveryCertainty,
    AlertChannelError,
    AlertChannelFailureCode,
)


class LocalJsonAlertChannel:
    """Write one immutable local JSON document per exact adjudicated alert ID."""

    def __init__(
        self,
        *,
        output_directory: str | Path,
        run_id: str,
        manifest_id: Sha256Hex,
        config_sha256: Sha256Hex,
    ) -> None:
        self._output_directory = Path(output_directory).absolute()
        self._run_id = require_portable_run_id(run_id, "local alert run_id")
        self._manifest_id = manifest_id
        self._config_sha256 = config_sha256

    def capability_authority(
        self,
        *,
        run_id: str,
        manifest_id: str,
        config_sha256: str,
    ) -> AlertChannelCapabilityAuthority:
        if (
            run_id != self._run_id
            or manifest_id != self._manifest_id
            or config_sha256 != self._config_sha256
        ):
            raise ValueError("local JSON alert capability scope does not match its run")
        return AlertChannelCapabilityAuthority(
            run_id=self._run_id,
            manifest_id=self._manifest_id,
            config_sha256=self._config_sha256,
            channel="local-json-alert-v1",
            capability_revision="local-json-alert-capability-v1",
            idempotency_guarantee=AlertChannelIdempotencyGuarantee.EXACT_ALERT_ID,
            provider_idempotency_key="alert_id",
        )

    def send(
        self,
        alert: AlertDecision,
        case: Case,
        idempotency_key: str,
    ) -> DeliveryReceipt:
        if not isinstance(alert, AlertDecision) or not isinstance(case, Case):
            raise TypeError("local JSON alert channel requires AlertDecision and Case")
        if (
            case.run_id != self._run_id
            or case.manifest_id != self._manifest_id
            or case.status != CaseStatus.CLOSED
            or case.final_decision is None
            or alert not in case.alerts
            or idempotency_key != alert.alert_id
        ):
            raise ValueError("local JSON alert channel received invalid delivery authority")

        document = PilotLocalAlertDocument(
            run_id=self._run_id,
            case_id=case.case_id,
            case_status=CaseStatus.CLOSED,
            final_decision=case.final_decision,
            alert=alert,
            idempotency_key=idempotency_key,
            manifest_id=self._manifest_id,
            config_sha256=self._config_sha256,
        )
        encoded = (canonical_json(document.model_dump(mode="json")) + "\n").encode("utf-8")
        target = self._output_directory / f"{alert.alert_id}.json"
        try:
            self._write_exact(target, encoded)
        except OSError as exc:
            if self._target_matches(target, encoded):
                return self._receipt(alert.alert_id, idempotency_key, document.document_id)
            raise AlertChannelError(
                AlertChannelFailureCode.CHANNEL_UNAVAILABLE,
                AlertChannelDeliveryCertainty.DEFINITELY_NOT_SENT,
            ) from exc
        return self._receipt(alert.alert_id, idempotency_key, document.document_id)

    @staticmethod
    def _target_matches(target: Path, encoded: bytes) -> bool:
        try:
            return target.is_file() and target.read_bytes() == encoded
        except OSError:
            return False

    def _write_exact(self, target: Path, encoded: bytes) -> None:
        self._output_directory.mkdir(parents=True, exist_ok=True)
        if target.exists():
            if not target.is_file() or target.read_bytes() != encoded:
                raise AlertChannelError(
                    AlertChannelFailureCode.REQUEST_REJECTED_BEFORE_SEND,
                    AlertChannelDeliveryCertainty.DEFINITELY_NOT_SENT,
                )
            return
        temporary = target.with_name(f".{target.name}.{uuid4().hex}.tmp")
        try:
            with temporary.open("xb") as stream:
                stream.write(encoded)
                stream.flush()
                os.fsync(stream.fileno())
            os.replace(temporary, target)
        finally:
            temporary.unlink(missing_ok=True)

    @staticmethod
    def _receipt(
        alert_id: str,
        idempotency_key: str,
        document_id: str,
    ) -> DeliveryReceipt:
        return DeliveryReceipt(
            alert_id=alert_id,
            channel="local-json-alert-v1",
            idempotency_key=idempotency_key,
            accepted=True,
            provider_receipt_ref=document_id,
        )


__all__ = ["LocalJsonAlertChannel"]
