"""Adapter from current role-scoped Case authority to a non-rule memory partition."""

from __future__ import annotations

from labcourt.contracts.m8_access_cases import M8OperationalCaseStatus
from labcourt.contracts.m8_api import M8ApiPrincipalV1
from labcourt.contracts.m8_knowledge_projection import (
    M8CaseMemoryAvailability,
    M8CaseMemoryEntryV1,
    M8CaseMemoryProjectionV1,
)
from labcourt.services.m8_operations_api import M8OperationsApiService

_TERMINAL_CASE_STATUSES = frozenset(
    {
        M8OperationalCaseStatus.REJECTED,
        M8OperationalCaseStatus.RESOLVED,
        M8OperationalCaseStatus.APPEAL_RESOLVED,
    }
)


class M8ScopedOperationalCaseMemoryAdapter:
    """Use only persisted, already role-scoped terminal Case receipts as memory."""

    def __init__(self, operations_api: M8OperationsApiService) -> None:
        if not isinstance(operations_api, M8OperationsApiService):
            raise TypeError("M8 Case-memory adapter requires the existing operations API")
        self._operations = operations_api

    def query(
        self,
        principal: M8ApiPrincipalV1,
        normalized_query: str,
        limit: int,
    ) -> M8CaseMemoryProjectionV1:
        if not isinstance(normalized_query, str) or not normalized_query:
            raise ValueError("M8 Case-memory query must be normalized visible text")
        if not isinstance(limit, int) or isinstance(limit, bool) or not 1 <= limit <= 8:
            raise ValueError("M8 Case-memory limit is outside the bounded projection")
        visible = self._operations.cases(principal)
        if not visible:
            return M8CaseMemoryProjectionV1(
                availability=M8CaseMemoryAvailability.NO_PLATFORM_AUTHORITY
            )
        terminal = tuple(item for item in visible if item.status in _TERMINAL_CASE_STATUSES)
        if not terminal:
            return M8CaseMemoryProjectionV1(availability=M8CaseMemoryAvailability.NO_MATCH)
        entries: list[M8CaseMemoryEntryV1] = []
        for receipt in terminal[:limit]:
            authority = receipt.audit_event.case_authority
            transition = receipt.audit_event.transition_intent
            reason = transition.command.reason_code.value if transition is not None else "CREATED"
            entries.append(
                M8CaseMemoryEntryV1(
                    case_id=receipt.case_id,
                    case_version=receipt.case_version,
                    status=receipt.status,
                    risk_level=authority.risk_level,
                    location_id=authority.location_id,
                    case_authority_id=receipt.case_authority_id,
                    case_document_sha256=receipt.case_document_sha256,
                    audit_event_id=receipt.audit_event_id,
                    summary=(
                        f"历史案件 {receipt.case_id[:12]} · {authority.risk_level.value} · "
                        f"{receipt.status.value} · {reason}"
                    ),
                )
            )
        return M8CaseMemoryProjectionV1(
            availability=M8CaseMemoryAvailability.AVAILABLE,
            entries=tuple(entries),
        )


__all__ = ["M8ScopedOperationalCaseMemoryAdapter"]
