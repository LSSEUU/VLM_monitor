"""Composition services that assemble replaceable LabCourt adapters."""

from labcourt.services.m3 import build_screening_prompt_catalog
from labcourt.services.m3_operations import (
    M3OperationsBoundaryCode,
    M3OperationsBoundaryError,
    M3OperationsService,
    open_m3_operations_service,
)
from labcourt.services.m4_maintenance_recovery import (
    build_m4_hearing_model_response_recovery,
)
from labcourt.services.m4_operations import (
    M4BacklogWorker,
    M4OperationsBoundaryCode,
    M4OperationsBoundaryError,
    M4OperationsService,
    build_hearing_prompt_catalog,
    open_m4_operations_service,
)
from labcourt.services.maintenance_recovery import build_maintenance_recovery_coordinator

__all__ = [
    "M3OperationsBoundaryCode",
    "M3OperationsBoundaryError",
    "M3OperationsService",
    "M4BacklogWorker",
    "M4OperationsBoundaryCode",
    "M4OperationsBoundaryError",
    "M4OperationsService",
    "build_hearing_prompt_catalog",
    "build_m4_hearing_model_response_recovery",
    "build_maintenance_recovery_coordinator",
    "build_screening_prompt_catalog",
    "open_m3_operations_service",
    "open_m4_operations_service",
]
