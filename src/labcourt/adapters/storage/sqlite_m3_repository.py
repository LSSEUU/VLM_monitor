"""Public façade for transactional M3 SQLite persistence.

Implementation responsibilities live in focused internal modules while this
module preserves the original import path and fault-injection limit knobs.
"""

from labcourt.contracts.model_response_recovery import (
    MAX_MODEL_CALL_RECOVERY_ITEMS as MAX_MODEL_CALL_RECOVERY_ITEMS,
)
from labcourt.ports.screening_repository import M3CaseCommit

from .sqlite_m3_repository_backlog import SQLiteM3BacklogRepository
from .sqlite_m3_repository_decisions import SQLiteM3DecisionRepository
from .sqlite_m3_repository_foundation import SQLiteM3RepositoryFoundation
from .sqlite_m3_repository_model import SQLiteM3ModelRepository
from .sqlite_m3_repository_support import (
    _MODEL_CALL_RECOVERY_SCAN_PAGE_SIZE as _MODEL_CALL_RECOVERY_SCAN_PAGE_SIZE,
)
from .sqlite_m3_repository_support import (
    CurrentPackVerifier as CurrentPackVerifier,
)
from .sqlite_m3_repository_support import (
    m3_root_document_sha256,
)


class SQLiteM3Repository(
    SQLiteM3RepositoryFoundation,
    SQLiteM3ModelRepository,
    SQLiteM3DecisionRepository,
    SQLiteM3BacklogRepository,
):
    """Run-scoped M3 response, decision, and durable backlog repository.

    ``complete_model_call`` is the only T1 write boundary. Aggregate commits,
    including leased backlog outcomes, are T2 boundaries guarded by the Case
    revision, audit head, and freshly verified current-pack closure.
    """


__all__ = ["M3CaseCommit", "SQLiteM3Repository", "m3_root_document_sha256"]
