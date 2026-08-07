"""Typed failure categories translated by orchestration and CLI boundaries."""

from pathlib import PurePosixPath

from labcourt.contracts.enums import ClosureDefectCode


class LabCourtError(Exception):
    """Base class for expected application failures."""


class ContractViolation(LabCourtError):
    """Input violates a public contract or configuration invariant."""


class ProviderUnavailable(LabCourtError):
    """A required external capability is unavailable."""


class PerceptionWorkerError(ProviderUnavailable):
    """Base for sanitized isolated-perception worker failures."""


class PerceptionWorkerTimeout(PerceptionWorkerError):
    """The bounded startup or frame inference deadline expired."""


class PerceptionWorkerCrashed(PerceptionWorkerError):
    """The worker exited or closed its protocol stream unexpectedly."""


class PerceptionWorkerProtocolViolation(PerceptionWorkerError):
    """The worker emitted malformed, oversized, or unexpected protocol data."""


class PerceptionWorkerRejected(PerceptionWorkerError):
    """The worker returned an explicit sanitized failure response."""


class ModelOutputInvalid(LabCourtError):
    """A model response cannot be validated against its output contract."""


class EvidenceMissing(LabCourtError):
    """Evidence required for adjudication is absent or unverifiable."""


class CreationClosureFailed(EvidenceMissing):
    """Creation-time closure failed with controlled, machine-readable defects."""

    def __init__(self, defect_codes: tuple[ClosureDefectCode, ...]) -> None:
        if not defect_codes:
            raise ValueError("creation closure failure requires at least one defect code")
        if any(not isinstance(code, ClosureDefectCode) for code in defect_codes):
            raise TypeError("creation closure defect_codes must contain ClosureDefectCode values")
        self.defect_codes = tuple(sorted(set(defect_codes), key=lambda code: code.value))
        codes = ", ".join(code.value for code in self.defect_codes)
        super().__init__(f"creation closure failed: {codes}")


class PrivacyPolicyViolation(LabCourtError):
    """A media operation would violate the selected privacy policy."""


class BudgetExceeded(LabCourtError):
    """A case exceeded its bounded model or acquisition budget."""


class ProceduralReviewFailed(LabCourtError):
    """A verdict failed deterministic procedural review."""


class ConcurrentModification(LabCourtError):
    """An optimistic concurrency precondition no longer holds."""


class ManifestMismatch(LabCourtError):
    """An artifact does not match the pinned run manifest."""


class PerceptionFrameIdentityMismatch(ManifestMismatch):
    """A worker result does not belong to the exact requested frame pixels."""


def _controlled_relative_reference(value: str | None) -> str | None:
    """Keep host paths out of expected-failure text even if a caller makes a mistake."""

    if value is None or not value or "\\" in value or ":" in value:
        return None
    path = PurePosixPath(value)
    if path.is_absolute() or ".." in path.parts or path.as_posix() != value:
        return None
    return value


class SecureWorkspaceError(LabCourtError):
    """Base for failures produced by the handle-anchored workspace adapter."""

    def __init__(self, reason_code: str, relative_path: str | None = None) -> None:
        self.reason_code = reason_code
        self.relative_path = _controlled_relative_reference(relative_path)
        suffix = f" [{self.relative_path}]" if self.relative_path is not None else ""
        super().__init__(f"secure workspace failure: {reason_code}{suffix}")


class PathBoundaryViolation(SecureWorkspaceError):
    """A path or opened filesystem object cannot be proven safe and contained."""


class ArtifactIntegrityViolation(SecureWorkspaceError):
    """Artifact bytes do not match their required immutable identity."""


class ArtifactConflict(SecureWorkspaceError):
    """A create/publish destination exists with incompatible content."""
