"""Append-only M4 cache adapter with physical raw-response revalidation."""

from __future__ import annotations

from dataclasses import dataclass
from threading import RLock
from typing import NoReturn

from pydantic import ValidationError

from labcourt.adapters.storage._hearing_response_journal import (
    hearing_response_matches_request,
    require_hearing_request,
    require_hearing_response,
)
from labcourt.contracts.hearing import (
    HearingModelCacheEntry,
    HearingModelRequest,
    HearingModelResponse,
)
from labcourt.contracts.references import require_reference_token
from labcourt.ports.hearing_vlm import (
    HearingModelResponseStoreError,
    HearingModelResponseStoreFailureCode,
    HearingRawModelResponseVerifier,
)


@dataclass(frozen=True, slots=True)
class _CachedHearingBinding:
    entry: HearingModelCacheEntry
    response: HearingModelResponse


class ImmutableHearingVLMResponseCache:
    """Bind each run/cache key once and reverify every observed cache hit.

    Durable implementations may persist the same contract in SQLite.  This
    adapter is intentionally small and useful for the offline/default path: it
    never treats a known entry with missing or changed raw bytes as a cache
    miss, and it offers no mutation or eviction capability.
    """

    __slots__ = ("_bindings", "_lock", "_response_verifier")

    def __init__(self, response_verifier: HearingRawModelResponseVerifier) -> None:
        verify = getattr(response_verifier, "verify_raw_response", None)
        if not callable(verify):
            raise TypeError("response_verifier must verify raw hearing responses")
        self._response_verifier = response_verifier
        self._bindings: dict[tuple[str, str], _CachedHearingBinding] = {}
        self._lock = RLock()

    def __repr__(self) -> str:
        with self._lock:
            count = len(self._bindings)
        return f"ImmutableHearingVLMResponseCache(entry_count={count})"

    def get(
        self,
        run_id: str,
        request: HearingModelRequest,
    ) -> HearingModelCacheEntry | None:
        """Return a verified immutable entry or a genuine never-seen miss."""

        cached = self._get_verified_binding(run_id, request)
        return cached.entry if cached is not None else None

    def get_response(
        self,
        run_id: str,
        request: HearingModelRequest,
    ) -> HearingModelResponse | None:
        """Return the exact physically reverified response behind a cache hit."""

        cached = self._get_verified_binding(run_id, request)
        return cached.response if cached is not None else None

    def put(
        self,
        run_id: str,
        request: HearingModelRequest,
        response: HearingModelResponse,
    ) -> HearingModelCacheEntry:
        """Publish one immutable binding; exact retries are idempotent."""

        request = require_hearing_request(request)
        response = require_hearing_response(response)
        controlled_run_id = self._require_run_scope(run_id, request)
        self._verify_physical(controlled_run_id, request, response)
        candidate = _CachedHearingBinding(
            entry=self._build_entry(request, response),
            response=response,
        )
        key = (controlled_run_id, request.cache_key)
        with self._lock:
            existing = self._bindings.get(key)
            if existing is None:
                self._bindings[key] = candidate
                return candidate.entry
            if existing != candidate:
                self._raise(HearingModelResponseStoreFailureCode.CACHE_CONFLICT)
            return existing.entry

    def verify_hit(
        self,
        run_id: str,
        request: HearingModelRequest,
        entry: HearingModelCacheEntry,
        response: HearingModelResponse,
    ) -> HearingModelCacheEntry:
        """Verify a durable repository hit without trusting either SQL document.

        This stateless surface lets the SQLite-backed cache retain authority for
        persistence while reusing the exact same binding and physical-byte gate
        as the offline append-only adapter.
        """

        request = require_hearing_request(request)
        response = require_hearing_response(response)
        controlled_run_id = self._require_run_scope(run_id, request)
        try:
            checked_entry = self._require_entry(entry)
            expected = self._build_entry(request, response)
            if checked_entry != expected or not hearing_response_matches_request(
                request,
                response,
            ):
                self._raise(HearingModelResponseStoreFailureCode.CACHE_INTEGRITY_FAILURE)
            self._verify_physical(controlled_run_id, request, response)
            return checked_entry
        except HearingModelResponseStoreError:
            raise
        except Exception:
            self._raise(HearingModelResponseStoreFailureCode.CACHE_INTEGRITY_FAILURE)

    def _get_verified_binding(
        self,
        run_id: str,
        request: HearingModelRequest,
    ) -> _CachedHearingBinding | None:
        request = require_hearing_request(request)
        controlled_run_id = self._require_run_scope(run_id, request)
        key = (controlled_run_id, request.cache_key)
        with self._lock:
            cached = self._bindings.get(key)
        if cached is None:
            return None
        entry = self.verify_hit(
            controlled_run_id,
            request,
            cached.entry,
            cached.response,
        )
        return _CachedHearingBinding(entry=entry, response=cached.response)

    def _verify_physical(
        self,
        run_id: str,
        request: HearingModelRequest,
        response: HearingModelResponse,
    ) -> None:
        try:
            verified = self._response_verifier.verify_raw_response(
                run_id,
                request,
                response,
            )
        except HearingModelResponseStoreError:
            raise
        except Exception:
            self._raise(HearingModelResponseStoreFailureCode.CACHE_INTEGRITY_FAILURE)
        if type(verified) is not HearingModelResponse or verified != response:
            self._raise(HearingModelResponseStoreFailureCode.CACHE_INTEGRITY_FAILURE)

    @staticmethod
    def _build_entry(
        request: HearingModelRequest,
        response: HearingModelResponse,
    ) -> HearingModelCacheEntry:
        if not hearing_response_matches_request(request, response):
            ImmutableHearingVLMResponseCache._raise(
                HearingModelResponseStoreFailureCode.CACHE_INTEGRITY_FAILURE
            )
        try:
            return HearingModelCacheEntry(
                run_id=request.run_id,
                case_id=request.case_id,
                hearing_session_id=request.hearing_session_id,
                round_index=request.round_index,
                role=request.role,
                current_evidence_pack_id=request.current_evidence_pack_id,
                current_evidence_pack_version=request.current_evidence_pack_version,
                cache_key=request.cache_key,
                request_id=request.request_id,
                request_sha256=request.request_sha256,
                response_id=response.response_id,
                response_content_sha256=response.content_sha256,
                model_manifest_id=request.model_manifest_id,
                prompt_manifest_id=request.prompt_manifest.prompt_manifest_id,
                output_schema_sha256=request.prompt_manifest.output_schema_sha256,
                manifest_id=request.manifest_id,
            )
        except (TypeError, ValueError, ValidationError):
            ImmutableHearingVLMResponseCache._raise(
                HearingModelResponseStoreFailureCode.CACHE_INTEGRITY_FAILURE
            )

    @staticmethod
    def _require_entry(entry: object) -> HearingModelCacheEntry:
        if type(entry) is not HearingModelCacheEntry:
            ImmutableHearingVLMResponseCache._raise(
                HearingModelResponseStoreFailureCode.CACHE_INTEGRITY_FAILURE
            )
        typed_entry = entry
        try:
            validated = HearingModelCacheEntry.model_validate(typed_entry.model_dump(mode="json"))
        except (TypeError, ValueError, ValidationError):
            ImmutableHearingVLMResponseCache._raise(
                HearingModelResponseStoreFailureCode.CACHE_INTEGRITY_FAILURE
            )
        if validated != typed_entry:
            ImmutableHearingVLMResponseCache._raise(
                HearingModelResponseStoreFailureCode.CACHE_INTEGRITY_FAILURE
            )
        return validated

    @staticmethod
    def _require_run_scope(run_id: str, request: HearingModelRequest) -> str:
        try:
            controlled = require_reference_token(run_id, "hearing cache run_id")
        except (TypeError, ValueError):
            ImmutableHearingVLMResponseCache._raise(
                HearingModelResponseStoreFailureCode.INVALID_ARGUMENT
            )
        if controlled != request.run_id:
            ImmutableHearingVLMResponseCache._raise(
                HearingModelResponseStoreFailureCode.RUN_SCOPE_MISMATCH
            )
        return controlled

    @staticmethod
    def _raise(reason: HearingModelResponseStoreFailureCode) -> NoReturn:
        raise HearingModelResponseStoreError(reason)


__all__ = ["ImmutableHearingVLMResponseCache"]
