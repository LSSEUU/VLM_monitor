"""Trusted configuration authority for M5 precedent policy decisions."""

from __future__ import annotations

from typing import Protocol

from labcourt.contracts.enums import RunMode
from labcourt.contracts.m5_precedents import M5PrecedentPolicy
from labcourt.contracts.manifests import RunManifest


class M5PrecedentPolicyVerifier(Protocol):
    """Derive the only accepted precedent policy from trusted application config."""

    @property
    def run_mode(self) -> RunMode: ...

    def expected_policy(self, manifest: RunManifest) -> M5PrecedentPolicy: ...


__all__ = ["M5PrecedentPolicyVerifier"]
