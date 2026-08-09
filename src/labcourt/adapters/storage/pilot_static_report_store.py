"""Atomic last-index publication store for A4 offline operator reports."""

from __future__ import annotations

import os
from pathlib import Path
from uuid import uuid4

from labcourt.application.pilot_operator_report import render_pilot_case, render_pilot_index
from labcourt.contracts.canonical import canonical_json
from labcourt.contracts.pilot_report import PilotA4Metrics
from labcourt.exceptions import PathBoundaryViolation


class PilotStaticReportStore:
    """Publish case pages and metrics before atomically replacing the index completion marker."""

    def __init__(self, *, run_root: str | Path, run_id: str) -> None:
        self._run_root = Path(run_root).absolute()
        if self._run_root.name != run_id:
            raise PathBoundaryViolation("pilot report root does not match the selected run")
        self._report_root = self._run_root / "report"

    def publish(self, metrics: PilotA4Metrics) -> None:
        if metrics.run_id != self._run_root.name:
            raise PathBoundaryViolation("pilot metrics belong to another report root")
        cases_root = self._report_root / "cases"
        cases_root.mkdir(parents=True, exist_ok=True)
        for case in metrics.cases:
            self._atomic_write_text(
                cases_root / f"{case.case_id}.html",
                render_pilot_case(case),
            )
        self._atomic_write_text(
            self._run_root / "metrics.json",
            canonical_json(metrics.model_dump(mode="json")) + "\n",
        )
        self._atomic_write_text(
            self._report_root / "index.html",
            render_pilot_index(metrics),
        )

    @staticmethod
    def _atomic_write_text(target: Path, content: str) -> None:
        encoded = content.encode("utf-8")
        target.parent.mkdir(parents=True, exist_ok=True)
        temporary = target.with_name(f".{target.name}.{uuid4().hex}.tmp")
        try:
            with temporary.open("xb") as stream:
                stream.write(encoded)
                stream.flush()
                os.fsync(stream.fileno())
            os.replace(temporary, target)
        finally:
            temporary.unlink(missing_ok=True)


__all__ = ["PilotStaticReportStore"]
