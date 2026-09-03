"""Process isolation and bounded restart policy for live Feishu components."""

from __future__ import annotations

import os
import subprocess
from collections.abc import Callable, Sequence
from dataclasses import dataclass
from pathlib import Path
from typing import Any, BinaryIO, Protocol, cast


class M8FeishuSupervisorAlreadyRunning(RuntimeError):
    """Raised when another supervisor owns the same artifact root."""


class M8FeishuManagedProcess(Protocol):
    pid: int

    def poll(self) -> int | None: ...

    def terminate(self) -> None: ...

    def wait(self, timeout: float | None = None) -> int: ...

    def kill(self) -> None: ...


@dataclass
class _ChildState:
    process: M8FeishuManagedProcess | None = None
    failures: int = 0
    started_at: float = 0.0
    restart_at: float = 0.0


class M8FeishuLiveProcessSupervisor:
    """Own exactly one child for each live component and restart boundedly."""

    COMPONENTS = ("LONG_CONNECTION", "AUTHORITY_WORKER", "DELIVERY_WORKER")

    def __init__(
        self,
        *,
        start_process: Callable[[str], M8FeishuManagedProcess],
        monotonic: Callable[[], float],
        restart_initial_seconds: float = 0.5,
        restart_max_seconds: float = 10.0,
        stable_seconds: float = 30.0,
    ) -> None:
        if restart_initial_seconds <= 0 or restart_max_seconds < restart_initial_seconds:
            raise ValueError("Feishu supervisor restart bounds are invalid")
        self._start_process = start_process
        self._monotonic = monotonic
        self._restart_initial = restart_initial_seconds
        self._restart_max = restart_max_seconds
        self._stable_seconds = stable_seconds
        self._children = {component: _ChildState() for component in self.COMPONENTS}

    def start_all(self) -> None:
        for component in self.COMPONENTS:
            state = self._children[component]
            if state.process is None:
                self._start(component, state)

    def poll_once(self) -> None:
        now = self._monotonic()
        for component, state in self._children.items():
            process = state.process
            if process is not None:
                if process.poll() is None:
                    if now - state.started_at >= self._stable_seconds:
                        state.failures = 0
                    continue
                state.process = None
                state.failures += 1
                delay = min(
                    self._restart_initial * (2 ** (state.failures - 1)),
                    self._restart_max,
                )
                state.restart_at = now + delay
            if state.process is None and now >= state.restart_at:
                self._start(component, state)

    def shutdown(self, timeout_seconds: float = 5.0) -> None:
        running = [
            state.process
            for state in self._children.values()
            if state.process is not None and state.process.poll() is None
        ]
        for process in running:
            process.terminate()
        for process in running:
            try:
                process.wait(timeout=timeout_seconds)
            except subprocess.TimeoutExpired:
                process.kill()
                process.wait(timeout=timeout_seconds)

    def _start(self, component: str, state: _ChildState) -> None:
        state.process = self._start_process(component)
        state.started_at = self._monotonic()
        state.restart_at = state.started_at


class M8FeishuSupervisorLock:
    """A one-byte cross-process lock scoped to one artifact root."""

    def __init__(self, path: Path) -> None:
        self._path = path
        self._handle: BinaryIO | None = None

    def acquire(self) -> None:
        self._path.parent.mkdir(parents=True, exist_ok=True)
        handle = self._path.open("a+b")
        if handle.tell() == 0:
            handle.write(b"0")
            handle.flush()
        handle.seek(0)
        try:
            if os.name == "nt":
                import msvcrt

                msvcrt.locking(handle.fileno(), msvcrt.LK_NBLCK, 1)
            else:
                import fcntl

                fcntl_api = cast(Any, fcntl)
                fcntl_api.flock(handle.fileno(), fcntl_api.LOCK_EX | fcntl_api.LOCK_NB)
        except OSError as error:
            handle.close()
            raise M8FeishuSupervisorAlreadyRunning(
                "a Feishu live supervisor already owns this artifact root"
            ) from error
        self._handle = handle

    def release(self) -> None:
        handle = self._handle
        if handle is None:
            return
        handle.seek(0)
        if os.name == "nt":
            import msvcrt

            msvcrt.locking(handle.fileno(), msvcrt.LK_UNLCK, 1)
        else:
            import fcntl

            fcntl_api = cast(Any, fcntl)
            fcntl_api.flock(handle.fileno(), fcntl_api.LOCK_UN)
        handle.close()
        self._handle = None

    def __enter__(self) -> M8FeishuSupervisorLock:
        self.acquire()
        return self

    def __exit__(self, _type: object, _value: object, _traceback: object) -> None:
        self.release()


def build_feishu_component_starter(
    *,
    command_prefix: Sequence[str],
    output: Path,
    input_media: Path,
) -> Callable[[str], M8FeishuManagedProcess]:
    """Create children with isolated logs and no secret-bearing command arguments."""

    log_directory = output / "feishu-live" / "logs"
    log_directory.mkdir(parents=True, exist_ok=True)

    def start(component: str) -> M8FeishuManagedProcess:
        if component not in M8FeishuLiveProcessSupervisor.COMPONENTS:
            raise ValueError("unknown Feishu live component")
        stdout = (log_directory / f"{component.lower()}.stdout.log").open("ab")
        stderr = (log_directory / f"{component.lower()}.stderr.log").open("ab")
        arguments = [
            *command_prefix,
            "feishu",
            "live-run",
            "--component",
            component,
            "--output",
            str(output),
            "--input",
            str(input_media),
        ]
        try:
            return subprocess.Popen(
                arguments,
                stdin=subprocess.DEVNULL,
                stdout=stdout,
                stderr=stderr,
                creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0),
            )
        finally:
            stdout.close()
            stderr.close()

    return start


__all__ = [
    "M8FeishuLiveProcessSupervisor",
    "M8FeishuManagedProcess",
    "M8FeishuSupervisorAlreadyRunning",
    "M8FeishuSupervisorLock",
    "build_feishu_component_starter",
]
