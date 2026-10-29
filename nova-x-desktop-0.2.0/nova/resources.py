"""§110 Performance profiling and resource adaptation.

Tuned for the stated target: a dual-core machine with roughly 10 GB of RAM.

Everything here reads the operating system rather than guessing. When a metric
cannot be read, the sample says so in ``limitations`` and the affected decision
falls back to the conservative setting - it never assumes headroom that was not
measured.

One rule is absolute: NOVA reduces *its own* activity under pressure. It never
kills, renices or otherwise interferes with a process it did not start. If
pressure requires a decision that could affect other work, the least disruptive
option consistent with policy is chosen and the reason is recorded.
"""
from __future__ import annotations

import os
import shutil
from dataclasses import dataclass, field
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

PRESSURE_NORMAL = "normal"
PRESSURE_ELEVATED = "elevated"
PRESSURE_HIGH = "high"
PRESSURE_CRITICAL = "critical"
PRESSURE_LEVELS = (PRESSURE_NORMAL, PRESSURE_ELEVATED, PRESSURE_HIGH, PRESSURE_CRITICAL)
PRESSURE_RANK = {name: index for index, name in enumerate(PRESSURE_LEVELS)}

SOURCE_PROC = "proc"
SOURCE_FALLBACK = "fallback"
SOURCE_UNAVAILABLE = "unavailable"

# Thresholds are ratios, not absolutes, so the same policy works on a 4 GB and a
# 16 GB machine. Absolute floors protect small disks from ratio-only reasoning.
MEMORY_AVAILABLE_RATIO_ELEVATED = 0.35
MEMORY_AVAILABLE_RATIO_HIGH = 0.20
MEMORY_AVAILABLE_RATIO_CRITICAL = 0.10
LOAD_PER_CPU_ELEVATED = 1.0
LOAD_PER_CPU_HIGH = 2.0
LOAD_PER_CPU_CRITICAL = 4.0
DISK_FREE_BYTES_ELEVATED = 5 * 1024**3
DISK_FREE_BYTES_HIGH = 2 * 1024**3
DISK_FREE_BYTES_CRITICAL = 512 * 1024**2
DISK_FREE_RATIO_CRITICAL = 0.02

HISTORY_LIMIT = 200


def _now() -> datetime:
    return datetime.now(UTC)


@dataclass(frozen=True)
class ResourceSample:
    """One measurement of the machine, with its own limits stated."""

    collected_at: str
    source: str
    cpu_count: int = 0
    load_1m: float = 0.0
    load_5m: float = 0.0
    load_15m: float = 0.0
    load_per_cpu: float = 0.0
    cpu_busy_ratio: float | None = None
    memory_total_mb: int = 0
    memory_available_mb: int = 0
    memory_available_ratio: float | None = None
    disk_total_mb: int = 0
    disk_free_mb: int = 0
    disk_free_bytes: int = 0
    process_count: int = 0
    limitations: tuple[str, ...] = ()

    def to_dict(self) -> dict[str, Any]:
        return {
            "collected_at": self.collected_at,
            "source": self.source,
            "cpu_count": self.cpu_count,
            "load_1m": self.load_1m,
            "load_5m": self.load_5m,
            "load_15m": self.load_15m,
            "load_per_cpu": self.load_per_cpu,
            "cpu_busy_ratio": self.cpu_busy_ratio,
            "memory_total_mb": self.memory_total_mb,
            "memory_available_mb": self.memory_available_mb,
            "memory_available_ratio": self.memory_available_ratio,
            "disk_total_mb": self.disk_total_mb,
            "disk_free_mb": self.disk_free_mb,
            "process_count": self.process_count,
            "limitations": list(self.limitations),
        }


@dataclass(frozen=True)
class ResourceBudget:
    """The concrete decisions taken in response to a sample."""

    decided_at: str
    pressure: str
    reasons: tuple[str, ...]
    max_parallel_tasks: int = 1
    max_model_concurrency: int = 1
    max_background_workers: int = 1
    indexing_enabled: bool = True
    index_chunk_bytes: int = 64 * 1024
    terminal_capture_chars: int = 12_000
    reduce_visual_effects: bool = False
    defer_optional_work: bool = False
    allow_local_model_start: bool = False
    max_concurrent_sandboxed_processes: int = 1
    duplicate_request_suppression: bool = True
    cache_reuse: bool = True
    warnings: tuple[str, ...] = ()
    sample: ResourceSample | None = None

    def to_dict(self) -> dict[str, Any]:
        result = {
            "decided_at": self.decided_at,
            "pressure": self.pressure,
            "reasons": list(self.reasons),
            "max_parallel_tasks": self.max_parallel_tasks,
            "max_model_concurrency": self.max_model_concurrency,
            "max_background_workers": self.max_background_workers,
            "indexing_enabled": self.indexing_enabled,
            "index_chunk_bytes": self.index_chunk_bytes,
            "terminal_capture_chars": self.terminal_capture_chars,
            "reduce_visual_effects": self.reduce_visual_effects,
            "defer_optional_work": self.defer_optional_work,
            "allow_local_model_start": self.allow_local_model_start,
            "max_concurrent_sandboxed_processes": self.max_concurrent_sandboxed_processes,
            "duplicate_request_suppression": self.duplicate_request_suppression,
            "cache_reuse": self.cache_reuse,
            "warnings": list(self.warnings),
        }
        if self.sample is not None:
            result["sample"] = self.sample.to_dict()
        return result


@dataclass(frozen=True)
class Thresholds:
    memory_available_ratio_elevated: float = MEMORY_AVAILABLE_RATIO_ELEVATED
    memory_available_ratio_high: float = MEMORY_AVAILABLE_RATIO_HIGH
    memory_available_ratio_critical: float = MEMORY_AVAILABLE_RATIO_CRITICAL
    load_per_cpu_elevated: float = LOAD_PER_CPU_ELEVATED
    load_per_cpu_high: float = LOAD_PER_CPU_HIGH
    load_per_cpu_critical: float = LOAD_PER_CPU_CRITICAL
    disk_free_bytes_elevated: int = DISK_FREE_BYTES_ELEVATED
    disk_free_bytes_high: int = DISK_FREE_BYTES_HIGH
    disk_free_bytes_critical: int = DISK_FREE_BYTES_CRITICAL


def _read_proc_stat() -> dict[str, int]:
    path = Path("/proc/stat")
    if not path.is_file():
        return {}
    try:
        line = path.read_text(encoding="utf-8", errors="replace").splitlines()[0]
    except OSError:
        return {}
    if not line.startswith("cpu "):
        return {}
    parts = line.split()[1:]
    names = ("user", "nice", "system", "idle", "iowait", "irq", "softirq", "steal")
    values: dict[str, int] = {}
    for index, name in enumerate(names):
        if index >= len(parts):
            break
        try:
            values[name] = int(parts[index])
        except ValueError:
            values[name] = 0
    return values


def _read_meminfo() -> tuple[int, int]:
    """Total and available memory in kilobytes; (0, 0) when unreadable."""
    path = Path("/proc/meminfo")
    if not path.is_file():
        return 0, 0
    total = available = 0
    try:
        for line in path.read_text(encoding="utf-8", errors="replace").splitlines():
            key, _, rest = line.partition(":")
            value = rest.strip().split()
            if not value:
                continue
            try:
                number = int(value[0])
            except ValueError:
                continue
            if key == "MemTotal":
                total = number
            elif key == "MemAvailable":
                available = number
    except OSError:
        return 0, 0
    if available == 0 and total:
        # MemAvailable is absent on very old kernels; MemFree understates what is
        # usable, so say so rather than reporting a falsely critical machine.
        return total, -1
    return total, available


def _read_loadavg() -> tuple[float, float, float]:
    path = Path("/proc/loadavg")
    if not path.is_file():
        return 0.0, 0.0, 0.0
    try:
        parts = path.read_text(encoding="utf-8", errors="replace").split()
        return float(parts[0]), float(parts[1]), float(parts[2])
    except (OSError, IndexError, ValueError):
        try:
            return tuple(round(value, 2) for value in os.getloadavg())  # type: ignore[return-value]
        except (OSError, AttributeError):
            return 0.0, 0.0, 0.0


def _count_processes() -> int:
    proc = Path("/proc")
    if not proc.is_dir():
        return 0
    try:
        return sum(1 for entry in proc.iterdir() if entry.is_dir() and entry.name.isdigit())
    except OSError:
        return 0


@dataclass
class ResourceManager:
    """Measures pressure and decides how much NOVA is allowed to do."""

    thresholds: Thresholds = field(default_factory=Thresholds)
    disk_path: str = "."
    low_resource_mode: bool = True
    baseline_parallel_tasks: int = 1
    baseline_model_concurrency: int = 2
    baseline_background_workers: int = 2
    history_limit: int = HISTORY_LIMIT
    _previous_cpu: dict[str, int] = field(default_factory=dict, init=False)
    _history: list[ResourceSample] = field(default_factory=list, init=False)
    _decisions: list[ResourceBudget] = field(default_factory=list, init=False)
    _read_failures: int = field(default=0, init=False)

    # -- measurement

    def sample(self) -> ResourceSample:
        limitations: list[str] = []
        source = SOURCE_PROC

        try:
            cpu_count = os.cpu_count() or 0
        except (OSError, ValueError):
            cpu_count = 0
        if cpu_count <= 0:
            cpu_count = 1
            limitations.append("CPU count could not be read; assumed 1 so load ratios stay conservative")

        load_1m, load_5m, load_15m = _read_loadavg()
        if load_1m == 0.0 and load_5m == 0.0 and load_15m == 0.0:
            limitations.append("load average is unavailable; CPU pressure is judged from /proc/stat deltas only")

        total_kb, available_kb = _read_meminfo()
        memory_total_mb = total_kb // 1024
        memory_available_mb = max(0, available_kb) // 1024
        memory_ratio: float | None = None
        if total_kb > 0 and available_kb >= 0:
            memory_ratio = round(available_kb / total_kb, 4)
        elif total_kb > 0:
            limitations.append("MemAvailable is not reported by this kernel; memory pressure is not assessed")
        else:
            source = SOURCE_FALLBACK
            limitations.append("/proc/meminfo is unreadable; memory pressure is not assessed")

        cpu_busy: float | None = None
        current_cpu = _read_proc_stat()
        if current_cpu and self._previous_cpu:
            previous = self._previous_cpu
            total_delta = sum(current_cpu.get(key, 0) - previous.get(key, 0) for key in current_cpu)
            idle_delta = (current_cpu.get("idle", 0) - previous.get("idle", 0)) + (
                current_cpu.get("iowait", 0) - previous.get("iowait", 0)
            )
            if total_delta > 0:
                cpu_busy = round(max(0.0, min(1.0, 1.0 - idle_delta / total_delta)), 4)
        if current_cpu:
            self._previous_cpu = current_cpu
        if cpu_busy is None:
            limitations.append("CPU busy ratio needs two samples; it is null on the first call and after a failure")

        disk_free_bytes = 0
        disk_total_mb = 0
        disk_free_mb = 0
        try:
            usage = shutil.disk_usage(self.disk_path)
            disk_total_mb = usage.total // 1024**2
            disk_free_mb = usage.free // 1024**2
            disk_free_bytes = usage.free
        except OSError as exc:
            self._read_failures += 1
            limitations.append(f"disk usage for '{self.disk_path}' could not be read: {type(exc).__name__}")

        process_count = _count_processes()
        if process_count == 0:
            limitations.append("process count is unavailable; runaway-subprocess detection relies on NOVA's own records")

        if total_kb == 0:
            # Neither /proc/meminfo nor any fallback produced a total, so memory
            # pressure is genuinely unknown rather than assumed comfortable.
            source = SOURCE_UNAVAILABLE

        sample = ResourceSample(
            collected_at=_now().isoformat(timespec="microseconds"),
            source=source,
            cpu_count=cpu_count,
            load_1m=round(load_1m, 3),
            load_5m=round(load_5m, 3),
            load_15m=round(load_15m, 3),
            load_per_cpu=round(load_1m / cpu_count, 3) if cpu_count else 0.0,
            cpu_busy_ratio=cpu_busy,
            memory_total_mb=memory_total_mb,
            memory_available_mb=memory_available_mb,
            memory_available_ratio=memory_ratio,
            disk_total_mb=disk_total_mb,
            disk_free_mb=disk_free_mb,
            disk_free_bytes=disk_free_bytes,
            process_count=process_count,
            limitations=tuple(limitations),
        )
        self._history.append(sample)
        if len(self._history) > self.history_limit:
            del self._history[: len(self._history) - self.history_limit]
        return sample

    # -- assessment

    def assess(self, sample: ResourceSample | None = None) -> ResourceBudget:
        """Turn a measurement into concrete limits on NOVA's own activity."""
        measured = sample or self.sample()
        reasons: list[str] = []
        warnings: list[str] = []
        levels: list[str] = []

        ratio = measured.memory_available_ratio
        if ratio is None:
            warnings.append("memory pressure is unknown, so memory-driven scaling stays at the conservative baseline")
        else:
            if ratio < self.thresholds.memory_available_ratio_critical:
                levels.append(PRESSURE_CRITICAL)
                reasons.append(f"only {ratio:.0%} of RAM is available")
            elif ratio < self.thresholds.memory_available_ratio_high:
                levels.append(PRESSURE_HIGH)
                reasons.append(f"only {ratio:.0%} of RAM is available")
            elif ratio < self.thresholds.memory_available_ratio_elevated:
                levels.append(PRESSURE_ELEVATED)
                reasons.append(f"{ratio:.0%} of RAM is available")

        load = measured.load_per_cpu
        if load > 0.0:
            if load >= self.thresholds.load_per_cpu_critical:
                levels.append(PRESSURE_CRITICAL)
                reasons.append(f"load per CPU is {load:.2f}")
            elif load >= self.thresholds.load_per_cpu_high:
                levels.append(PRESSURE_HIGH)
                reasons.append(f"load per CPU is {load:.2f}")
            elif load >= self.thresholds.load_per_cpu_elevated:
                levels.append(PRESSURE_ELEVATED)
                reasons.append(f"load per CPU is {load:.2f}")

        free = measured.disk_free_bytes
        if free > 0:
            if free < self.thresholds.disk_free_bytes_critical:
                levels.append(PRESSURE_CRITICAL)
                reasons.append(f"only {free // 1024**2} MB of disk is free")
                warnings.append("disk space is critically low; new downloads, model pulls and indexing are refused")
            elif free < self.thresholds.disk_free_bytes_high:
                levels.append(PRESSURE_HIGH)
                reasons.append(f"only {free // 1024**3} GB of disk is free")
                warnings.append("disk space is low; large artifacts should be avoided")
            elif free < self.thresholds.disk_free_bytes_elevated:
                levels.append(PRESSURE_ELEVATED)
                reasons.append(f"only {free // 1024**3} GB of disk is free")

        # A single busy sample is normal on two cores - compiling, or running the
        # test suite, saturates them. CPU utilization only escalates the level when
        # the load average corroborates it, so NOVA does not flap between profiles
        # every time it does real work.
        if measured.cpu_busy_ratio is not None and measured.cpu_busy_ratio > 0.9:
            if load >= self.thresholds.load_per_cpu_elevated:
                levels.append(PRESSURE_ELEVATED)
                reasons.append(f"CPUs are {measured.cpu_busy_ratio:.0%} busy with a load of {load:.2f} per CPU")
            else:
                warnings.append(
                    f"CPUs measured {measured.cpu_busy_ratio:.0%} busy but the load average is {load:.2f} per CPU, "
                    "so this looks like NOVA's own work rather than machine-wide pressure"
                )

        if self.low_resource_mode and not levels:
            reasons.append("NOVA_LOW_RESOURCE_MODE is on, so the conservative profile is the floor")

        pressure = PRESSURE_NORMAL
        for level in levels:
            if PRESSURE_RANK[level] > PRESSURE_RANK[pressure]:
                pressure = level
        rank = PRESSURE_RANK[pressure]

        budget = ResourceBudget(
            decided_at=_now().isoformat(timespec="microseconds"),
            pressure=pressure,
            reasons=tuple(reasons),
            warnings=tuple(warnings),
            sample=measured,
            # Serial execution is already the default; pressure can only reduce.
            max_parallel_tasks=1 if rank >= PRESSURE_RANK[PRESSURE_ELEVATED] else max(1, self.baseline_parallel_tasks),
            max_model_concurrency=1 if rank >= PRESSURE_RANK[PRESSURE_HIGH] else max(1, self.baseline_model_concurrency - (1 if rank else 0)),
            max_background_workers=0 if rank >= PRESSURE_RANK[PRESSURE_CRITICAL] else (1 if rank >= PRESSURE_RANK[PRESSURE_HIGH] else self.baseline_background_workers),
            indexing_enabled=rank < PRESSURE_RANK[PRESSURE_HIGH],
            index_chunk_bytes=32 * 1024 if rank >= PRESSURE_RANK[PRESSURE_ELEVATED] else 64 * 1024,
            terminal_capture_chars=4_000 if rank >= PRESSURE_RANK[PRESSURE_HIGH] else (8_000 if rank >= PRESSURE_RANK[PRESSURE_ELEVATED] else 12_000),
            reduce_visual_effects=rank >= PRESSURE_RANK[PRESSURE_ELEVATED],
            defer_optional_work=rank >= PRESSURE_RANK[PRESSURE_ELEVATED],
            # §110: never start a local model under pressure, and never start one
            # automatically at all - the operator asks for it.
            allow_local_model_start=False,
            max_concurrent_sandboxed_processes=1 if rank >= PRESSURE_RANK[PRESSURE_ELEVATED] else max(1, measured.cpu_count // 2 or 1),
        )
        self._decisions.append(budget)
        if len(self._decisions) > self.history_limit:
            del self._decisions[: len(self._decisions) - self.history_limit]
        return budget

    def should_defer(self, kind: str, sample: ResourceSample | None = None) -> dict[str, Any]:
        """Ask whether an optional activity should wait. Returns the reason."""
        optional = {"indexing", "embedding", "background_scan", "prefetch", "local_model", "report_generation", "visual_effects"}
        budget = self.assess(sample)
        if kind not in optional:
            return {
                "kind": kind,
                "defer": False,
                "reason": f"'{kind}' is not an optional activity, so resource policy does not defer it",
                "pressure": budget.pressure,
            }
        if kind == "indexing":
            defer = not budget.indexing_enabled
            reason = "indexing is paused under high resource pressure" if defer else "indexing is permitted"
        elif kind == "local_model":
            defer = True
            reason = "a local model is never started automatically; it needs an explicit operator request and enough free RAM"
        else:
            defer = budget.defer_optional_work
            reason = f"optional work is deferred at '{budget.pressure}' pressure" if defer else f"optional work is permitted at '{budget.pressure}' pressure"
        return {"kind": kind, "defer": defer, "reason": reason, "pressure": budget.pressure, "reasons": list(budget.reasons)}

    def adapt(self, budget: ResourceBudget, settings: Any) -> dict[str, Any]:
        """Project a budget onto a Settings-like object without mutating it.

        Returns the effective values a caller should use. The original settings
        object is never changed, so an operator's explicit configuration is not
        silently overwritten by a transient measurement.
        """
        effective = {
            "max_parallel_tasks": min(int(getattr(settings, "max_parallel_tasks", 1) or 1), budget.max_parallel_tasks),
            "max_model_concurrency": min(int(getattr(settings, "max_model_concurrency", 1) or 1), budget.max_model_concurrency),
            "max_tool_output_chars": min(int(getattr(settings, "max_tool_output_chars", 12_000) or 12_000), budget.terminal_capture_chars),
            "indexing_enabled": budget.indexing_enabled,
            "defer_optional_work": budget.defer_optional_work,
            "reduce_visual_effects": budget.reduce_visual_effects,
        }
        reduced = [key for key, value in effective.items() if isinstance(value, int) and value < int(getattr(settings, key, value) or value)]
        return {
            "pressure": budget.pressure,
            "effective": effective,
            "reduced": reduced,
            "reasons": list(budget.reasons),
            "note": "Adaptation lowers NOVA's own limits. It never terminates or renices a process NOVA did not start.",
        }

    # -- runaway detection

    def check_runaway(self, tracked: list[dict[str, Any]], *, max_age_seconds: float = 900.0) -> dict[str, Any]:
        """Report NOVA-started processes that outlived their limit.

        Only processes NOVA recorded are considered. Nothing is killed here; the
        caller decides, and the decision is reported.
        """
        now = _now()
        runaway: list[dict[str, Any]] = []
        for entry in tracked:
            started_at = str(entry.get("started_at", "") or "")
            if not started_at:
                continue
            try:
                started = datetime.fromisoformat(started_at)
            except ValueError:
                continue
            if started.tzinfo is None:
                started = started.replace(tzinfo=UTC)
            age = (now - started).total_seconds()
            limit = float(entry.get("time_limit_seconds", max_age_seconds) or max_age_seconds)
            if age > limit:
                runaway.append(
                    {
                        "pid": entry.get("pid"),
                        "session_id": entry.get("session_id", ""),
                        "started_at": started_at,
                        "age_seconds": round(age, 1),
                        "time_limit_seconds": limit,
                        "started_by_nova": bool(entry.get("started_by_nova", True)),
                        "action": "reported",
                    }
                )
        return {
            "checked": len(tracked),
            "runaway": runaway,
            "policy": "Processes NOVA started are reported for termination through the terminal workspace. Unrelated user processes are never touched.",
        }

    # -- reporting

    def snapshot(self) -> dict[str, Any]:
        latest = self._history[-1] if self._history else None
        decision = self._decisions[-1] if self._decisions else None
        return {
            "sample": latest.to_dict() if latest else None,
            "budget": decision.to_dict() if decision else None,
            "samples_collected": len(self._history),
            "decisions_made": len(self._decisions),
            "read_failures": self._read_failures,
            "low_resource_mode": self.low_resource_mode,
            "thresholds": {
                "memory_available_ratio": {
                    "elevated": self.thresholds.memory_available_ratio_elevated,
                    "high": self.thresholds.memory_available_ratio_high,
                    "critical": self.thresholds.memory_available_ratio_critical,
                },
                "load_per_cpu": {
                    "elevated": self.thresholds.load_per_cpu_elevated,
                    "high": self.thresholds.load_per_cpu_high,
                    "critical": self.thresholds.load_per_cpu_critical,
                },
                "disk_free_bytes": {
                    "elevated": self.thresholds.disk_free_bytes_elevated,
                    "high": self.thresholds.disk_free_bytes_high,
                    "critical": self.thresholds.disk_free_bytes_critical,
                },
            },
            "pressure_levels": list(PRESSURE_LEVELS),
            "history": [item.to_dict() for item in self._history[-20:]],
            "note": (
                "A sample describes the whole machine, not NOVA's share of it. Adaptation only ever "
                "reduces NOVA's own limits and never interferes with other processes."
            ),
        }

    def export_report(self) -> dict[str, Any]:
        """Diagnostic export: no credentials, no command arguments, no file content."""
        snapshot = self.snapshot()
        return {
            "generated_at": _now().isoformat(timespec="microseconds"),
            "resource": snapshot,
            "environment": {
                "cpu_count": os.cpu_count() or 0,
                "pid": os.getpid(),
                "disk_path": self.disk_path,
            },
            "redaction": "This report contains measurements only. No credentials, tokens, file contents or command arguments are included.",
        }

    def with_sample(self, sample: ResourceSample) -> ResourceBudget:
        """Assess an externally supplied sample (used by tests and callers that already measured)."""
        return self.assess(sample)


__all__ = [
    "DISK_FREE_BYTES_CRITICAL",
    "DISK_FREE_BYTES_ELEVATED",
    "DISK_FREE_BYTES_HIGH",
    "HISTORY_LIMIT",
    "LOAD_PER_CPU_CRITICAL",
    "LOAD_PER_CPU_ELEVATED",
    "LOAD_PER_CPU_HIGH",
    "MEMORY_AVAILABLE_RATIO_CRITICAL",
    "MEMORY_AVAILABLE_RATIO_ELEVATED",
    "MEMORY_AVAILABLE_RATIO_HIGH",
    "PRESSURE_CRITICAL",
    "PRESSURE_ELEVATED",
    "PRESSURE_HIGH",
    "PRESSURE_LEVELS",
    "PRESSURE_NORMAL",
    "ResourceBudget",
    "ResourceManager",
    "ResourceSample",
    "Thresholds",
]
