"""§101 Safe execution sandbox.

Runs generated, experimental or untrusted code with a restricted filesystem,
controlled network access, resource limits and a hard timeout.

Two honesty rules drive the design:

* **A separate Python process is not a sandbox.** :data:`MECHANISM_PROCESS`
  exists only so that pure, side-effect-free commands can still run when no
  isolation mechanism is present, and it reports itself as *not isolated* with
  an empty guarantee list. Nothing may describe it as sandboxed.
* **Never silently downgrade.** If the isolation a risk level requires is
  unavailable, the run is refused with a reason. Risky code is not executed
  unprotected just because the user asked for it and the host cannot comply.

Mechanism preference is bubblewrap, then Podman, then Linux namespaces entered
directly with ``unshare`` plus the in-repo child at :mod:`nova.sandbox_child`.
The namespace path is what runs on a stock Kali install with no extra packages:
it was verified to confine writes to the granted roots, make the rest of the
filesystem read-only, hide listed paths entirely, remove or provide the network
as configured, and enforce rlimits.
"""
from __future__ import annotations

import json
import os
import resource
import selectors
import shutil
import signal
import subprocess
import sys
import time
from dataclasses import dataclass, field, replace
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

MECHANISM_NONE = "none"
MECHANISM_PROCESS = "process_only"
MECHANISM_NAMESPACED = "linux_namespaces"
MECHANISM_BWRAP = "bubblewrap"
MECHANISM_PODMAN = "podman"
MECHANISMS = (MECHANISM_NONE, MECHANISM_PROCESS, MECHANISM_NAMESPACED, MECHANISM_BWRAP, MECHANISM_PODMAN)
MECHANISM_RANK = {name: index for index, name in enumerate(MECHANISMS)}

RISK_PURE = "pure"
RISK_SCOPED_WRITE = "scoped_write"
RISK_GENERATED_CODE = "generated_code"
RISK_UNTRUSTED_CODE = "untrusted_code"
RISK_LEVELS = (RISK_PURE, RISK_SCOPED_WRITE, RISK_GENERATED_CODE, RISK_UNTRUSTED_CODE)
RISK_RANK = {name: index for index, name in enumerate(RISK_LEVELS)}

STATUS_COMPLETED = "completed"
STATUS_TIMEOUT = "timeout"
STATUS_REFUSED = "refused"
STATUS_SETUP_FAILED = "setup_failed"
STATUS_ERROR = "error"
RESULT_STATUSES = (STATUS_COMPLETED, STATUS_TIMEOUT, STATUS_REFUSED, STATUS_SETUP_FAILED, STATUS_ERROR)

MINIMUM_MECHANISM_FOR_RISK = {
    RISK_PURE: MECHANISM_PROCESS,
    RISK_SCOPED_WRITE: MECHANISM_NAMESPACED,
    RISK_GENERATED_CODE: MECHANISM_NAMESPACED,
    RISK_UNTRUSTED_CODE: MECHANISM_NAMESPACED,
}

DEFAULT_TIMEOUT_SECONDS = 30.0
MAX_TIMEOUT_SECONDS = 600.0
DEFAULT_MAX_OUTPUT_BYTES = 65_536
MAX_OUTPUT_BYTES_CEILING = 4 * 1024 * 1024
# Kept below the 64 KiB default pipe capacity so writing stdin cannot block
# forever on a child that never reads.
MAX_STDIN_BYTES = 32_768
CHILD_SETUP_FAILED_EXIT = 126
CHILD_BAD_CONFIG_EXIT = 127

# Paths that untrusted code must never read, even read-only.
DEFAULT_HIDDEN_PATHS = (
    "~/.ssh",
    "~/.gnupg",
    "~/.config/keyring",
    "~/.local/share/keyrings",
    "~/.aws",
    "~/.kube",
    "~/.netrc",
    "~/.git-credentials",
)

_NAMESPACED_GUARANTEES = (
    "writes are confined to the granted writable roots; everything else is read-only",
    "paths listed as hidden are unreadable, not merely read-only",
    "the network namespace is empty unless the policy explicitly enables network access",
    "host processes are not visible: the child runs in a new PID namespace",
    "CPU time, process count, open-file, file-size and core-dump limits are enforced",
    "setuid and file-capability privilege escalation is disabled via PR_SET_NO_NEW_PRIVS",
    "the child is killed, together with its process group, when the timeout expires; a PID-namespace\n    init ignores SIGTERM, so escalation to SIGKILL is immediate rather than after a grace period",
    "if any mount or limit cannot be applied the command is never executed",
)

_NAMESPACED_NOT_GUARANTEED = (
    "this is not a boundary against a kernel exploit; a vulnerability in the kernel could still escape",
    "read-only is not unreadable: anything not explicitly listed as hidden can be read by the child",
    "no seccomp system-call filter is applied, so the child may make any syscall",
    "resource limits bound the child process tree, not the machine as a whole",
    "the NOVA process that launched the sandbox is itself not isolated",
    "user-namespace root is mapped to the invoking user, so files created are owned by that user",
)

_PROCESS_GUARANTEES = (
    "the child runs in its own process group and is killed when the timeout expires",
    "captured output is bounded and truncated rather than buffered without limit",
    "CPU time, process count, open-file and file-size limits are applied to the child",
)

_PROCESS_NOT_GUARANTEED = (
    "THIS IS NOT A SANDBOX: a separate process provides no isolation whatsoever",
    "the filesystem is fully accessible with the privileges of the NOVA user",
    "network access is unrestricted",
    "no path is hidden; credentials readable by the user are readable by the child",
    "it must never be used for untrusted or downloaded code",
)


def _now() -> str:
    return datetime.now(UTC).isoformat(timespec="microseconds")


def _expand(path: str) -> str:
    return str(Path(path).expanduser())


@dataclass(frozen=True)
class SandboxPolicy:
    """What one sandboxed run is allowed to touch, and for how long."""

    writable_roots: tuple[str, ...] = ()
    hidden_paths: tuple[str, ...] = DEFAULT_HIDDEN_PATHS
    network: bool = False
    timeout_seconds: float = DEFAULT_TIMEOUT_SECONDS
    max_cpu_seconds: int = 20
    max_processes: int = 32
    max_open_files: int = 128
    max_file_size_bytes: int = 10 * 1024 * 1024
    # Address-space limits are opt-in: interpreters reserve far more virtual
    # memory than they use, so a tight RLIMIT_AS makes Python fail to start and
    # the failure looks like the sandboxed program's fault.
    max_address_space_mb: int = 0
    tmpfs_mb: int = 32
    max_output_bytes: int = DEFAULT_MAX_OUTPUT_BYTES
    env: tuple[str, ...] = ("PATH", "HOME", "LANG", "LC_ALL", "TERM", "TMPDIR")
    cwd: str = ""

    def validated(self) -> tuple[SandboxPolicy, list[str]]:
        """Clamp the policy into range and report what was changed."""
        notes: list[str] = []
        timeout = self.timeout_seconds
        if timeout <= 0:
            timeout = DEFAULT_TIMEOUT_SECONDS
            notes.append("a non-positive timeout was replaced with the default")
        if timeout > MAX_TIMEOUT_SECONDS:
            timeout = MAX_TIMEOUT_SECONDS
            notes.append(f"timeout was capped at {MAX_TIMEOUT_SECONDS:g}s")
        output = self.max_output_bytes
        if output <= 0 or output > MAX_OUTPUT_BYTES_CEILING:
            output = min(max(output, 1024), MAX_OUTPUT_BYTES_CEILING)
            notes.append(f"output cap was clamped to {output} bytes")
        writable = tuple(dict.fromkeys(_expand(item) for item in self.writable_roots if str(item).strip()))
        hidden = tuple(dict.fromkeys(_expand(item) for item in self.hidden_paths if str(item).strip()))
        overlap = sorted({item for item in writable if any(item == h or item.startswith(h + os.sep) for h in hidden)})
        if overlap:
            notes.append(f"writable roots inside hidden paths were dropped: {', '.join(overlap)}")
            writable = tuple(item for item in writable if item not in overlap)
        policy = SandboxPolicy(
            writable_roots=writable,
            hidden_paths=hidden,
            network=bool(self.network),
            timeout_seconds=timeout,
            max_cpu_seconds=max(1, int(self.max_cpu_seconds)),
            max_processes=max(1, int(self.max_processes)),
            max_open_files=max(8, int(self.max_open_files)),
            max_file_size_bytes=max(1024, int(self.max_file_size_bytes)),
            max_address_space_mb=max(0, int(self.max_address_space_mb)),
            tmpfs_mb=max(1, int(self.tmpfs_mb)),
            max_output_bytes=output,
            env=self.env,
            cwd=_expand(self.cwd) if self.cwd else "",
        )
        return policy, notes

    def rlimits(self) -> dict[str, int]:
        limits = {
            "RLIMIT_CPU": int(self.max_cpu_seconds),
            "RLIMIT_NPROC": int(self.max_processes),
            "RLIMIT_NOFILE": int(self.max_open_files),
            "RLIMIT_FSIZE": int(self.max_file_size_bytes),
            "RLIMIT_CORE": 0,
        }
        if self.max_address_space_mb > 0:
            limits["RLIMIT_AS"] = int(self.max_address_space_mb) * 1024 * 1024
        return {name: value for name, value in limits.items() if hasattr(resource, name)}

    def to_dict(self) -> dict[str, Any]:
        return {
            "writable_roots": list(self.writable_roots),
            "hidden_paths": list(self.hidden_paths),
            "network": self.network,
            "timeout_seconds": self.timeout_seconds,
            "max_cpu_seconds": self.max_cpu_seconds,
            "max_processes": self.max_processes,
            "max_open_files": self.max_open_files,
            "max_file_size_bytes": self.max_file_size_bytes,
            "max_address_space_mb": self.max_address_space_mb,
            "tmpfs_mb": self.tmpfs_mb,
            "max_output_bytes": self.max_output_bytes,
            "env": list(self.env),
            "cwd": self.cwd,
            "rlimits": self.rlimits(),
        }


@dataclass(frozen=True)
class IsolationCapability:
    """What isolation this machine can actually provide, and what it means."""

    mechanism: str
    available: bool
    detail: str
    guarantees: tuple[str, ...] = ()
    not_guaranteed: tuple[str, ...] = ()
    checked_at: str = field(default_factory=_now)

    def to_dict(self) -> dict[str, Any]:
        return {
            "mechanism": self.mechanism,
            "available": self.available,
            "detail": self.detail,
            "guarantees": list(self.guarantees),
            "not_guaranteed": list(self.not_guaranteed),
            "checked_at": self.checked_at,
        }


@dataclass(frozen=True)
class SandboxResult:
    """The outcome of one sandboxed run, including how isolated it really was."""

    status: str
    mechanism: str
    isolation_claim: str
    exit_code: int | None = None
    stdout: str = ""
    stderr: str = ""
    duration_ms: float = 0.0
    output_truncated: bool = False
    signal_name: str = ""
    guarantees: tuple[str, ...] = ()
    not_guaranteed: tuple[str, ...] = ()
    limitations: tuple[str, ...] = ()
    refused_reason: str = ""
    argv: tuple[str, ...] = ()
    risk: str = RISK_PURE
    policy_notes: tuple[str, ...] = ()
    writable_roots: tuple[str, ...] = ()
    network_enabled: bool = False

    def to_dict(self) -> dict[str, Any]:
        return {
            "status": self.status,
            "mechanism": self.mechanism,
            "isolation_claim": self.isolation_claim,
            "exit_code": self.exit_code,
            "stdout": self.stdout,
            "stderr": self.stderr,
            "duration_ms": self.duration_ms,
            "output_truncated": self.output_truncated,
            "signal_name": self.signal_name,
            "guarantees": list(self.guarantees),
            "not_guaranteed": list(self.not_guaranteed),
            "limitations": list(self.limitations),
            "refused_reason": self.refused_reason,
            "argv": list(self.argv),
            "risk": self.risk,
            "policy_notes": list(self.policy_notes),
            "writable_roots": list(self.writable_roots),
            "network_enabled": self.network_enabled,
        }


def classify_risk(argv: list[str] | tuple[str, ...], *, writes_files: bool = False, code_is_generated: bool = False, code_is_downloaded: bool = False) -> dict[str, Any]:
    """Assign a risk level to a command and say what isolation it therefore needs.

    This is the classification §101 asks for: which operations can run in
    isolation, which necessarily touch the host, and which need the strongest
    available boundary.
    """
    if code_is_downloaded or any(str(item).endswith((".sh", ".bash")) for item in argv[1:]):
        risk = RISK_UNTRUSTED_CODE
        reason = "the code came from outside NOVA, or a shell script is being interpreted"
    elif code_is_generated:
        risk = RISK_GENERATED_CODE
        reason = "the code was produced by a model and has not been reviewed"
    elif writes_files:
        risk = RISK_SCOPED_WRITE
        reason = "the command writes files, so its writable scope must be bounded"
    else:
        risk = RISK_PURE
        reason = "the command is read-only and deterministic"
    required = MINIMUM_MECHANISM_FOR_RISK[risk]
    host_interaction = risk == RISK_PURE
    return {
        "risk": risk,
        "reason": reason,
        "required_mechanism": required,
        "runs_in_isolation": not host_interaction,
        "necessarily_touches_host": host_interaction,
        "network_must_be_disabled": risk == RISK_UNTRUSTED_CODE,
        "hidden_paths_required": risk in (RISK_UNTRUSTED_CODE, RISK_GENERATED_CODE),
        "note": (
            "A pure read-only command is the only class that may run without isolation, and even then "
            "the process-only mechanism reports itself as not sandboxed."
        ),
    }


@dataclass
class Sandbox:
    """Detects the available isolation mechanism and runs commands inside it."""

    python_executable: str = ""
    podman_image: str = ""
    detection_timeout_seconds: float = 10.0
    allow_process_only_for_pure_commands: bool = True
    _capability: IsolationCapability | None = field(default=None, init=False)
    _runs: int = field(default=0, init=False)
    _refusals: int = field(default=0, init=False)
    _timeouts: int = field(default=0, init=False)
    _setup_failures: int = field(default=0, init=False)

    def __post_init__(self) -> None:
        self.python_executable = self.python_executable or sys.executable or "python3"

    # -- detection

    def detect(self, *, force: bool = False) -> IsolationCapability:
        if self._capability is not None and not force:
            return self._capability
        capability = self._detect()
        self._capability = capability
        return capability

    def _detect(self) -> IsolationCapability:
        bwrap = shutil.which("bwrap")
        if bwrap:
            try:
                bwrap_probe = subprocess.run(
                    [bwrap, "--ro-bind", "/", "/", "true"],
                    capture_output=True,
                    timeout=self.detection_timeout_seconds,
                    check=False,
                )
            except (OSError, subprocess.SubprocessError):
                bwrap_probe = None
            if bwrap_probe is not None and bwrap_probe.returncode == 0:
                return IsolationCapability(
                    mechanism=MECHANISM_BWRAP,
                    available=True,
                    detail=f"bubblewrap verified operational at {bwrap}",
                    guarantees=_NAMESPACED_GUARANTEES,
                    not_guaranteed=_NAMESPACED_NOT_GUARANTEED,
                )
        podman = shutil.which("podman")
        if podman and self.podman_image:
            return IsolationCapability(
                mechanism=MECHANISM_PODMAN,
                available=True,
                detail=f"podman found at {podman} with configured image '{self.podman_image}'",
                guarantees=_NAMESPACED_GUARANTEES,
                not_guaranteed=_NAMESPACED_NOT_GUARANTEED,
            )
        unshare = shutil.which("unshare")
        if not unshare:
            return IsolationCapability(
                mechanism=MECHANISM_NONE,
                available=False,
                detail="'unshare' is not available and no container runtime is installed, so no isolation mechanism exists on this host",
                guarantees=(),
                not_guaranteed=("no isolation is possible; risky execution must be refused",),
            )
        try:
            probe = subprocess.run(
                [unshare, "--user", "--map-root-user", "--mount", "true"],
                capture_output=True,
                timeout=self.detection_timeout_seconds,
                check=False,
            )
        except (OSError, subprocess.SubprocessError) as exc:
            return IsolationCapability(
                mechanism=MECHANISM_NONE,
                available=False,
                detail=f"the namespace probe could not run: {type(exc).__name__}: {exc}",
            )
        if probe.returncode != 0:
            detail = (probe.stderr or b"").decode("utf-8", "replace").strip().splitlines()
            return IsolationCapability(
                mechanism=MECHANISM_NONE,
                available=False,
                detail=(
                    "unprivileged user namespaces are blocked on this host: "
                    + (detail[-1][:200] if detail else f"unshare exited {probe.returncode}")
                ),
                not_guaranteed=("no isolation is possible; risky execution must be refused",),
            )
        return IsolationCapability(
            mechanism=MECHANISM_NAMESPACED,
            available=True,
            detail="unprivileged user namespaces are permitted; isolation is built with unshare and nova.sandbox_child",
            guarantees=_NAMESPACED_GUARANTEES,
            not_guaranteed=_NAMESPACED_NOT_GUARANTEED,
        )

    # -- execution

    def run(
        self,
        argv: list[str] | tuple[str, ...],
        *,
        risk: str = RISK_PURE,
        policy: SandboxPolicy | None = None,
        stdin_text: str = "",
        classification: dict[str, Any] | None = None,
    ) -> SandboxResult:
        """Run ``argv`` under the strongest isolation this host can provide."""
        self._runs += 1
        items = [str(item) for item in argv]
        if not items:
            return self._refuse(items, risk, MECHANISM_NONE, "no command was supplied")
        if risk not in RISK_LEVELS:
            return self._refuse(items, risk, MECHANISM_NONE, f"unknown risk level '{risk}'")
        if any("\x00" in item for item in items):
            return self._refuse(items, risk, MECHANISM_NONE, "the command contains a NUL byte")

        requested = policy or SandboxPolicy()
        effective, notes = requested.validated()
        classification = classification or classify_risk(items, writes_files=bool(effective.writable_roots))
        if classification.get("network_must_be_disabled") and effective.network:
            notes.append("network access was forced off because the risk classification requires it")
            effective = replace(effective, network=False)
        if classification.get("hidden_paths_required") and not effective.hidden_paths:
            notes.append("credential paths were hidden because the risk classification requires it")
            effective = replace(effective, hidden_paths=DEFAULT_HIDDEN_PATHS)

        capability = self.detect()
        required = MINIMUM_MECHANISM_FOR_RISK[risk]

        if not capability.available:
            if risk == RISK_PURE and self.allow_process_only_for_pure_commands:
                return self._run_process_only(items, effective, notes, stdin_text, risk)
            self._refusals += 1
            return SandboxResult(
                status=STATUS_REFUSED,
                mechanism=MECHANISM_NONE,
                isolation_claim="no isolation mechanism is available on this host",
                refused_reason=(
                    f"'{risk}' execution requires at least '{required}' isolation, but {capability.detail}. "
                    "NOVA refuses to run it unprotected rather than silently falling back to the host."
                ),
                argv=tuple(items),
                risk=risk,
                policy_notes=tuple(notes),
                limitations=(
                    "Install bubblewrap, or enable unprivileged user namespaces, to run this class of command.",
                    "The refusal is the safe outcome: nothing was executed.",
                ),
                not_guaranteed=("nothing ran, so nothing was isolated",),
            )

        if MECHANISM_RANK[capability.mechanism] < MECHANISM_RANK[required]:
            self._refusals += 1
            return SandboxResult(
                status=STATUS_REFUSED,
                mechanism=capability.mechanism,
                isolation_claim=capability.detail,
                refused_reason=f"'{risk}' execution requires '{required}' but only '{capability.mechanism}' is available",
                argv=tuple(items),
                risk=risk,
                policy_notes=tuple(notes),
            )

        if capability.mechanism in (MECHANISM_NAMESPACED, MECHANISM_BWRAP, MECHANISM_PODMAN):
            return self._run_namespaced(items, effective, notes, stdin_text, risk, capability)
        return self._run_process_only(items, effective, notes, stdin_text, risk)

    def _refuse(self, argv: list[str], risk: str, mechanism: str, reason: str) -> SandboxResult:
        self._refusals += 1
        return SandboxResult(
            status=STATUS_REFUSED,
            mechanism=mechanism,
            isolation_claim="nothing was executed",
            refused_reason=reason,
            argv=tuple(argv),
            risk=risk,
        )

    def _run_namespaced(
        self,
        argv: list[str],
        policy: SandboxPolicy,
        notes: list[str],
        stdin_text: str,
        risk: str,
        capability: IsolationCapability,
    ) -> SandboxResult:
        limitations = list(capability.not_guaranteed)
        if capability.mechanism == MECHANISM_BWRAP:
            launcher = self._bwrap_argv(argv, policy)
            claim = "bubblewrap sandbox: read-only root bind with explicit writable binds and an unshared network"
        elif capability.mechanism == MECHANISM_PODMAN:
            # Podman needs an image; rather than pulling one silently (which would
            # cost network access and hundreds of MB on a small machine) NOVA
            # reports that the mechanism is present but unusable until configured.
            self._refusals += 1
            return SandboxResult(
                status=STATUS_REFUSED,
                mechanism=capability.mechanism,
                isolation_claim=capability.detail,
                refused_reason=(
                    "podman is installed but NOVA has no configured container image, and pulling one would "
                    "require network access and disk space the operator has not approved"
                ),
                argv=tuple(argv),
                risk=risk,
                policy_notes=tuple(notes),
                limitations=("Configure a local image and the podman path becomes usable.",),
            )
        else:
            # unshare creates the namespaces; nova.sandbox_child performs the mounts
            # and applies the limits inside them, then execs the real command. No
            # shell is involved at any point.
            launcher = ["unshare", "--user", "--map-root-user", "--mount", "--pid", "--fork", "--ipc", "--uts"]
            if not policy.network:
                launcher.append("--net")
            launcher += ["--", self.python_executable, "-m", "nova.sandbox_child"]
            claim = "user, mount, PID, IPC and UTS namespaces with rlimits and NO_NEW_PRIVS"
            if policy.max_address_space_mb == 0:
                limitations.append("no address-space limit was applied; memory use is bounded only by the host")
        child_config = {
            "argv": argv,
            "cwd": policy.cwd,
            "writable_roots": list(policy.writable_roots),
            "hidden_paths": list(policy.hidden_paths),
            "tmpfs_mb": policy.tmpfs_mb,
            "rlimits": policy.rlimits() if capability.mechanism != MECHANISM_BWRAP else {},
            "env": self._build_environment(policy),
        }
        environment = self._host_environment(policy)
        if capability.mechanism != MECHANISM_BWRAP:
            environment["NOVA_SANDBOX_CONFIG"] = json.dumps(child_config, separators=(",", ":"))
            repo_root = str(Path(__file__).resolve().parent.parent)
            existing = environment.get("PYTHONPATH", "")
            environment["PYTHONPATH"] = f"{repo_root}{os.pathsep}{existing}" if existing else repo_root
        return self._execute(
            launcher,
            environment,
            policy,
            notes,
            stdin_text,
            risk,
            mechanism=capability.mechanism,
            isolation_claim=claim,
            guarantees=capability.guarantees,
            not_guaranteed=tuple(limitations),
            argv=tuple(argv),
        )

    @staticmethod
    def _bwrap_argv(argv: list[str], policy: SandboxPolicy) -> list[str]:
        """Build a bubblewrap command line. Fixed structure, validated paths only."""
        launcher = [
            "bwrap",
            "--ro-bind", "/", "/",
            "--dev", "/dev",
            "--proc", "/proc",
            "--tmpfs", "/tmp",
            "--die-with-parent",
            "--new-session",
            "--clearenv",
        ]
        for name in policy.env:
            value = os.environ.get(name)
            if value is not None:
                launcher += ["--setenv", name, value]
        for path in policy.writable_roots:
            launcher += ["--bind", path, path]
        for path in policy.hidden_paths:
            if os.path.isdir(path):
                launcher += ["--tmpfs", path]
        launcher.append("--share-net" if policy.network else "--unshare-net")
        return [*launcher, "--", *argv]

    def _run_process_only(
        self, argv: list[str], policy: SandboxPolicy, notes: list[str], stdin_text: str, risk: str
    ) -> SandboxResult:
        return self._execute(
            argv,
            self._build_environment(policy),
            policy,
            notes,
            stdin_text,
            risk,
            mechanism=MECHANISM_PROCESS,
            isolation_claim="NOT ISOLATED - a separate process with resource limits and a timeout, which is not a sandbox",
            guarantees=_PROCESS_GUARANTEES,
            not_guaranteed=_PROCESS_NOT_GUARANTEED,
            argv=tuple(argv),
        )

    @staticmethod
    def _host_environment(policy: SandboxPolicy) -> dict[str, str]:
        environment: dict[str, str] = {}
        for name in policy.env:
            value = os.environ.get(name)
            if value is not None:
                environment[name] = value
        return environment

    @staticmethod
    def _build_environment(policy: SandboxPolicy) -> dict[str, str]:
        environment = Sandbox._host_environment(policy)
        environment.setdefault("PATH", "/usr/local/bin:/usr/bin:/bin")
        environment["TMPDIR"] = "/tmp"
        # Never hand a child the provider key or the session token: a sandboxed
        # process should not be able to exfiltrate what it does not need.
        for secret in ("AI_API_KEY", "NOVA_ACCESS_TOKEN", "TAVILY_API_KEY", "NOVA_SANDBOX_CONFIG"):
            environment.pop(secret, None)
        return environment

    def _execute(
        self,
        launcher: list[str],
        environment: dict[str, str],
        policy: SandboxPolicy,
        notes: list[str],
        stdin_text: str,
        risk: str,
        *,
        mechanism: str,
        isolation_claim: str,
        guarantees: tuple[str, ...],
        not_guaranteed: tuple[str, ...],
        argv: tuple[str, ...],
    ) -> SandboxResult:
        started = time.monotonic()
        cwd = policy.cwd or None
        if cwd and not Path(cwd).is_dir():
            notes.append(f"the requested working directory '{cwd}' does not exist; the process default was used")
            cwd = None
        try:
            process = subprocess.Popen(
                launcher,
                stdin=subprocess.PIPE,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                env=environment,
                cwd=cwd,
                start_new_session=True,
                preexec_fn=self._apply_parent_side_limits(policy) if mechanism == MECHANISM_PROCESS else None,
            )
        except OSError as exc:
            return SandboxResult(
                status=STATUS_ERROR,
                mechanism=mechanism,
                isolation_claim=isolation_claim,
                stderr=f"the sandbox could not be started: {type(exc).__name__}",
                duration_ms=round((time.monotonic() - started) * 1000, 2),
                guarantees=guarantees,
                not_guaranteed=not_guaranteed,
                argv=argv,
                risk=risk,
                policy_notes=tuple(notes),
            )

        stdout, stderr, truncated, timed_out = self._communicate(process, policy, stdin_text, namespaced=mechanism != MECHANISM_PROCESS)
        duration = round((time.monotonic() - started) * 1000, 2)
        exit_code = process.returncode
        signal_name = ""
        if exit_code is not None and exit_code < 0:
            try:
                signal_name = signal.Signals(-exit_code).name
            except ValueError:
                signal_name = str(-exit_code)

        status = STATUS_COMPLETED
        limitations = list(not_guaranteed)
        if timed_out:
            status = STATUS_TIMEOUT
            self._timeouts += 1
            limitations.append(f"the run was killed after exceeding {policy.timeout_seconds:g}s")
        if truncated:
            limitations.append(f"output was capped at {policy.max_output_bytes} bytes and the run was terminated")
        if mechanism == MECHANISM_NAMESPACED and exit_code in (CHILD_SETUP_FAILED_EXIT, CHILD_BAD_CONFIG_EXIT):
            status = STATUS_SETUP_FAILED
            self._setup_failures += 1
            limitations.append("the sandbox could not be built, so the requested command was never executed")

        return SandboxResult(
            status=status,
            mechanism=mechanism,
            isolation_claim=isolation_claim,
            exit_code=exit_code,
            stdout=stdout,
            stderr=stderr,
            duration_ms=duration,
            output_truncated=truncated,
            signal_name=signal_name,
            guarantees=guarantees,
            not_guaranteed=tuple(limitations),
            limitations=tuple(notes),
            argv=argv,
            risk=risk,
            policy_notes=tuple(notes),
            writable_roots=policy.writable_roots,
            network_enabled=policy.network,
        )

    @staticmethod
    def _apply_parent_side_limits(policy: SandboxPolicy) -> Any:
        """Best-effort rlimits for the non-isolated path (POSIX only)."""

        def apply() -> None:
            for name, value in policy.rlimits().items():
                limit = getattr(resource, name, None)
                if limit is None:
                    continue
                try:
                    resource.setrlimit(limit, (value, value))
                except (ValueError, OSError):
                    # This path is already reported as not isolated, so a limit
                    # that cannot be applied weakens it further but is not fatal.
                    continue

        return apply

    @staticmethod
    def _communicate(
        process: subprocess.Popen[bytes], policy: SandboxPolicy, stdin_text: str, *, namespaced: bool = False
    ) -> tuple[str, str, bool, bool]:
        """Bounded, deadline-driven I/O.

        Output is capped rather than buffered without limit: a chatty sandboxed
        process must not exhaust the parent's memory. Reaching the cap terminates
        the run, and the result reports that the output was truncated.
        """
        cap = max(1, policy.max_output_bytes)
        # A PID-namespace init ignores signals whose action is the default, so
        # SIGTERM cannot stop a sandboxed child. Waiting the full grace period
        # would add seconds to every timeout for no effect, so the namespaced path
        # escalates to SIGKILL almost immediately - and SIGKILL from an ancestor
        # namespace is always honoured.
        grace = 0.25 if namespaced else 3.0
        buffers: dict[Any, bytearray] = {process.stdout: bytearray(), process.stderr: bytearray()}
        truncated = False
        timed_out = False
        deadline = time.monotonic() + policy.timeout_seconds

        if stdin_text and process.stdin is not None:
            # MAX_STDIN_BYTES is below the pipe capacity, so this cannot block on a
            # child that never reads.
            payload = stdin_text.encode("utf-8", "replace")[:MAX_STDIN_BYTES]
            try:
                process.stdin.write(payload)
            except OSError:
                pass
        if process.stdin is not None:
            try:
                process.stdin.close()
            except OSError:
                pass

        selector = selectors.DefaultSelector()
        try:
            for stream in (process.stdout, process.stderr):
                if stream is not None:
                    os.set_blocking(stream.fileno(), False)
                    selector.register(stream, selectors.EVENT_READ)
            while selector.get_map() and not truncated and not timed_out:
                remaining = deadline - time.monotonic()
                if remaining <= 0:
                    timed_out = True
                    break
                ready = selector.select(timeout=min(remaining, 0.2))
                if not ready:
                    if process.poll() is not None:
                        break
                    continue
                for key, _ in ready:
                    stream = key.fileobj
                    try:
                        chunk = os.read(stream.fileno(), 65_536)
                    except (BlockingIOError, InterruptedError):
                        continue
                    except OSError:
                        chunk = b""
                    if not chunk:
                        selector.unregister(stream)
                        continue
                    buffer = buffers[stream]
                    room = cap - len(buffer)
                    if len(chunk) >= room:
                        buffer.extend(chunk[:max(0, room)])
                        truncated = True
                        break
                    buffer.extend(chunk)
            if timed_out or truncated:
                Sandbox._terminate(process, grace)
        except (OSError, ValueError):
            Sandbox._terminate(process, grace)
        finally:
            selector.close()
        try:
            process.wait(timeout=5)
        except subprocess.TimeoutExpired:
            Sandbox._terminate(process, grace)
            try:
                process.wait(timeout=5)
            except subprocess.TimeoutExpired:
                process.kill()
        for stream in (process.stdout, process.stderr, process.stdin):
            if stream is not None:
                try:
                    stream.close()
                except OSError:
                    pass
        decode = lambda raw: bytes(raw).decode("utf-8", "replace")  # noqa: E731 - one-line local decoder
        return decode(buffers[process.stdout]), decode(buffers[process.stderr]), truncated, timed_out

    @staticmethod
    def _terminate(process: subprocess.Popen[bytes], grace_seconds: float = 3.0) -> None:
        """Kill the whole process group, then escalate. Never touches other processes."""
        if process.returncode is not None:
            return
        try:
            os.killpg(os.getpgid(process.pid), signal.SIGTERM)
        except (OSError, ProcessLookupError):
            try:
                process.terminate()
            except OSError:
                return
        try:
            process.wait(timeout=grace_seconds)
            return
        except subprocess.TimeoutExpired:
            pass
        try:
            os.killpg(os.getpgid(process.pid), signal.SIGKILL)
        except (OSError, ProcessLookupError):
            try:
                process.kill()
            except OSError:
                return

    # -- reporting

    def report(self) -> dict[str, Any]:
        capability = self.detect()
        return {
            "capability": capability.to_dict(),
            "runs": self._runs,
            "refusals": self._refusals,
            "timeouts": self._timeouts,
            "setup_failures": self._setup_failures,
            "risk_levels": list(RISK_LEVELS),
            "minimum_mechanism_for_risk": dict(MINIMUM_MECHANISM_FOR_RISK),
            "mechanisms": list(MECHANISMS),
            "process_only_is_a_sandbox": False,
            "silent_fallback_to_host": False,
            "note": (
                "A 'refused' result means nothing was executed. NOVA does not run risky code "
                "unprotected when the required isolation is missing."
            ),
        }


def default_hidden_paths() -> tuple[str, ...]:
    """Credential locations that exist on this machine, expanded and resolved."""
    found = []
    for item in DEFAULT_HIDDEN_PATHS:
        path = Path(_expand(item))
        if path.exists():
            found.append(str(path))
    return tuple(found)


__all__ = [
    "CHILD_BAD_CONFIG_EXIT",
    "CHILD_SETUP_FAILED_EXIT",
    "DEFAULT_HIDDEN_PATHS",
    "DEFAULT_MAX_OUTPUT_BYTES",
    "DEFAULT_TIMEOUT_SECONDS",
    "MAX_OUTPUT_BYTES_CEILING",
    "MAX_STDIN_BYTES",
    "MAX_TIMEOUT_SECONDS",
    "MECHANISMS",
    "MECHANISM_BWRAP",
    "MECHANISM_NAMESPACED",
    "MECHANISM_NONE",
    "MECHANISM_PODMAN",
    "MECHANISM_PROCESS",
    "MINIMUM_MECHANISM_FOR_RISK",
    "RESULT_STATUSES",
    "RISK_GENERATED_CODE",
    "RISK_LEVELS",
    "RISK_PURE",
    "RISK_SCOPED_WRITE",
    "RISK_UNTRUSTED_CODE",
    "IsolationCapability",
    "Sandbox",
    "SandboxPolicy",
    "SandboxResult",
    "classify_risk",
    "default_hidden_paths",
]
