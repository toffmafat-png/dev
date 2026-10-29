"""Sandbox child: sets up the isolated environment, then execs the real command.

This module runs *inside* the namespaces created by :mod:`nova.sandbox`. It is
deliberately stdlib-only, short, and auditable: it is the part of NOVA that
holds privileges, so it should be readable in one sitting.

The contract is fail-closed. If any mount or limit cannot be applied the child
exits non-zero **without executing the requested command**. A sandbox that could
not be built never becomes an unsandboxed run.

No shell is involved at any point. The command arrives as an argv list and leaves
as ``os.execve``.
"""
from __future__ import annotations

import ctypes
import json
import os
import resource
import sys

CONFIG_ENV_VAR = "NOVA_SANDBOX_CONFIG"

# mount(2) flags, from <sys/mount.h>
MS_RDONLY = 1
MS_NOSUID = 2
MS_NODEV = 4
MS_NOEXEC = 8
MS_REMOUNT = 32
MS_BIND = 4096
MS_REC = 16384
MS_PRIVATE = 1 << 18

PR_SET_NO_NEW_PRIVS = 38

EXIT_SETUP_FAILED = 126
EXIT_BAD_CONFIG = 127

# Device nodes that must stay writable even though / is mounted read-only, or
# ordinary programs fail in confusing ways.
WRITABLE_DEVICES = ("/dev/null", "/dev/zero", "/dev/full", "/dev/random", "/dev/urandom", "/dev/tty")


def _log(message: str) -> None:
    print(f"[nova-sandbox] {message}", file=sys.stderr, flush=True)


def main() -> int:
    raw = os.environ.get(CONFIG_ENV_VAR, "")
    if not raw:
        _log(f"{CONFIG_ENV_VAR} is not set; refusing to run anything")
        return EXIT_BAD_CONFIG
    try:
        config = json.loads(raw)
    except ValueError as exc:
        _log(f"configuration is not valid JSON ({exc}); refusing to run anything")
        return EXIT_BAD_CONFIG
    if not isinstance(config, dict):
        _log("configuration must be a JSON object")
        return EXIT_BAD_CONFIG

    argv = config.get("argv")
    if not isinstance(argv, list) or not argv or not all(isinstance(item, str) and item for item in argv):
        _log("argv must be a non-empty list of strings")
        return EXIT_BAD_CONFIG
    if any("\x00" in item for item in argv):
        _log("argv contains a NUL byte")
        return EXIT_BAD_CONFIG

    libc = ctypes.CDLL(None, use_errno=True)

    def mount(source: str | None, target: str, fstype: str | None, flags: int, data: str | None = None) -> bool:
        result = libc.mount(
            source.encode() if source else None,
            target.encode(),
            fstype.encode() if fstype else None,
            ctypes.c_ulong(flags),
            data.encode() if data else None,
        )
        if result != 0:
            errno = ctypes.get_errno()
            _log(f"mount failed for {target!r} (flags={flags}): {os.strerror(errno)}")
            return False
        return True

    failures: list[str] = []

    # 1. Stop mount events from propagating back to the host.
    if not mount(None, "/", None, MS_REC | MS_PRIVATE):
        failures.append("could not make the mount tree private")

    # 2. Make the whole filesystem read-only, recursively.
    if not mount("/", "/", None, MS_BIND | MS_REC):
        failures.append("could not bind /")
    if not mount(None, "/", None, MS_BIND | MS_REMOUNT | MS_RDONLY | MS_REC):
        failures.append("could not remount / read-only")

    # 3. Re-open only the granted writable roots. This must happen before any
    #    tmpfs is placed over /tmp, or paths under /tmp would be hidden first.
    for path in config.get("writable_roots") or ():
        if not isinstance(path, str) or not path.startswith("/"):
            failures.append(f"writable root {path!r} is not an absolute path")
            continue
        if not os.path.isdir(path):
            failures.append(f"writable root {path!r} does not exist")
            continue
        if not mount(path, path, None, MS_BIND | MS_REC):
            failures.append(f"could not bind {path!r}")
            continue
        if not mount(None, path, None, MS_BIND | MS_REMOUNT):
            failures.append(f"could not make {path!r} writable")

    # 4. Hide paths that must not even be readable.
    for path in config.get("hidden_paths") or ():
        if not isinstance(path, str) or not path.startswith("/") or not os.path.exists(path):
            continue
        if os.path.isdir(path):
            if not mount("tmpfs", path, "tmpfs", MS_NOSUID | MS_NODEV, "size=1M,mode=700"):
                failures.append(f"could not hide {path!r}")
        elif not mount("/dev/null", path, None, MS_BIND):
            failures.append(f"could not hide {path!r}")

    # 5. Isolated scratch tmpfs. When argv, cwd or a writable root already lives
    #    under /tmp (for instance pytest tmp_path), mounting over /tmp would hide
    #    the entrypoint, so scratch tmpfs is mounted on /var/tmp instead while /tmp
    #    remains read-only except for explicitly bound writable roots.
    writable = [item for item in (config.get("writable_roots") or ()) if isinstance(item, str)]
    referenced = [*argv, *writable, str(config.get("cwd") or "")]
    uses_tmp = any(item == "/tmp" or item.startswith("/tmp/") for item in referenced if item)
    tmpfs_mb = int(config.get("tmpfs_mb") or 32)
    scratch_target = "/var/tmp" if uses_tmp and os.path.isdir("/var/tmp") else "/tmp"
    if (not uses_tmp or scratch_target == "/var/tmp") and not mount(
        "tmpfs", scratch_target, "tmpfs", MS_NOSUID | MS_NODEV, f"size={tmpfs_mb}M,mode=1777"
    ):
        failures.append(f"could not mount tmpfs on {scratch_target}")

    # 6. Device nodes stay writable; /proc is remounted for the new PID namespace.
    for device in WRITABLE_DEVICES:
        if os.path.exists(device):
            mount(device, device, None, MS_BIND)
            mount(None, device, None, MS_BIND | MS_REMOUNT)
    if not mount("proc", "/proc", "proc", MS_NOSUID | MS_NODEV | MS_NOEXEC):
        failures.append("could not mount /proc")

    if failures:
        _log(f"setup failed ({len(failures)} problem(s)); the command was NOT executed")
        for item in failures:
            _log(f"  - {item}")
        return EXIT_SETUP_FAILED

    # 7. Resource limits, applied before the exec so the child inherits them.
    limits_applied: list[str] = []
    for name, value in (config.get("rlimits") or {}).items():
        limit = getattr(resource, name, None)
        if limit is None:
            _log(f"unknown rlimit {name!r}; ignored")
            continue
        try:
            resource.setrlimit(limit, (int(value), int(value)))
            limits_applied.append(name)
        except (ValueError, OSError) as exc:
            # A limit that cannot be set means the sandbox is weaker than asked
            # for, so the run is refused rather than continued unprotected.
            _log(f"could not apply {name}={value}: {exc}; refusing to exec")
            return EXIT_SETUP_FAILED

    # 8. Never allow the sandboxed process to gain privileges through setuid.
    if libc.prctl(PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) != 0:
        _log("could not set NO_NEW_PRIVS; refusing to exec")
        return EXIT_SETUP_FAILED

    environment = dict(config.get("env") or {})
    environment.setdefault("PATH", "/usr/local/bin:/usr/bin:/bin")
    environment["TMPDIR"] = scratch_target
    environment.pop(CONFIG_ENV_VAR, None)

    _log(f"setup complete: uid={os.getuid()} limits={','.join(limits_applied) or 'none'} exec={argv[0]}")
    try:
        os.execve(argv[0], argv, environment)
    except OSError as exc:
        _log(f"exec of {argv[0]!r} failed: {exc}")
        return EXIT_SETUP_FAILED
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
