"""The `nova-x` launcher: native window, local diagnostics, or reviewed CLI execution."""
from __future__ import annotations

import argparse
import json
import os
import sys
from collections.abc import Sequence

os.environ["NOVA_DESKTOP_MODE"] = "1"

from nova import __version__
from nova.desktop.runtime import DesktopRuntime


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="nova-x", description="NOVA X local-first Linux desktop assistant")
    parser.add_argument("--version", action="version", version=f"NOVA X {__version__}")
    subparsers = parser.add_subparsers(dest="action")
    subparsers.add_parser("desktop", help="Open the native desktop window (default)")
    subparsers.add_parser("diagnostics", help="Print local setup diagnostics as JSON")
    run = subparsers.add_parser("exec", help="Run one local command under the current user's permissions")
    run.add_argument("--cwd", default=None, help="Working directory (default: selected workspace)")
    run.add_argument("--timeout", type=int, default=120, help="Timeout in seconds (1–600)")
    run.add_argument("--privileged", action="store_true", help="Use pkexec/polkit after a second confirmation")
    run.add_argument("--shell", action="store_true", help="Interpret the remainder as a user-authored Bash script; always prompts")
    run.add_argument("command", nargs=argparse.REMAINDER, help="Program and arguments; use -- before a command beginning with a dash")
    return parser


def _ask_approval(summary: str) -> bool:
    if not sys.stdin.isatty():
        print("Approval required, but this process has no interactive terminal. Nothing was run.", file=sys.stderr)
        return False
    print("\nNOVA X approval request\n" + summary)
    try:
        answer = input("Run exactly this operation? [y/N] ").strip().lower()
    except (EOFError, KeyboardInterrupt):
        print("\nNo operation was run.", file=sys.stderr)
        return False
    return answer in {"y", "yes"}


def _run_cli(args: argparse.Namespace) -> int:
    runtime = DesktopRuntime()
    try:
        argv = list(args.command or [])
        if argv and argv[0] == "--":
            argv = argv[1:]
        if args.shell:
            script = " ".join(argv)
            if not script:
                print("Pass a Bash script after --.", file=sys.stderr)
                return 2
            outcome = runtime.async_service.submit(
                runtime.runner.run_manual_shell(script, args.cwd or runtime.active_workspace(), args.timeout, approved=False, source="cli_shell")
            ).result()
            if outcome.status == "approval_required":
                approved = _ask_approval(outcome.summary)
                if approved:
                    outcome = runtime.async_service.submit(
                        runtime.runner.run_manual_shell(script, args.cwd or runtime.active_workspace(), args.timeout, approved=True, source="cli_shell")
                    ).result()
        else:
            if not argv:
                print("Pass a program after -- (example: nova-x exec -- ls -la).", file=sys.stderr)
                return 2
            outcome = runtime.async_service.submit(
                runtime.runner.run(argv, cwd=args.cwd, timeout_seconds=args.timeout, approved=False, privileged=args.privileged, source="cli")
            ).result()
            if outcome.status == "approval_required":
                approved = _ask_approval(outcome.summary)
                if approved:
                    outcome = runtime.async_service.submit(
                        runtime.runner.run(argv, cwd=args.cwd, timeout_seconds=args.timeout, approved=True, privileged=args.privileged, source="cli")
                    ).result()
        data = outcome.data if isinstance(outcome.data, dict) else {}
        if data.get("stdout"):
            print(data["stdout"], end="" if data["stdout"].endswith("\n") else "\n")
        if data.get("stderr"):
            print(data["stderr"], end="" if data["stderr"].endswith("\n") else "\n", file=sys.stderr)
        print(f"NOVA X: {outcome.status} — {outcome.summary}", file=sys.stderr)
        if data.get("exit_code") is not None:
            print(f"Exit status: {data['exit_code']} · Duration: {data.get('duration_seconds', 0)}s · Local log: {data.get('log_path', 'unavailable')}", file=sys.stderr)
        return 0 if outcome.status == "success" else (124 if outcome.status == "error" and data.get("timed_out") else 1)
    except KeyboardInterrupt:
        print("\nInterrupted.", file=sys.stderr)
        return 130
    except Exception as exc:
        print(f"NOVA X CLI failed safely ({type(exc).__name__}).", file=sys.stderr)
        return 1
    finally:
        runtime.close()


def main(argv: Sequence[str] | None = None) -> int:
    parser = _parser()
    args = parser.parse_args(list(argv) if argv is not None else None)
    if args.action == "diagnostics":
        runtime = DesktopRuntime()
        try:
            print(json.dumps(runtime.diagnostics(), indent=2, ensure_ascii=False, default=str))
            return 0
        finally:
            runtime.close()
    if args.action == "exec":
        if not 1 <= args.timeout <= 600:
            parser.error("--timeout must be between 1 and 600 seconds")
        return _run_cli(args)
    try:
        from nova.desktop.app import launch
    except ImportError as exc:
        print(
            "The native Qt desktop is not installed. Install the `desktop` extra / Debian PySide6 packages, "
            "or use `nova-x exec` for reviewed local commands.\n"
            f"Import detail: {type(exc).__name__}",
            file=sys.stderr,
        )
        return 2
    return launch()


if __name__ == "__main__":
    raise SystemExit(main())
