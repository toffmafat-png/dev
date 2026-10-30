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
    subparsers.add_parser("setup", help="Run non-root Kali Linux environment & capability verification")
    hw = subparsers.add_parser("hardware", help="Search discovered Linux hardware & driver status (§149)")
    hw.add_argument("--query", default="", help="Optional hardware filter query")
    srvs = subparsers.add_parser("servers", help="List registered OpenSSH servers & health (§157)")
    srvs.add_argument("--audit", action="store_true", help="Run read-only OpenSSH health check across registered servers")
    tor_cmd = subparsers.add_parser("tor", help="Inspect or toggle Kali Linux Tor & Privacy Network Dashboard (§165.1/§165.8)")
    tor_group = tor_cmd.add_mutually_exclusive_group()
    tor_group.add_argument("--enable", action="store_true", help="Enable NOVA X Tor SOCKS5h integration")
    tor_group.add_argument("--disable", action="store_true", help="Immediately disable NOVA X Tor SOCKS5h integration")
    tor_cmd.add_argument("--dashboard", action="store_true", help="Include 6-component Privacy Network Dashboard")
    osint_cmd = subparsers.add_parser("osint", help="Run §165.3 Unified Multi-Source Search or §165.4 12-Step Research Assistant")
    osint_cmd.add_argument("query", help="Search query or research question")
    osint_cmd.add_argument("--research", action="store_true", help="Run full 12-step epistemic research report")
    gw_cmd = subparsers.add_parser("gateway", help="Inspect Cloud Frontier Gateway, Privacy Ledger, Offline Queue & llama.cpp RAM fit (§1–§11)")
    gw_cmd.add_argument("--transmissions", action="store_true", help="List secret-free cloud privacy transmission audit entries")
    gw_cmd.add_argument("--llama-check", default="", help="Check whether a compact quantized GGUF model fits host RAM")
    gw_cmd.add_argument("--local-project", default="", help="Mark a project key/path as local-only (blocks cloud providers)")
    kali_cmd = subparsers.add_parser("kali", help="Kali Linux Intelligence, Tool Mastery, Docs, App Learning, Labs & Troubleshooting (§181–§200)")
    kali_cmd.add_argument("--system", action="store_true", help="Inspect all 21 live Kali/Linux system dimensions")
    kali_cmd.add_argument("--search", default="", help="Search Kali/Linux tools for a natural-language objective")
    kali_cmd.add_argument("--profile", default="", help="Build 20-field verified profile for a Kali/Linux tool")
    kali_cmd.add_argument("--docs", default="", help="Retrieve 5-tier prioritized documentation for a tool")
    kali_cmd.add_argument("--learn", default="", help="Learn an unfamiliar local program (known vs inferred vs tested)")
    kali_cmd.add_argument("--troubleshoot", default="", help="Run 13-step Kali host diagnostic playbook")
    kali_cmd.add_argument("--lesson", default="", help="Generate Kali Training lesson for a track (e.g. kali_fundamentals)")
    kali_cmd.add_argument("--capability", default="", help="Query Capability Registry in natural language")
    cyber_cmd = subparsers.add_parser("cyber", help="Autonomous Cybersecurity, Vulnerability Research & Security Engineering Division (§201–§220)")
    cyber_cmd.add_argument("--capabilities", action="store_true", help="Print honest empirically tested vs optional security capabilities")
    cyber_cmd.add_argument("--register-scope", default="", help="Register a local development/testing directory or host target in scope")
    cyber_cmd.add_argument("--analyze-source", default="", help="Run SAST/SCA/Dockerfile security audit on an in-scope directory")
    cyber_cmd.add_argument("--inspect-sample", default="", help="Run static non-executing binary/artifact inspection on a file")
    cyber_cmd.add_argument("--research", default="", help="Research a CVE, CWE, or security advisory across 8 epistemic fields")
    cyber_cmd.add_argument("--tutor", default="", help="Generate an adaptive cybersecurity training module (17 disciplines)")
    acq_cmd = subparsers.add_parser("acquire", help="Autonomous Software Acquisition, Dependency Resolution & Environment Builder (§221–§228)")
    acq_cmd.add_argument("--discover", default="", help="Run 15-step intelligent software discovery for a capability or tool")
    acq_cmd.add_argument("--install", default="", help="Acquire, provenance-verify, test, and register a utility under policy")
    acq_cmd.add_argument("--managers", action="store_true", help="Discover installed package managers across all 7 ecosystems")
    acq_cmd.add_argument("--inventory", action="store_true", help="Generate verified software lifecycle inventory")
    mig_cmd = subparsers.add_parser("migrate", help="DEV Portable Identity, Backup, Offline Kit & Hardware-Aware Restore (§229–§234)")
    mig_cmd.add_argument("--backup", default="", help="Create & verify a backup kind (e.g. full_backup, config_only, memory_only)")
    mig_cmd.add_argument("--preview", default="", help="Preview compatibility & conflicts for a migration archive safely")
    mig_cmd.add_argument("--restore", default="", help="Restore a verified migration archive with pre-restore rollback backup")
    mig_cmd.add_argument("--offline-kit", action="store_true", help="Build a verified offline migration & reinstallation kit")
    worker = subparsers.add_parser("worker", help="Run optional user-level background goal/task worker")
    worker.add_argument("--once", action="store_true", help="Run one scheduled-goal check tick and exit")
    worker.add_argument("--poll-seconds", type=int, default=15, help="Polling interval in seconds (5–300)")
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


def _run_worker(once: bool, poll_seconds: int) -> int:
    import time

    runtime = DesktopRuntime()
    sup = runtime.platform.unified_os.worker
    interval = max(5, min(int(poll_seconds), 300))
    try:
        while True:
            tick = sup.tick_once("nova-x-cli-worker")
            for due in tick["dispatched_tasks"]:
                fut = runtime.async_service.submit(runtime.engine.run_task(due["task_id"]))
                fut.result(timeout=180)
            if once:
                print(json.dumps(tick, indent=2, default=str))
                return 0
            time.sleep(interval)
    except KeyboardInterrupt:
        return 0
    finally:
        try:
            sup.mark_stopped("nova-x-cli-worker")
        except Exception:
            pass
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
    if args.action == "setup":
        runtime = DesktopRuntime()
        try:
            diag = runtime.diagnostics()
            print(
                json.dumps(
                    {
                        "app": f"NOVA X {__version__}",
                        "root_required": False,
                        "running_as_root": bool(hasattr(os, "geteuid") and os.geteuid() == 0),
                        "checks": diag["checks"],
                        "architecture": diag["architecture"],
                    },
                    indent=2,
                    ensure_ascii=False,
                    default=str,
                )
            )
            return 0
        finally:
            runtime.close()
    if args.action == "worker":
        return _run_worker(bool(args.once), int(args.poll_seconds))
    if args.action == "hardware":
        runtime = DesktopRuntime()
        try:
            print(json.dumps(runtime.system_access.hardware.search(args.query, refresh=True), indent=2, default=str))
            return 0
        finally:
            runtime.close()
    if args.action == "servers":
        runtime = DesktopRuntime()
        try:
            payload = (
                runtime.system_access.servers.multi_server_audit()
                if args.audit
                else {"servers": runtime.system_access.servers.list_servers()}
            )
            print(json.dumps(payload, indent=2, default=str))
            return 0
        finally:
            runtime.close()
    if args.action == "tor":
        runtime = DesktopRuntime()
        try:
            if args.enable:
                runtime.privacy_intel.tor.update_config({"tor_enabled": True})
            elif args.disable:
                runtime.privacy_intel.tor.update_config({"tor_enabled": False})
            out: dict[str, object] = {"tor": runtime.privacy_intel.tor.detect_installation_and_status()}
            if args.dashboard:
                out["privacy_dashboard"] = runtime.privacy_intel.tor.privacy_dashboard()
            print(json.dumps(out, indent=2, default=str))
            return 0
        finally:
            runtime.close()
    if args.action == "osint":
        runtime = DesktopRuntime()
        try:
            guard = runtime.privacy_intel.check_ethics(args.query)
            if not guard["allowed"]:
                print(json.dumps({"ok": False, **guard}, indent=2), file=sys.stderr)
                return 1
            payload = (
                runtime.privacy_intel.research_assistant.conduct_research(args.query)
                if args.research
                else runtime.privacy_intel.search.search(args.query)
            )
            print(json.dumps(payload, indent=2, default=str))
            return 0
        finally:
            runtime.close()
    if args.action == "gateway":
        runtime = DesktopRuntime()
        try:
            if args.local_project:
                proj = runtime.hybrid_cloud.privacy_gateway.set_project_local_only(
                    args.local_project,
                    project_path=args.local_project,
                    local_only=True,
                )
                print(json.dumps({"local_only_project": proj}, indent=2, default=str))
                return 0
            if args.llama_check:
                fit = runtime.hybrid_cloud.llama_cpp_advisor.evaluate_candidate(args.llama_check)
                print(json.dumps(fit, indent=2, default=str))
                return 0
            if args.transmissions:
                rows = runtime.hybrid_cloud.db.list_cloud_transmissions(limit=50)
                print(json.dumps({"transmissions": rows}, indent=2, default=str))
                return 0
            print(json.dumps(runtime.hybrid_cloud.status_summary(), indent=2, default=str))
            return 0
        finally:
            runtime.close()
    if args.action == "kali":
        runtime = DesktopRuntime()
        try:
            ki = runtime.kali_intel
            if args.system:
                print(json.dumps(ki.system_model.get_or_refresh_model(force_refresh=True), indent=2, default=str))
                return 0
            if args.search:
                print(json.dumps(ki.tool_engine.search_tools_for_objective(args.search), indent=2, default=str))
                return 0
            if args.profile:
                print(json.dumps(ki.tool_engine.build_tool_profile(args.profile), indent=2, default=str))
                return 0
            if args.docs:
                print(json.dumps(ki.doc_engine.retrieve_prioritized_documentation(args.docs), indent=2, default=str))
                return 0
            if args.learn:
                print(json.dumps(ki.program_learner.learn_unfamiliar_program(args.learn), indent=2, default=str))
                return 0
            if args.troubleshoot:
                print(json.dumps(ki.troubleshooter.diagnose_13_steps(args.troubleshoot), indent=2, default=str))
                return 0
            if args.lesson:
                print(json.dumps(ki.training_academy.generate_lesson(args.lesson), indent=2, default=str))
                return 0
            if args.capability:
                print(json.dumps(ki.app_registry.query_capabilities(args.capability), indent=2, default=str))
                return 0
            print(json.dumps(ki.status_summary(), indent=2, default=str))
            return 0
        finally:
            runtime.close()
    if args.action == "cyber":
        runtime = DesktopRuntime()
        try:
            cy = runtime.cyber_division
            if args.capabilities:
                print(json.dumps(cy.honest_capability_statement(), indent=2, default=str))
                return 0
            if args.register_scope:
                sc = cy.scope_registry.register_scope(
                    name=f"CLI Scope: {args.register_scope}",
                    category="development_environment",
                    targets=[args.register_scope],
                    authorization_evidence="Explicit local operator CLI scope registration",
                )
                print(json.dumps({"scope": sc}, indent=2, default=str))
                return 0
            if args.analyze_source:
                print(json.dumps(cy.code_security.analyze_project(args.analyze_source), indent=2, default=str))
                return 0
            if args.inspect_sample:
                print(json.dumps(cy.re_forensics.inspect_sample_statically(args.inspect_sample), indent=2, default=str))
                return 0
            if args.research:
                print(json.dumps(cy.research_workbench.research_vulnerability(args.research), indent=2, default=str))
                return 0
            if args.tutor:
                print(json.dumps(cy.expert_tutor.generate_adaptive_module(args.tutor), indent=2, default=str))
                return 0
            print(json.dumps(cy.status_summary(), indent=2, default=str))
            return 0
        finally:
            runtime.close()
    if args.action == "acquire":
        runtime = DesktopRuntime()
        try:
            am = runtime.acquisition_migration
            if args.managers:
                print(json.dumps(am.pkg_managers.discover_installed_managers(), indent=2, default=str))
                return 0
            if args.inventory:
                print(json.dumps(am.lifecycle.generate_software_inventory(), indent=2, default=str))
                return 0
            if args.discover:
                print(json.dumps(am.discovery.discover_for_capability_or_tool(args.discover), indent=2, default=str))
                return 0
            if args.install:
                print(json.dumps(am.installer.acquire_verify_and_register(args.install, explicit_operator_approval=True), indent=2, default=str))
                return 0
            print(json.dumps(am.status_summary(), indent=2, default=str))
            return 0
        finally:
            runtime.close()
    if args.action == "migrate":
        runtime = DesktopRuntime()
        try:
            am = runtime.acquisition_migration
            if args.backup:
                print(json.dumps(am.backup.create_verified_backup(args.backup), indent=2, default=str))
                return 0
            if args.offline_kit:
                print(json.dumps(am.migration.create_migration_package(offline_kit=True, package_name="dev-offline-kit"), indent=2, default=str))
                return 0
            if args.preview:
                print(json.dumps(am.migration.restore_migration_package(args.preview, preview_only=True), indent=2, default=str))
                return 0
            if args.restore:
                print(json.dumps(am.migration.restore_migration_package(args.restore), indent=2, default=str))
                return 0
            print(json.dumps(am.status_summary(), indent=2, default=str))
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
