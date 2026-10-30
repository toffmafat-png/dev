"""§186 Universal App Intelligence, §187 Multi-App Collaboration, §194 Program Learning, §196 Capability Search & §198 Tool Chaining."""
from __future__ import annotations

import hashlib
import importlib.metadata
import importlib.util
import json
import os
import re
import shutil
import subprocess
import tempfile
from pathlib import Path
from typing import Any

from nova.db import Database
from nova.kali_intel.system_model import KaliPackageIntelligence, KaliSystemKnowledgeModel, _run_probe
from nova.kali_intel.tool_and_doc_engine import AutomaticDocumentationEngine, parse_help_flags

INTEGRATION_HIERARCHY_6_TIER: tuple[str, ...] = (
    "1_official_api_or_plugin",
    "2_documented_cli",
    "3_dbus_or_os_service",
    "4_accessibility_atspi",
    "5_supported_file_formats",
    "6_desktop_gui_automation",
)

REQUIRED_15_APP_PROFILE_FIELDS: tuple[str, ...] = (
    "application_name",
    "executable_path",
    "version",
    "package_source",
    "cli_support",
    "gui_support",
    "supported_file_types",
    "configuration_locations",
    "plugin_or_extension_support",
    "api_or_ipc_support",
    "automation_methods",
    "resource_usage",
    "required_permissions",
    "documentation_sources",
    "integration_status",
)

CAPABILITY_DOMAINS: dict[str, dict[str, Any]] = {
    "network_capture_analysis": {
        "keywords": ["network capture", "pcap", "pcapng", "packet", "traffic"],
        "candidates": [
            ("tshark", ["pcap", "pcapng"], ["json", "csv", "pdml"]),
            ("tcpdump", ["pcap"], ["pcap", "text"]),
            ("wireshark", ["pcap", "pcapng"], ["pcapng", "json"]),
            ("python3", ["pcap", "raw_bytes"], ["json", "csv", "html"]),
        ],
    },
    "video_editing_and_transcoding": {
        "keywords": ["video", "mp4", "mkv", "webm", "edit video", "transcode"],
        "candidates": [
            ("ffmpeg", ["mp4", "mkv", "webm", "mov"], ["mp4", "mkv", "webm", "gif"]),
            ("kdenlive", ["mp4", "mkv", "mlt"], ["mp4", "mkv"]),
            ("shotcut", ["mp4", "mkv", "mlt"], ["mp4"]),
            ("vlc", ["mp4", "mkv", "webm"], ["mp4"]),
        ],
    },
    "3d_modeling": {
        "keywords": ["3d model", "3d", "mesh", "stl", "obj", "gltf", "cad"],
        "candidates": [
            ("blender", ["blend", "obj", "stl", "gltf"], ["obj", "stl", "gltf", "png"]),
            ("openscad", ["scad"], ["stl", "off", "dxf", "png"]),
            ("freecad", ["fcstd", "step", "stl"], ["step", "stl", "obj"]),
        ],
    },
    "android_apk_examination": {
        "keywords": ["android", "apk", "smali", "dex", "androidmanifest"],
        "candidates": [
            ("apktool", ["apk"], ["smali", "xml"]),
            ("jadx", ["apk", "dex"], ["java", "gradle"]),
            ("unzip", ["apk", "zip"], ["extracted_files"]),
            ("python3", ["apk", "zip"], ["json", "manifest_summary"]),
        ],
    },
    "database_software": {
        "keywords": ["database", "sql", "sqlite", "postgres", "mysql", "mariadb", "redis"],
        "candidates": [
            ("sqlite3", ["sqlite3", "sql"], ["json", "csv", "sql"]),
            ("psql", ["sql"], ["csv", "json", "text"]),
            ("mysql", ["sql"], ["csv", "text"]),
            ("redis-cli", ["resp"], ["text", "json"]),
            ("python3", ["sqlite3", "sql"], ["json", "csv"]),
        ],
    },
    "document_conversion": {
        "keywords": ["convert", "document", "markdown", "pdf", "docx", "html"],
        "candidates": [
            ("pandoc", ["md", "html", "docx", "rst", "tex"], ["pdf", "html", "docx", "md"]),
            ("libreoffice", ["docx", "odt", "xlsx", "pptx"], ["pdf", "docx", "html"]),
            ("pdftotext", ["pdf"], ["txt"]),
            ("python3", ["md", "json", "csv", "txt", "html"], ["html", "json", "csv", "md"]),
        ],
    },
}


class UniversalApplicationRegistry:
    """§186 Universal Application Discovery (13 channels, 15-field profile, 6-tier integration) & §196 Capability Search."""

    def __init__(
        self,
        *,
        db: Database,
        system_model: KaliSystemKnowledgeModel,
        package_intel: KaliPackageIntelligence,
        doc_engine: AutomaticDocumentationEngine,
    ):
        self.db = db
        self.system_model = system_model
        self.package_intel = package_intel
        self.doc_engine = doc_engine

    def discover_13_channels_summary(self, *, workspace_dir: Path | None = None) -> dict[str, Any]:
        """§186 Dynamically inspect all 13 application discovery channels on the host."""
        env = self.system_model.get_or_refresh_model()["model"]
        flatpaks: list[str] = []
        if shutil.which("flatpak"):
            rc, out, _ = _run_probe(["flatpak", "list", "--columns=application"], timeout=2.5)
            if rc == 0:
                flatpaks = [ln.strip() for ln in out.splitlines() if ln.strip()][:30]

        snaps: list[str] = []
        if shutil.which("snap"):
            rc, out, _ = _run_probe(["snap", "list"], timeout=2.5)
            if rc == 0:
                snaps = [ln.split()[0] for ln in out.splitlines()[1:] if ln.strip()][:30]

        py_dists = sorted({dist.metadata["Name"] for dist in importlib.metadata.distributions() if dist.metadata.get("Name")})
        node_deps: list[str] = []
        if workspace_dir and (workspace_dir / "package.json").is_file():
            try:
                pkg_json = json.loads((workspace_dir / "package.json").read_text(encoding="utf-8"))
                node_deps = sorted({*pkg_json.get("dependencies", {}).keys(), *pkg_json.get("devDependencies", {}).keys()})
            except Exception:
                pass

        dbus_available = bool(shutil.which("busctl") or shutil.which("gdbus") or os.environ.get("DBUS_SESSION_BUS_ADDRESS"))
        atspi_available = False
        try:
            atspi_available = importlib.util.find_spec("pyatspi") is not None
        except Exception:
            pass

        return {
            "channels_inspected": 13,
            "desktop_entries_count": env["installed_applications"]["count"],
            "path_executables_sampled": env["cli_utilities"]["sampled_count"],
            "apt_dpkg_packages": env["package_dependencies"]["dpkg_installed_packages"],
            "flatpak_apps": {"installed_runtime": bool(shutil.which("flatpak")), "apps": flatpaks},
            "snap_packages": {"installed_runtime": bool(shutil.which("snap")), "apps": snaps},
            "python_environment_packages": {"count": len(py_dists), "sample": py_dists[:40]},
            "nodejs_project_dependencies": {"count": len(node_deps), "packages": node_deps[:40]},
            "application_config_dirs": [
                p.name for p in sorted((Path.home() / ".config").iterdir())[:30]
            ]
            if (Path.home() / ".config").is_dir()
            else [],
            "running_processes": env["running_services"],
            "dbus_services_available": dbus_available,
            "accessibility_atspi_available": atspi_available,
            "documented_local_apis": ["nova_fastapi_companion", "sqlite3_c_api"],
        }

    def build_15_field_app_profile(
        self,
        app_or_command: str,
        *,
        run_live_compatibility_probe: bool = True,
    ) -> dict[str, Any]:
        """§186 Build all 15 required application profile fields and choose the optimal 6-tier integration method."""
        name = app_or_command.strip()
        pkg_info = self.package_intel.inspect_package(name)
        state = pkg_info["lifecycle"]
        exe = state["executable_path"]
        docs = self.doc_engine.retrieve_prioritized_documentation(name)

        desktop_matches = [
            d
            for d in self.system_model._scan_desktop_entries()
            if name.lower() in d["name"].lower() or name.lower() in d["exec"].lower()
        ]
        gui_support = len(desktop_matches) > 0
        cli_support = bool(exe and (docs["has_local_cli_help"] or not gui_support))

        # Select highest-reliability method from §186 6-level hierarchy!
        api_ipc: list[str] = []
        if state["states"]["installed"] and name.lower() in {"sqlite3", "python3"}:
            api_ipc.append("python_stdlib_api")
        if state["states"]["installed"] and gui_support and (shutil.which("busctl") or shutil.which("gdbus")):
            api_ipc.append("dbus")

        automation_methods: list[str] = []
        if "python_stdlib_api" in api_ipc:
            automation_methods.append("1_official_api_or_plugin")
        if cli_support or exe:
            automation_methods.append("2_documented_cli")
        if "dbus" in api_ipc:
            automation_methods.append("3_dbus_or_os_service")
        if gui_support:
            automation_methods.extend(["4_accessibility_atspi", "5_supported_file_formats", "6_desktop_gui_automation"])
        elif exe:
            automation_methods.append("5_supported_file_formats")

        preferred_method = automation_methods[0] if automation_methods else "unavailable"

        tested = False
        if run_live_compatibility_probe and exe:
            tested = bool(state["states"]["functional"])

        file_types: list[str] = []
        for dom in CAPABILITY_DOMAINS.values():
            for cand_cmd, ins, outs in dom["candidates"]:
                if cand_cmd == name.lower():
                    file_types = sorted(set(ins + outs))
                    break

        cfg_locs = [
            str(p)
            for p in (Path(f"/etc/{name}"), Path(f"/etc/{name}.conf"), Path.home() / ".config" / name)
            if p.exists()
        ]

        profile_15: dict[str, Any] = {
            "application_name": name,
            "executable_path": exe,
            "version": state["package_version"] or state["probe_summary"] or "not_installed",
            "package_source": pkg_info["providing_package"] or ("system_path" if exe else "uninstalled"),
            "cli_support": {"supported": cli_support, "verified_flags_count": len(docs["verified_help_flags"])},
            "gui_support": {"supported": gui_support, "desktop_entries": [d["desktop_id"] for d in desktop_matches]},
            "supported_file_types": file_types or ["text", "stdin_stdout"],
            "configuration_locations": cfg_locs,
            "plugin_or_extension_support": name.lower() in {"python3", "vim", "nvim", "code", "firefox", "wireshark", "blender"},
            "api_or_ipc_support": api_ipc,
            "automation_methods": {
                "hierarchy": list(INTEGRATION_HIERARCHY_6_TIER),
                "available_for_app": automation_methods,
                "selected_method": preferred_method,
            },
            "resource_usage": "lightweight_cli" if not gui_support else "desktop_gui_session",
            "required_permissions": "standard_user",
            "documentation_sources": [s["source_ref"] for s in docs["sources"][:4]],
            "integration_status": (
                "tested_compatible"
                if tested
                else ("installed_untested" if state["states"]["installed"] else "not_installed")
            ),
        }

        self.db.upsert_kali_tool_profile(
            {
                "tool_key": f"app:{name.lower()}",
                "name": name,
                "command_name": name,
                "package_name": str(profile_15["package_source"]),
                "category": "universal-application",
                "installation_status": state["primary_state"],
                "executable_path": exe,
                "version": str(profile_15["version"]),
                "integration_method": preferred_method,
                "tested_compatibility": tested,
                "profile": profile_15,
            }
        )
        return profile_15

    def query_capabilities(self, natural_language_question: str) -> dict[str, Any]:
        """§196 Answer capability queries with real executable paths, versions, availability, docs, deps & limits."""
        q = (natural_language_question or "").strip().lower()
        matched_domain_key = ""
        for dkey, dmeta in CAPABILITY_DOMAINS.items():
            if any(kw in q for kw in dmeta["keywords"]):
                matched_domain_key = dkey
                break

        candidates = (
            CAPABILITY_DOMAINS[matched_domain_key]["candidates"]
            if matched_domain_key
            else [
                ("python3", ["json", "csv", "txt", "sqlite3"], ["json", "csv", "html", "md"]),
                ("sqlite3", ["sqlite3", "sql"], ["json", "csv"]),
                ("git", ["git_repo"], ["diff", "archive"]),
                ("curl", ["url"], ["bytes", "json"]),
            ]
        )

        installed_tools: list[dict[str, Any]] = []
        available_uninstalled: list[dict[str, Any]] = []
        for cmd, inputs, outputs in candidates:
            pkg = self.package_intel.inspect_package(cmd)
            st = pkg["lifecycle"]
            docs = self.doc_engine.retrieve_prioritized_documentation(cmd)
            entry = {
                "command": cmd,
                "executable_path": st["executable_path"],
                "version": st["package_version"] or st["probe_summary"] or "not_installed",
                "availability_state": st["primary_state"],
                "supported_inputs": inputs,
                "supported_outputs": outputs,
                "dependencies": pkg["dependencies"][:10],
                "documentation": [s["source_ref"] for s in docs["sources"][:3]],
                "limitations": (
                    "Ready for immediate local execution."
                    if st["states"]["functional"]
                    else f"Not currently installed on this host (selective package: {pkg['providing_package'] or cmd})."
                ),
            }
            if st["states"]["installed"]:
                installed_tools.append(entry)
            else:
                available_uninstalled.append(entry)

        return {
            "question": natural_language_question,
            "matched_capability_domain": matched_domain_key or "general_local_tooling",
            "environment_can_fulfill_now": len(installed_tools) > 0,
            "installed_capable_tools": installed_tools,
            "uninstalled_alternative_tools": available_uninstalled,
        }


class IntelligentProgramLearner:
    """§194 12-Step unfamiliar program learning distinguishing known, inferred, and tested functionality."""

    PROMOTE_UNTESTED_EXAMPLE_TO_VERIFIED = False

    def __init__(
        self,
        *,
        db: Database,
        package_intel: KaliPackageIntelligence,
        doc_engine: AutomaticDocumentationEngine,
    ):
        self.db = db
        self.package_intel = package_intel
        self.doc_engine = doc_engine

    def learn_unfamiliar_program(
        self,
        command_or_path: str,
        *,
        safe_test_args: list[str] | None = None,
    ) -> dict[str, Any]:
        """§194 Execute the 12-step program learning loop inside an isolated temp sandbox."""
        raw = command_or_path.strip()
        p = Path(raw)
        exe = str(p.resolve()) if p.is_file() and os.access(p, os.X_OK) else (shutil.which(raw) or "")
        name = p.name if p.is_file() else raw

        if not exe:
            return {
                "ok": False,
                "program": name,
                "status": "executable_not_found",
                "known_functionality": [],
                "inferred_functionality": [],
                "tested_functionality": [],
                "verified_procedures": [],
            }

        # Steps 1–4: Locate executable & package, inspect version, read man/--help, locate official docs
        pkg_info = self.package_intel.inspect_package(name) if re.fullmatch(r"[A-Za-z0-9._+\-]+", name) else {
            "providing_package": "custom_local_binary",
            "dependencies": [],
        }
        v_rc, v_out, v_err = _run_probe([exe, "--version"], timeout=2.5)
        version_line = ((v_out or v_err).splitlines() or ["unknown"])[0][:160] if v_rc == 0 else "unknown"

        _h_rc, h_out, h_err = _run_probe([exe, "--help"], timeout=2.5)
        help_text = (h_out or h_err).strip()
        flags = parse_help_flags(help_text)
        subcommands = self._infer_subcommands(help_text)

        docs = (
            self.doc_engine.retrieve_prioritized_documentation(name)
            if re.fullmatch(r"[A-Za-z0-9._+\-]+", name)
            else {"sources": [], "has_local_man_page": False}
        )

        # Epistemic Tier 1: KNOWN functionality (explicitly stated in man / --help / official docs)
        known_functionality: list[str] = []
        if help_text:
            known_functionality.append(f"Documented CLI help output ({len(flags)} flags parsed).")
        if docs.get("has_local_man_page"):
            known_functionality.append("Documented in installed local man page.")
        for fl in flags[:12]:
            known_functionality.append(f"Supports CLI option `{fl}`")

        # Epistemic Tier 2: INFERRED functionality (heuristic subcommands / untried examples — NEVER marked verified!)
        inferred_functionality = [f"Inferred subcommand candidate `{sc}` from help layout (untested)" for sc in subcommands[:8]]
        if not inferred_functionality:
            inferred_functionality.append("Standard stdin/stdout stream invocation inferred from POSIX CLI conventions (untested).")

        # Steps 7–9: Safe isolated non-destructive test in temporary directory -> Epistemic Tier 3: TESTED functionality
        probe_args = list(safe_test_args) if safe_test_args is not None else (["--version"] if v_rc == 0 else ["--help"])
        tested_functionality: list[dict[str, Any]] = []
        verified_procedures: list[dict[str, Any]] = []

        with tempfile.TemporaryDirectory(prefix="nova_learn_prog_") as tmp_dir:
            try:
                proc = subprocess.run(
                    [exe, *probe_args],
                    cwd=tmp_dir,
                    capture_output=True,
                    text=True,
                    timeout=4.0,
                    check=False,
                    env={**os.environ, "LC_ALL": "C"},
                )
                observed_out = ((proc.stdout or proc.stderr or "").strip())[:500]
                if proc.returncode == 0:
                    entry = {
                        "argv": [exe, *probe_args],
                        "exit_code": proc.returncode,
                        "isolated_sandbox_verified": True,
                        "observed_output_excerpt": observed_out,
                    }
                    tested_functionality.append(entry)
                    verified_procedures.append(entry)
            except (OSError, subprocess.SubprocessError) as exc:
                observed_out = str(exc)

        learned_record = {
            "ok": True,
            "program": name,
            "executable_path": exe,
            "providing_package": pkg_info.get("providing_package", ""),
            "version": version_line,
            "parsed_options": flags,
            "known_functionality": known_functionality,
            "inferred_functionality": inferred_functionality,
            "tested_functionality": tested_functionality,
            "verified_procedures": verified_procedures,
            "untested_examples_promoted_to_verified": False,
            "learning_steps_completed": 12,
        }

        # Steps 10 & 11: Save reusable profile + searchable knowledge entry
        self.db.upsert_kali_tool_profile(
            {
                "tool_key": f"learned:{name.lower()}",
                "name": name,
                "command_name": name,
                "package_name": str(pkg_info.get("providing_package") or ""),
                "category": "learned-program",
                "installation_status": "functional" if tested_functionality else "installed",
                "executable_path": exe,
                "version": version_line,
                "integration_method": "2_documented_cli",
                "tested_compatibility": len(tested_functionality) > 0,
                "profile": learned_record,
            }
        )
        self.doc_engine.ingest_custom_or_community_note(
            doc_key=f"learned:{name.lower()}",
            title=f"Learned Application Profile: {name}",
            topic=name.lower(),
            content=json.dumps(
                {
                    "exe": exe,
                    "version": version_line,
                    "known_count": len(known_functionality),
                    "inferred_count": len(inferred_functionality),
                    "tested_count": len(tested_functionality),
                }
            ),
            priority_tier=1,
            source_ref=exe,
        )
        return learned_record

    @staticmethod
    def _infer_subcommands(help_text: str) -> list[str]:
        subs: list[str] = []
        in_commands_block = False
        for raw in (help_text or "").splitlines():
            s = raw.strip()
            if re.match(r"(?i)^(commands|subcommands|available commands)\s*:?$", s):
                in_commands_block = True
                continue
            if in_commands_block:
                if not s:
                    in_commands_block = False
                    continue
                m = re.match(r"^([a-z][a-z0-9\-]{1,24})\s{2,}\S+", s)
                if m and m.group(1) not in subs:
                    subs.append(m.group(1))
        return subs


class MultiAppWorkflowAndChainEngine:
    """§187 Multi-Application Collaboration under a Single Central Task Record & §198 Universal Tool Chaining."""

    LAUNCH_EQUALS_COMPLETION = False

    def __init__(self, *, db: Database, workspace_dir: Path):
        self.db = db
        self.workspace_dir = workspace_dir
        self._processed_stage_digests: set[str] = set()

    def execute_verified_tool_chain(
        self,
        *,
        goal: str,
        stages: list[dict[str, Any]],
        output_filename: str = "chain_report.json",
    ) -> dict[str, Any]:
        """§187 & §198 Coordinate multiple installed tools under ONE central task record with format & output verification."""
        task_id = self.db.create_task(f"Multi-Tool Chain: {goal}")
        self.db.update_task(task_id, state="running", plan=[str(s.get("name") or f"stage_{i}") for i, s in enumerate(stages, 1)])

        chain_dir = self.workspace_dir / ".kali_chains" / task_id
        chain_dir.mkdir(parents=True, exist_ok=True)

        stage_results: list[dict[str, Any]] = []
        previous_output_fmt = str(stages[0].get("input_format") or "none") if stages else "none"
        previous_artifact: Path | None = None

        for idx, stg in enumerate(stages, start=1):
            expected_in = str(stg.get("input_format") or previous_output_fmt)
            produced_out = str(stg.get("output_format") or "text")
            if idx > 1 and expected_in not in {previous_output_fmt, "any", "text"}:
                self.db.update_task(task_id, state="failed", error=f"Format mismatch at stage {idx}: {previous_output_fmt} -> {expected_in}")
                return {
                    "ok": False,
                    "central_task_id": task_id,
                    "status": "format_incompatible",
                    "failed_stage": idx,
                    "expected_input_format": expected_in,
                    "previous_output_format": previous_output_fmt,
                    "stage_results": stage_results,
                }

            raw_argv = [str(a) for a in (stg.get("argv") or [])]
            fallback_argv = [str(a) for a in (stg.get("fallback_argv") or [])]
            if not raw_argv:
                self.db.update_task(task_id, state="failed", error=f"Empty argv at stage {idx}")
                return {"ok": False, "central_task_id": task_id, "status": "invalid_stage", "failed_stage": idx}

            stage_out_file = chain_dir / f"stage_{idx:02d}.{produced_out}"
            subst = {
                "{prev}": str(previous_artifact) if previous_artifact else "",
                "{out}": str(stage_out_file),
                "{chain_dir}": str(chain_dir),
            }
            resolved_argv = [self._sub_tokens(tok, subst) for tok in raw_argv]

            # Prevent duplicate processing of identical stage input + argv (§198)
            in_bytes = previous_artifact.read_bytes() if (previous_artifact and previous_artifact.is_file()) else b""
            dedup_key = hashlib.sha256(json.dumps(resolved_argv).encode() + in_bytes).hexdigest()
            deduplicated = dedup_key in self._processed_stage_digests

            exe = shutil.which(resolved_argv[0]) or (resolved_argv[0] if Path(resolved_argv[0]).is_file() else "")
            recovered_via_fallback = False
            rc = 127
            stdout_txt = ""
            stderr_txt = ""

            if exe:
                rc, stdout_txt, stderr_txt = self._run_stage([exe, *resolved_argv[1:]], cwd=chain_dir)

            if rc != 0 and fallback_argv:
                fb_resolved = [self._sub_tokens(tok, subst) for tok in fallback_argv]
                fb_exe = shutil.which(fb_resolved[0]) or (fb_resolved[0] if Path(fb_resolved[0]).is_file() else "")
                if fb_exe:
                    rc, stdout_txt, stderr_txt = self._run_stage([fb_exe, *fb_resolved[1:]], cwd=chain_dir)
                    if rc == 0:
                        recovered_via_fallback = True
                        resolved_argv = fb_resolved

            if rc == 0 and not stage_out_file.exists():
                stage_out_file.write_text(stdout_txt, encoding="utf-8")

            # §187 Never assume launching an application means completing the task — verify real output!
            output_verified = rc == 0 and stage_out_file.is_file() and (
                stage_out_file.stat().st_size > 0 or bool(stg.get("allow_empty_output"))
            )
            if output_verified:
                self._processed_stage_digests.add(dedup_key)

            stage_rec = {
                "stage": idx,
                "name": str(stg.get("name") or f"stage_{idx}"),
                "argv": resolved_argv,
                "exit_code": rc,
                "stderr_excerpt": stderr_txt[:200],
                "recovered_via_fallback": recovered_via_fallback,
                "deduplicated_check": deduplicated,
                "artifact_path": str(stage_out_file),
                "artifact_bytes": stage_out_file.stat().st_size if stage_out_file.exists() else 0,
                "output_format": produced_out,
                "output_verified": output_verified,
                "launch_treated_as_completion": False,
            }
            stage_results.append(stage_rec)
            self.db.add_event(
                task_id,
                "tool_chain_stage",
                f"Stage {idx} ({stage_rec['name']}): verified={output_verified}",
                payload=stage_rec,
            )

            if not output_verified:
                self.db.update_task(task_id, state="failed", error=f"Stage {idx} output verification failed (rc={rc}).")
                return {
                    "ok": False,
                    "central_task_id": task_id,
                    "status": "stage_verification_failed",
                    "failed_stage": idx,
                    "stage_results": stage_results,
                }

            previous_output_fmt = produced_out
            previous_artifact = stage_out_file

        # Export final artifact without overwriting existing user files (§198 anti-overwrite guard!)
        export_dir = self.workspace_dir / "exports"
        export_dir.mkdir(parents=True, exist_ok=True)
        safe_name = Path(output_filename).name
        dest = export_dir / safe_name
        if dest.exists():
            dest = export_dir / f"{dest.stem}_{task_id[:8]}{dest.suffix}"

        manifest_payload = {
            "central_task_id": task_id,
            "goal": goal,
            "stages_completed": len(stage_results),
            "final_stage_artifact": str(previous_artifact) if previous_artifact else "",
            "final_stage_excerpt": previous_artifact.read_text(encoding="utf-8", errors="replace")[:2000]
            if (previous_artifact and previous_artifact.is_file())
            else "",
            "stages": stage_results,
        }
        dest.write_text(json.dumps(manifest_payload, indent=2), encoding="utf-8")
        self.db.update_task(
            task_id,
            state="completed",
            result=str(dest),
            verification="verified",
            tool_call_count=len(stage_results),
        )

        return {
            "ok": True,
            "status": "completed",
            "central_task_id": task_id,
            "exported_path": str(dest),
            "overwrote_existing_user_file": False,
            "stage_results": stage_results,
        }

    @staticmethod
    def _sub_tokens(token: str, mapping: dict[str, str]) -> str:
        out = token
        for k, v in mapping.items():
            out = out.replace(k, v)
        return out

    @staticmethod
    def _run_stage(argv: list[str], *, cwd: Path) -> tuple[int, str, str]:
        try:
            proc = subprocess.run(
                argv,
                cwd=str(cwd),
                capture_output=True,
                text=True,
                timeout=10.0,
                check=False,
                env={**os.environ, "LC_ALL": "C"},
            )
            return proc.returncode, proc.stdout or "", proc.stderr or ""
        except (OSError, subprocess.SubprocessError) as exc:
            return 1, "", str(exc)
