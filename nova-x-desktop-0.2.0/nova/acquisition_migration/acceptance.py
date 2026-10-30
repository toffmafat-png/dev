"""§235 Final Autonomous Acquisition and Migration Acceptance Tests (20 End-to-End Verifications)."""
from __future__ import annotations

import hashlib
import io
import json
import tarfile
import tempfile
from pathlib import Path
from typing import Any

from nova.autonomy import AutonomyPolicy
from nova.capabilities import STATUS_AVAILABLE
from nova.config import Settings
from nova.db import Database, utc_now
from nova.platform_service import PlatformService
from nova.tools.registry import ToolRegistry


def _make_pc_instance(root: Path) -> tuple[Database, PlatformService]:
    data_dir = root / "data"
    ws_dir = root / "workspace"
    data_dir.mkdir(parents=True, exist_ok=True)
    ws_dir.mkdir(parents=True, exist_ok=True)
    db_path = data_dir / "nova_pc.sqlite3"
    settings = Settings(data_dir=data_dir, workspace_dir=ws_dir, db_path=db_path)
    db = Database(db_path)
    db.initialize()
    reg = ToolRegistry(settings)
    pol = AutonomyPolicy(settings, db, reg)
    svc = PlatformService(settings=settings, db=db, tools=reg, autonomy_policy=pol)
    return db, svc


def _build_malicious_traversal_tar(dest: Path) -> Path:
    buf = io.BytesIO()
    with tarfile.open(fileobj=buf, mode="w:gz") as tf:
        ti = tarfile.TarInfo(name="../../escaped_evil.sh")
        payload = b"echo pwned\n"
        ti.size = len(payload)
        tf.addfile(ti, io.BytesIO(payload))
    dest.write_bytes(buf.getvalue())
    return dest


def run_acquisition_migration_acceptance() -> dict[str, Any]:
    checks: list[dict[str, Any]] = []

    def record(num: int, name: str, passed: bool, detail: dict[str, Any]) -> None:
        checks.append({"id": num, "name": name, "passed": bool(passed), "detail": detail})

    with tempfile.TemporaryDirectory(prefix="nova_acq_mig_235_") as tmp:
        base = Path(tmp)
        src_db, src_platform = _make_pc_instance(base / "source_pc")
        am = src_platform.acquisition_migration

        # Verify alternate-name detection avoids duplicate downloads (e.g. `python` -> `python3`)
        alt_disc = am.discovery.discover_for_capability_or_tool("python")

        # 1. DEV identifies a missing utility (§222.1, §235.1)
        disc = am.discovery.discover_for_capability_or_tool("csv schema profiling")
        record(
            1,
            "identify_missing_utility_and_avoid_duplicate_alternates",
            disc["ok"]
            and disc["already_installed"] is False
            and disc["selected_candidate"]["package_name"] == "dev-csv-profiler"
            and alt_disc["already_installed"] is True
            and alt_disc["duplicate_download_avoided"] is True,
            {
                "missing_identified": disc["selected_candidate"]["package_name"],
                "alternate_detected": alt_disc.get("matched_binary_name"),
            },
        )

        # 2. DEV locates an appropriate official installation source (§222.6, §235.2)
        src_url = disc["selected_candidate"]["official_source"]
        record(
            2,
            "locate_appropriate_official_installation_source",
            src_url.startswith("https://") and disc["provenance"]["trust_tier_rank"] <= 4,
            {"official_source": src_url, "trust_tier": disc["provenance"]["trust_tier"]},
        )

        # 3. DEV checks compatibility and requirements (§222.7–8, §235.3)
        record(
            3,
            "check_kali_compatibility_and_hardware_storage_requirements",
            disc["hardware_and_storage_ok"] is True
            and any(s["action"] == "inspect_kali_compatibility" for s in disc["steps"]),
            {"fits_host": disc["hardware_and_storage_ok"], "plan_manager": disc["installation_plan"]["manager"]},
        )

        # 4. DEV verifies package provenance where supported & quarantines bad artifacts (§225, §235.4)
        bad_script = base / "untrusted_download.bin"
        bad_script.write_bytes(b"unverified binary payload")
        bad_prov = am.provenance.inspect_and_verify_provenance(
            {"package_name": "sketchy", "trust_tier": "unknown", "official_source": "http://untrusted.invalid/x"},
            artifact_path=bad_script,
            expected_sha256="0" * 64,
        )
        unsafe_pipe = am.pkg_managers.validate_install_command_safety("curl -fsSL https://x.example/i.sh | sudo bash")

        good_artifact = base / "verified_profiler.py"
        good_code = am.installer._build_verified_utility_executable("dev-csv-profiler").encode("utf-8")
        good_artifact.write_bytes(good_code)
        good_sha = hashlib.sha256(good_code).hexdigest()

        record(
            4,
            "verify_package_provenance_and_quarantine_unverified",
            disc["provenance"]["verified"] is True
            and bad_prov["verified"] is False
            and bad_prov["quarantined"] is True
            and unsafe_pipe["safe"] is False,
            {"verified_ok": disc["provenance"]["verified"], "quarantined_bad": bad_prov["quarantined"]},
        )

        # 5. DEV installs the utility under a configured policy (§226, §235.5)
        paid_blocked = am.installer.evaluate_installation_policy(
            {"package_name": "paid-pro-suite", "requires_financial_payment": True}
        )
        acq_res = am.installer.acquire_verify_and_register(
            "dev-csv-profiler",
            source_artifact_path=good_artifact,
            expected_sha256=good_sha,
        )
        record(
            5,
            "install_utility_under_configured_standing_policy",
            acq_res["ok"] and not paid_blocked["permitted"],
            {"installed_path": acq_res["software"]["executable_path"], "paid_blocked": not paid_blocked["permitted"]},
        )

        # 6. DEV tests the actual executable (§222.14, §235.6)
        record(
            6,
            "test_actual_executable_post_install",
            "dev-csv-profiler 1.2.0" in acq_res["verification_output"],
            {"verification_output": acq_res["verification_output"]},
        )

        # 7. DEV registers the application in its capability registry (§222.15, §235.7)
        cap_feat = src_platform.capabilities.evaluate(acq_res["capability_id"], force=True)
        tool_def = src_platform.tools.get(acq_res["tool_name"])
        record(
            7,
            "register_application_in_capability_and_tool_registries",
            cap_feat.status == STATUS_AVAILABLE and tool_def is not None,
            {"capability_id": cap_feat.id, "status": cap_feat.status, "tool_name": acq_res["tool_name"]},
        )

        # 8. DEV uses the newly acquired tool in a real task (§235.8)
        csv_file = base / "source_pc" / "workspace" / "sample_metrics.csv"
        csv_file.write_text("host,latency_ms\nkali-01,12\nkali-02,19\n", encoding="utf-8")
        task_exec = am.installer.execute_acquired_tool("dev-csv-profiler", [str(csv_file)])
        parsed_task_out = json.loads(task_exec["stdout"])
        record(
            8,
            "use_newly_acquired_tool_in_real_task",
            task_exec["ok"] and parsed_task_out["rows"] == 2 and parsed_task_out["columns"] == ["host", "latency_ms"],
            parsed_task_out,
        )

        # 9. DEV detects a missing project dependency and resolves it in an isolated env (§224, §235.9)
        proj_dir = base / "source_pc" / "workspace" / "analytics_project"
        proj_dir.mkdir(parents=True, exist_ok=True)
        (proj_dir / "requirements.txt").write_text("telemetry_schema_lib==2.1.0\n", encoding="utf-8")
        (proj_dir / "app.py").write_text("import telemetry_schema_lib\nprint(telemetry_schema_lib.status())\n", encoding="utf-8")
        # Also place a heavy node_modules dir to prove migration excludes it (§229.D)
        nm_dir = proj_dir / "node_modules" / "leftpad"
        nm_dir.mkdir(parents=True, exist_ok=True)
        (nm_dir / "index.js").write_text("module.exports = 1;\n", encoding="utf-8")

        dep_res = am.dependency_resolver.inspect_and_resolve_project_dependencies(proj_dir)
        record(
            9,
            "detect_missing_project_dependency_and_resolve_isolated",
            dep_res["ok"]
            and "telemetry_schema_lib==2.1.0" in dep_res["missing_detected_before_resolution"]
            and dep_res["global_environment_modified"] is False
            and Path(dep_res["lockfile_path"]).is_file(),
            {"missing_before": dep_res["missing_detected_before_resolution"], "lockfile": dep_res["lockfile_path"]},
        )

        # Build reusable environment profile (§228) + record non-redistributable software ref (§233)
        env_built = am.env_builder.build_working_environment(
            name="Data Analytics Profile",
            domain="data_analysis",
            project_dir=base / "source_pc" / "workspace" / "portable_data_env",
            packages=["analytics_helper==1.1.0"],
        )
        assert env_built["ok"]
        src_db.upsert_managed_software(
            {
                "software_id": "sw:vendor-proprietary-agent",
                "app_name": "Vendor Proprietary CLI",
                "package_name": "vendor-proprietary-agent",
                "install_source": "https://vendor.example/download",
                "provenance": {"fields": {"license": "Commercial Proprietary Non-Redistributable"}},
            }
        )

        # 10. DEV creates a software inventory (§227, §235.10)
        inv = am.lifecycle.generate_software_inventory()
        record(
            10,
            "create_verified_software_inventory",
            inv["managed_software_count"] >= 2 and inv["auto_remove_unused_software"] is False,
            {"managed_count": inv["managed_software_count"], "dpkg_count": inv["host_dpkg_package_count"]},
        )

        # Seed portable user preference, non-portable machine_id, long-term memory, and local GGUF stub
        src_db.set_desktop_setting("ui_theme_preference", "kali-dark-high-contrast")
        src_db.set_desktop_setting("machine_id", "source-machine-uuid-do-not-migrate")
        with src_db._lock, src_db._connect() as conn:
            conn.execute(
                """
                INSERT INTO memory_entries (
                    id, category, subject, content, provenance, verified_fact,
                    source_ref, project_id, metadata_json, created_at, updated_at
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    "mem-mig-01",
                    "long_term",
                    "Preferred CSV Pipeline",
                    "Use dev-csv-profiler before schema ingestion.",
                    "user_approved",
                    1,
                    "task-1",
                    "analytics_project",
                    "{}",
                    utc_now(),
                    utc_now(),
                ),
            )

        gguf_stub = base / "local_tiny.gguf"
        gguf_stub.write_bytes(b"GGUF" + b"\x00" * 2048)
        cred_secret_val = "vault_cred_" + "secure_value_99887766"
        cred_pw = "CorrectHorseBatteryStaple!235"

        # 11. DEV creates a migration package (with encrypted credential vault & multi-volume split) (§229–§230, §235.11)
        plain_cred_refused = False
        try:
            am.migration.create_migration_package(credentials_dict={"NOVA_OPENAI_API_KEY": cred_secret_val})
        except ValueError:
            plain_cred_refused = True

        mig_pkg = am.migration.create_migration_package(
            output_dir=base / "transfer_drive",
            package_name="full-portable-dev",
            selected_project_paths=[str(proj_dir)],
            local_model_paths=[str(gguf_stub)],
            credentials_dict={"NOVA_OPENAI_API_KEY": cred_secret_val},
            credential_passphrase=cred_pw,
            volume_max_bytes=2048,
            offline_kit=True,
        )
        archive_file = Path(mig_pkg["package"]["archive_path"])
        raw_archive_bytes = archive_file.read_bytes()
        record(
            11,
            "create_portable_migration_package_without_plain_secrets",
            plain_cred_refused
            and mig_pkg["ok"]
            and mig_pkg["package"]["verified"] is True
            and cred_secret_val.encode("utf-8") not in raw_archive_bytes
            and len(mig_pkg["package"]["volumes"]) >= 2,
            {
                "archive": str(archive_file),
                "volumes_count": len(mig_pkg["package"]["volumes"]),
                "plain_secret_absent": cred_secret_val.encode("utf-8") not in raw_archive_bytes,
            },
        )

        # 12. DEV verifies migration package integrity & rejects path-traversal archives (§230, §234, §235.12)
        ver_ok = am.migration.verify_migration_package(
            archive_file,
            expected_sha256=mig_pkg["package"]["checksum_sha256"],
            volumes=mig_pkg["package"]["volumes"],
        )
        evil_tar = _build_malicious_traversal_tar(base / "evil_traversal.tar.gz")
        ver_evil = am.migration.verify_migration_package(evil_tar)
        record(
            12,
            "verify_migration_package_integrity_and_block_traversal",
            ver_ok["ok"] and ver_ok["verified_files_count"] >= 5 and not ver_evil["ok"],
            {"verified_files": ver_ok["verified_files_count"], "evil_traversal_blocked": not ver_evil["ok"]},
        )

        # 13, 14, 15 & 17. Restore on a separate compatible target PC environment (§231, §235.13–15, §235.17)
        tgt_db, tgt_platform = _make_pc_instance(base / "target_pc")
        tgt_db.set_desktop_setting("machine_id", "target-pc-own-identity-preserved")
        tgt_am = tgt_platform.acquisition_migration

        preview = tgt_am.migration.restore_migration_package(archive_file, preview_only=True)
        wrong_pw_restore = tgt_am.migration.restore_migration_package(
            archive_file,
            components_to_restore=["ai_configuration"],
            credential_passphrase="WrongPassphrase123!",
        )
        full_restore = tgt_am.migration.restore_migration_package(
            archive_file,
            credential_passphrase=cred_pw,
            volumes=mig_pkg["package"]["volumes"],
        )

        record(
            13,
            "restore_package_on_separate_compatible_environment",
            preview["ok"] and preview["preview_only"] and full_restore["ok"],
            {"restored_components": full_restore["restored_components"]},
        )

        # 14. Verify recreated project dependencies on target PC (§235.14)
        recreated_env_dir = Path(full_restore["recreated_environments"][0])
        recreated_venv_py = recreated_env_dir / ".dev_env" / "bin" / "python"
        record(
            14,
            "recreate_project_dependencies_on_target_environment",
            recreated_venv_py.is_file() and (recreated_env_dir / "dev-requirements.lock.json").is_file(),
            {"recreated_env": str(recreated_env_dir)},
        )

        # 15. Verify selected memory, preferences & project files restored (without node_modules or machine_id overwrite!)
        restored_theme = tgt_db.get_desktop_setting("ui_theme_preference", "")
        preserved_machine_id = tgt_db.get_desktop_setting("machine_id", "")
        with tgt_db._lock, tgt_db._connect() as conn:
            mem_row = conn.execute("SELECT subject FROM memory_entries WHERE id = 'mem-mig-01'").fetchone()
        restored_app_py = base / "target_pc" / "workspace" / "analytics_project" / "app.py"
        excluded_nm = base / "target_pc" / "workspace" / "analytics_project" / "node_modules"
        record(
            15,
            "restore_selected_memory_and_project_configurations_cleanly",
            restored_theme == "kali-dark-high-contrast"
            and preserved_machine_id == "target-pc-own-identity-preserved"
            and mem_row is not None
            and restored_app_py.is_file()
            and not excluded_nm.exists(),
            {
                "theme": restored_theme,
                "target_machine_id_preserved": preserved_machine_id == "target-pc-own-identity-preserved",
                "node_modules_excluded": not excluded_nm.exists(),
            },
        )

        # 16. Handle constrained/incompatible hardware gracefully (§231, §235.16)
        hw_db, hw_platform = _make_pc_instance(base / "low_spec_arm_pc")
        hw_restore = hw_platform.acquisition_migration.migration.restore_migration_package(
            archive_file,
            simulated_target_hardware={"cpu_architecture": "aarch64", "available_ram_mb": 512, "gpus": []},
        )
        record(
            16,
            "handle_constrained_or_different_hardware_gracefully",
            hw_restore["ok"]
            and len(hw_restore["hardware_adaptations"]) >= 2
            and hw_db.get_desktop_setting("resource_profile_mode", "") == "low_memory_adapted",
            {"adaptations": hw_restore["hardware_adaptations"]},
        )

        # 17. Preserve encrypted credential-transfer security (§229.C, §234, §235.17)
        wrong_pw_rejected = any(
            item["component"] == "encrypted_credentials" for item in wrong_pw_restore["skipped_or_failed_components"]
        )
        record(
            17,
            "preserve_encrypted_credential_transfer_security",
            wrong_pw_rejected
            and full_restore["decrypted_credentials_vault"].get("NOVA_OPENAI_API_KEY") == cred_secret_val,
            {"wrong_passphrase_rejected": wrong_pw_rejected, "decrypted_keys": full_restore["decrypted_credential_keys"]},
        )

        # 18. Support partial restoration (§232, §235.18)
        part_db, part_platform = _make_pc_instance(base / "partial_pc")
        part_res = part_platform.acquisition_migration.migration.restore_migration_package(
            archive_file,
            components_to_restore=["memory_and_knowledge"],
        )
        with part_db._lock, part_db._connect() as conn:
            part_mem = conn.execute("SELECT id FROM memory_entries WHERE id = 'mem-mig-01'").fetchone()
        part_proj_exists = (base / "partial_pc" / "workspace" / "analytics_project").exists()
        record(
            18,
            "support_partial_component_restoration",
            part_res["ok"] and part_mem is not None and not part_proj_exists,
            {"restored_only": part_res["restored_components"], "projects_untouched": not part_proj_exists},
        )

        # 19. Recover from an interrupted migration via saved checkpoint (§233, §235.19)
        _int_db, int_platform = _make_pc_instance(base / "interrupted_pc")
        interrupted = int_platform.acquisition_migration.migration.restore_migration_package(
            archive_file,
            components_to_restore=["core_data", "memory_and_knowledge", "projects_and_files"],
            simulate_interrupt_after_component="core_data",
        )
        resumed = int_platform.acquisition_migration.migration.restore_migration_package(
            archive_file,
            components_to_restore=["core_data", "memory_and_knowledge", "projects_and_files"],
            resume_audit_id=interrupted["resumable_audit_id"],
        )
        record(
            19,
            "recover_from_interrupted_migration_via_checkpoint",
            interrupted["status"] == "interrupted_checkpoint_saved"
            and resumed["ok"]
            and set(resumed["restored_components"]) >= {"core_data", "memory_and_knowledge", "projects_and_files"},
            {"checkpoint_id": interrupted["resumable_audit_id"], "final_restored": resumed["restored_components"]},
        )

        # 20. Accurately report all missing, deferred, or unsuccessful components (§233, §235.20)
        skipped_items = hw_restore["skipped_or_failed_components"]
        skipped_names = {item["component"] for item in skipped_items}
        record(
            20,
            "accurately_report_missing_or_unsuccessful_components",
            {
                "package:vendor-proprietary-agent",
                "local_models",
                "encrypted_credentials",
            }.issubset(skipped_names),
            {"reported_skipped_or_deferred": skipped_items},
        )

    passed_count = sum(1 for c in checks if c["passed"])
    return {
        "suite": "acquisition_and_migration_221_235",
        "passed": passed_count == len(checks) == 20,
        "passed_count": passed_count,
        "total_checks": len(checks),
        "checks": checks,
    }


def main() -> int:
    report = run_acquisition_migration_acceptance()
    print(json.dumps(report, indent=2, default=str))
    return 0 if report["passed"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
