"""§229 Portable Identity, §230 Universal Format, §231 Hardware-Aware Restore, §232 Backup & §233–§234 Offline/Security."""
from __future__ import annotations

import hashlib
import json
import platform as py_platform
import shutil
import tempfile
from pathlib import Path
from typing import Any, ClassVar

from nova import __version__
from nova.acquisition_migration.crypto_and_archive import (
    MIGRATION_FORMAT_VERSION,
    ArchiveSecurityError,
    MigrationVaultCipher,
    UniversalMigrationArchiveCodec,
)
from nova.acquisition_migration.discovery_and_provenance import (
    UniversalPackageManagerDiscovery,
)
from nova.acquisition_migration.installer_lifecycle_env import (
    AutonomousEnvironmentBuilder,
    SoftwareLifecycleManager,
)
from nova.db import Database, utc_now
from nova.kali_intel.system_model import KaliSystemKnowledgeModel

MIGRATION_6_SECTIONS: tuple[str, ...] = (
    "core_data",
    "memory_and_knowledge",
    "ai_configuration",
    "software_and_environments",
    "projects_and_files",
    "local_models",
)

BACKUP_11_KINDS: tuple[str, ...] = (
    "full_backup",
    "config_only",
    "memory_only",
    "project_only",
    "model_only",
    "software_inventory_only",
    "selected_app_backup",
    "encrypted_complete_backup",
    "incremental_backup",
    "scheduled_backup",
    "pre_update_restore_point",
)

# §231 Non-portable machine/hardware-specific keys that MUST NEVER overwrite target machine identity
NON_PORTABLE_MACHINE_SETTING_KEYS: frozenset[str] = frozenset(
    {
        "workspace_roots",
        "active_workspace",
        "machine_id",
        "systemd_machine_id",
        "network_interface_names",
        "gpu_driver_config",
        "device_paths",
        "boot_parameters",
    }
)

# §234 Sensitive filename patterns excluded unless explicitly placed in encrypted vault
SENSITIVE_CREDENTIAL_FILENAMES: frozenset[str] = frozenset(
    {
        "id_rsa",
        "id_ed25519",
        "cookies.sqlite",
        ".netrc",
        ".env",
        "credentials.json",
    }
)


class DevMigrationManager:
    """§229–§231 & §233–§234 DEV Portable Identity, Offline Kit, Hardware-Aware Restore & Security Engine."""

    ALLOW_PLAIN_CREDENTIAL_EXPORT = False
    ALLOW_REMOTE_PROPRIETARY_WEIGHT_DOWNLOAD = False

    def __init__(
        self,
        *,
        db: Database,
        workspace_dir: Path,
        system_model: KaliSystemKnowledgeModel,
        pkg_managers: UniversalPackageManagerDiscovery,
        lifecycle_mgr: SoftwareLifecycleManager,
        env_builder: AutonomousEnvironmentBuilder,
    ):
        self.db = db
        self.workspace_dir = workspace_dir
        self.system_model = system_model
        self.pkg_managers = pkg_managers
        self.lifecycle_mgr = lifecycle_mgr
        self.env_builder = env_builder

    # ------------------------------------------------- §229, §230 & §233 Export

    def estimate_migration_storage(
        self,
        *,
        selected_project_paths: list[str] | None = None,
        local_model_paths: list[str] | None = None,
    ) -> dict[str, Any]:
        """§233 Estimate total required storage before creating a migration package or offline kit."""
        proj_bytes = 0
        for raw_p in selected_project_paths or []:
            p = Path(raw_p)
            if p.exists():
                proj_bytes += self._measure_filtered_bytes(p)

        model_bytes = 0
        for raw_m in local_model_paths or []:
            mp = Path(raw_m)
            if mp.is_file():
                model_bytes += mp.stat().st_size

        metadata_overhead = 256 * 1024
        estimated_uncompressed = proj_bytes + model_bytes + metadata_overhead
        free_bytes = shutil.disk_usage(self.workspace_dir).free
        return {
            "project_files_bytes": proj_bytes,
            "local_models_bytes": model_bytes,
            "metadata_overhead_bytes": metadata_overhead,
            "estimated_total_bytes": estimated_uncompressed,
            "destination_free_bytes": free_bytes,
            "sufficient_storage": free_bytes > int(estimated_uncompressed * 1.25),
        }

    def create_migration_package(
        self,
        *,
        output_dir: Path | str | None = None,
        package_name: str = "dev-migration",
        sections: list[str] | None = None,
        selected_project_paths: list[str] | None = None,
        local_model_paths: list[str] | None = None,
        credentials_dict: dict[str, str] | None = None,
        credential_passphrase: str = "",
        encrypt_entire_archive_passphrase: str = "",
        compression: str = "auto",
        volume_max_bytes: int = 0,
        offline_kit: bool = False,
        backup_kind: str = "full_backup",
        since_timestamp: str = "",
    ) -> dict[str, Any]:
        """§229, §230, §232 & §233 Build & cryptographically verify a portable DEV migration package."""
        chosen_sections = list(sections or MIGRATION_6_SECTIONS)
        invalid = [s for s in chosen_sections if s not in MIGRATION_6_SECTIONS]
        if invalid:
            raise ValueError(f"Unsupported migration sections {invalid}. Valid: {MIGRATION_6_SECTIONS}")

        if credentials_dict and not credential_passphrase and not encrypt_entire_archive_passphrase:
            raise ValueError(
                "Refused: DEV never places API keys or private credentials into an unencrypted migration archive (§229.C / §234)."
            )

        storage_est = self.estimate_migration_storage(
            selected_project_paths=selected_project_paths,
            local_model_paths=local_model_paths if "local_models" in chosen_sections else None,
        )
        if not storage_est["sufficient_storage"]:
            return {"ok": False, "status": "insufficient_disk_storage", "estimate": storage_est}

        dest_dir = Path(output_dir).resolve() if output_dir else (self.workspace_dir / "migrations")
        dest_dir.mkdir(parents=True, exist_ok=True)

        env_snap = self.system_model.get_or_refresh_model()["model"]
        mgr_snap = self.pkg_managers.discover_installed_managers()
        sw_inv = self.lifecycle_mgr.generate_software_inventory()

        with tempfile.TemporaryDirectory(prefix="nova_mig_stage_") as tmp_stage:
            stage = Path(tmp_stage)

            # A. Core application data
            if "core_data" in chosen_sections:
                core_payload = self._export_core_data(since_timestamp=since_timestamp)
                self._write_json(stage / "core_data" / "core_state.json", core_payload)

            # B. Memory and knowledge
            if "memory_and_knowledge" in chosen_sections:
                mem_payload = self._export_memory_and_knowledge(since_timestamp=since_timestamp)
                self._write_json(stage / "memory_and_knowledge" / "memory_bundle.json", mem_payload)

            # C. AI configuration (secrets stripped; optional separate encrypted vault!)
            credentials_mode = "excluded"
            if "ai_configuration" in chosen_sections:
                ai_payload = self._export_ai_configuration_secret_free()
                self._write_json(stage / "ai_configuration" / "ai_profiles.json", ai_payload)

            if credentials_dict:
                pw = credential_passphrase or encrypt_entire_archive_passphrase
                vault_bytes = MigrationVaultCipher.encrypt_bytes(
                    json.dumps(credentials_dict, sort_keys=True).encode("utf-8"),
                    pw,
                )
                vault_file = stage / "credentials" / "credentials.vault.enc"
                vault_file.parent.mkdir(parents=True, exist_ok=True)
                vault_file.write_bytes(vault_bytes)
                credentials_mode = "encrypted_vault"

            # D. Software and development environments
            non_redistributable_refs: list[dict[str, str]] = []
            if "software_and_environments" in chosen_sections:
                env_profiles = self.db.list_environment_profiles()
                for sw in sw_inv["managed_software"]:
                    lic = str(sw.get("provenance", {}).get("fields", {}).get("license", ""))
                    if "proprietary" in lic.lower() or "commercial" in lic.lower():
                        non_redistributable_refs.append(
                            {
                                "package_name": sw["package_name"],
                                "install_source": sw["install_source"],
                                "reason": "non_redistributable_license_preserved_as_reference",
                            }
                        )
                    elif offline_kit and sw.get("executable_path") and Path(sw["executable_path"]).is_file():
                        off_dest = stage / "offline_kit" / "binaries" / Path(sw["executable_path"]).name
                        off_dest.parent.mkdir(parents=True, exist_ok=True)
                        shutil.copy2(sw["executable_path"], off_dest)

                self._write_json(
                    stage / "software_and_environments" / "software_and_envs.json",
                    {
                        "software_inventory": sw_inv["managed_software"],
                        "environment_profiles": [p["portable_spec"] for p in env_profiles],
                        "acquisition_policy": self.db.get_software_acquisition_policy(),
                        "deferred_online_recreation_references": non_redistributable_refs,
                    },
                )

            # E. Selected projects and personal files (skipping heavy caches/node_modules & raw credential files)
            copied_projects: list[str] = []
            if "projects_and_files" in chosen_sections:
                proj_stage_root = stage / "projects_and_files"
                sources = [Path(p).resolve() for p in (selected_project_paths or []) if Path(p).exists()]
                if not sources:
                    # Include lightweight custom project dirs inside workspace (excluding internal dirs)
                    for child in sorted(self.workspace_dir.iterdir()) if self.workspace_dir.is_dir() else []:
                        if child.name in {"migrations", "backups", "quarantine", "acquired_software", "forensic_preservation"}:
                            continue
                        sources.append(child)
                for src_item in sources:
                    self._copy_filtered_tree(src_item, proj_stage_root / src_item.name, since_timestamp=since_timestamp)
                    copied_projects.append(src_item.name)

            # F. Optional local AI models (separately selectable; never downloading cloud proprietary weights!)
            copied_models: list[dict[str, Any]] = []
            if "local_models" in chosen_sections and local_model_paths:
                mod_root = stage / "local_models"
                mod_root.mkdir(parents=True, exist_ok=True)
                for raw_mp in local_model_paths:
                    mp = Path(raw_mp).resolve()
                    if mp.is_file():
                        shutil.copy2(mp, mod_root / mp.name)
                        copied_models.append({"filename": mp.name, "size_bytes": mp.stat().st_size})
                self._write_json(mod_root / "models_metadata.json", {"models": copied_models, "remote_weights_downloaded": False})

            # Restore & Offline instructions (§230 & §233)
            restore_md = (
                f"# DEV Universal Migration & Restore Guide (`{MIGRATION_FORMAT_VERSION}`)\n\n"
                "1. Copy this archive (and `.partNNN` volumes if split) to the target Linux/Kali machine.\n"
                "2. Preview safely: `nova-x migrate --preview <archive-path>`\n"
                "3. Restore selected or full state: `nova-x migrate --restore <archive-path>`\n"
                "4. Machine-specific drivers, `/etc/machine-id`, and interface names are never overwritten.\n"
            )
            (stage / "RESTORE_INSTRUCTIONS.md").write_text(restore_md, encoding="utf-8")

            # Compute SHA-256 of every staged payload file BEFORE writing manifest.json
            file_checksums: dict[str, str] = {}
            for f in sorted(stage.rglob("*")):
                if f.is_file():
                    rel = f.relative_to(stage).as_posix()
                    file_checksums[rel] = hashlib.sha256(f.read_bytes()).hexdigest()

            source_os_info = {
                "system": py_platform.system(),
                "release": py_platform.release(),
                "distribution": env_snap["distribution"],
                "cpu_architecture": py_platform.machine(),
            }
            hw_info = {
                "hardware_and_drivers": env_snap["hardware_and_drivers"],
                "disk_and_memory_resources": env_snap["disk_and_memory_resources"],
                "gpus": [p for p in env_snap["hardware_and_drivers"].get("pci_sample", []) if "vga" in p.lower() or "3d" in p.lower()],
                "package_managers": mgr_snap["available_managers"],
            }

            manifest = {
                "format_version": MIGRATION_FORMAT_VERSION,
                "dev_version": __version__,
                "created_at": utc_now(),
                "backup_kind": backup_kind,
                "offline_kit": bool(offline_kit),
                "source_os": source_os_info,
                "hardware_snapshot": hw_info,
                "selections": {
                    "sections": chosen_sections,
                    "projects": copied_projects,
                    "local_models": [m["filename"] for m in copied_models],
                },
                "credentials_mode": credentials_mode,
                "deferred_online_recreation_references": non_redistributable_refs,
                "compatibility_requirements": {
                    "min_python": "3.11",
                    "supported_os": ["Linux"],
                    "recommended_ram_mb": 2048 if copied_models else 512,
                },
                "restore_instructions_file": "RESTORE_INSTRUCTIONS.md",
                "file_checksums": file_checksums,
            }
            self._write_json(stage / "manifest.json", manifest)

            stamp = utc_now().replace(":", "").replace(".", "")[:15]
            base_out = dest_dir / f"{package_name}-{stamp}"
            packed = UniversalMigrationArchiveCodec.pack_staging_directory(
                stage,
                base_out,
                compression=compression,
                encrypt_passphrase=encrypt_entire_archive_passphrase,
                volume_max_bytes=volume_max_bytes,
            )

        # §232 Never claim success until archive, checksums, and manifest pass independent round-trip verification!
        verification = self.verify_migration_package(
            packed["archive_path"],
            expected_sha256=packed["checksum_sha256"],
            decrypt_passphrase=encrypt_entire_archive_passphrase,
            volumes=packed["volumes"] or None,
        )
        if not verification["ok"]:
            return {"ok": False, "status": "post_pack_verification_failed", "verification": verification}

        saved_pkg = self.db.upsert_migration_package(
            {
                "archive_path": packed["archive_path"],
                "format_version": MIGRATION_FORMAT_VERSION,
                "compression": packed["compression"],
                "backup_kind": backup_kind,
                "source_os": source_os_info,
                "hardware_snapshot": hw_info,
                "selections": manifest["selections"],
                "encrypted": packed["encrypted"],
                "credentials_mode": credentials_mode,
                "volumes": packed["volumes"],
                "checksum_sha256": packed["checksum_sha256"],
                "verified": True,
                "offline_kit": offline_kit,
                "manifest": manifest,
            }
        )
        self.db.record_migration_audit(
            {
                "operation": "export_offline_kit" if offline_kit else f"export_{backup_kind}",
                "package_id": saved_pkg["package_id"],
                "status": "verified",
                "detail": {"archive_path": packed["archive_path"], "verified_files": verification["verified_files_count"]},
            }
        )
        return {
            "ok": True,
            "package": saved_pkg,
            "verification": verification,
            "storage_estimate": storage_est,
        }

    def verify_migration_package(
        self,
        archive_path: Path | str,
        *,
        expected_sha256: str = "",
        decrypt_passphrase: str = "",
        volumes: list[dict[str, Any]] | None = None,
    ) -> dict[str, Any]:
        """§230, §232 & §234 Verify archive integrity, path-traversal safety, manifest & per-file SHA-256."""
        with tempfile.TemporaryDirectory(prefix="nova_mig_ver_") as tmp_v:
            try:
                res = UniversalMigrationArchiveCodec.verify_and_extract_untrusted_archive(
                    Path(archive_path),
                    Path(tmp_v),
                    expected_archive_sha256=expected_sha256,
                    decrypt_passphrase=decrypt_passphrase,
                    volumes=volumes,
                )
                return {"ok": True, **res}
            except ArchiveSecurityError as exc:
                return {"ok": False, "verified": False, "error": str(exc)}

    # ------------------------------------------------- §231, §233 & §234 Restore

    def inspect_target_compatibility(
        self,
        manifest: dict[str, Any],
        *,
        simulated_target_hardware: dict[str, Any] | None = None,
    ) -> dict[str, Any]:
        """§231 Compare all 11 compatibility dimensions & generate graceful hardware adaptations."""
        env_now = self.system_model.get_or_refresh_model()["model"]
        mgr_now = self.pkg_managers.discover_installed_managers()

        target_arch = str((simulated_target_hardware or {}).get("cpu_architecture") or py_platform.machine())
        target_ram_mb = int(
            (simulated_target_hardware or {}).get("available_ram_mb")
            or env_now["disk_and_memory_resources"].get("mem_total_mb")
            or 2048
        )
        target_disk_gb = float((simulated_target_hardware or {}).get("free_disk_gb") or round(shutil.disk_usage(self.workspace_dir).free / (1024**3), 2))
        host_gpus = [p for p in env_now["hardware_and_drivers"].get("pci_sample", []) if "vga" in p.lower() or "3d" in p.lower()]
        target_gpus = (
            list(simulated_target_hardware["gpus"])
            if simulated_target_hardware and "gpus" in simulated_target_hardware
            else host_gpus
        )

        src_arch = str(manifest.get("source_os", {}).get("cpu_architecture") or target_arch)
        adaptations: list[str] = []
        warnings: list[str] = []

        if src_arch != target_arch:
            adaptations.append(
                f"CPU architecture changed (`{src_arch}` -> `{target_arch}`): skipping compiled host binaries and rebuilding project environments natively."
            )
        if not target_gpus and manifest.get("hardware_snapshot", {}).get("gpus"):
            adaptations.append("No discrete GPU detected on target PC: switching local AI/media settings to CPU-optimized mode.")
        if target_ram_mb < 4096:
            adaptations.append(
                f"Target RAM ({target_ram_mb} MB) is constrained: capping concurrent workers to 1 and disabling heavy local GGUF preload."
            )
            warnings.append("High-memory local models (>3 GB) exceed target available RAM and will remain unloaded by default.")

        return {
            "compatible": target_disk_gb >= 0.2,
            "dimensions_compared": {
                "1_cpu_architecture": {"source": src_arch, "target": target_arch},
                "2_operating_system": {"source": manifest.get("source_os", {}).get("system"), "target": py_platform.system()},
                "3_kali_or_distro_version": {
                    "source": manifest.get("source_os", {}).get("distribution", {}).get("pretty_name"),
                    "target": env_now["distribution"]["pretty_name"],
                },
                "4_kernel_version": {"target": py_platform.release()},
                "5_available_ram_mb": target_ram_mb,
                "6_disk_space_gb": target_disk_gb,
                "7_gpu_availability": len(target_gpus) > 0,
                "8_installed_drivers": len(env_now.get("loaded_kernel_modules_sample", [])),
                "9_package_managers": mgr_now["available_managers"],
                "10_development_toolchains": env_now["development_environments"],
                "11_non_portable_identity_blocked": sorted(NON_PORTABLE_MACHINE_SETTING_KEYS),
            },
            "hardware_adaptations": adaptations,
            "limitations_reported": warnings,
        }

    def restore_migration_package(
        self,
        archive_path: Path | str,
        *,
        components_to_restore: list[str] | None = None,
        credential_passphrase: str = "",
        decrypt_archive_passphrase: str = "",
        preview_only: bool = False,
        overwrite_existing_files: bool = True,
        create_pre_restore_backup: bool = True,
        simulated_target_hardware: dict[str, Any] | None = None,
        simulate_interrupt_after_component: str = "",
        resume_audit_id: str = "",
        volumes: list[dict[str, Any]] | None = None,
    ) -> dict[str, Any]:
        """§231, §233 & §234 Validate, preview, partially/fully restore, resume interrupted runs & adapt hardware."""
        already_completed: list[str] = []
        rollback_pkg_id = ""
        if resume_audit_id:
            prev_aud = self.db.get_migration_audit(resume_audit_id)
            if prev_aud is not None:
                already_completed = list(prev_aud["restored_components"])
                rollback_pkg_id = str(prev_aud.get("rollback_backup_id") or "")

        with tempfile.TemporaryDirectory(prefix="nova_mig_rest_") as tmp_ext:
            ext_dir = Path(tmp_ext)
            try:
                verified = UniversalMigrationArchiveCodec.verify_and_extract_untrusted_archive(
                    Path(archive_path),
                    ext_dir,
                    decrypt_passphrase=decrypt_archive_passphrase,
                    volumes=volumes,
                )
            except ArchiveSecurityError as exc:
                aud = self.db.record_migration_audit(
                    {
                        "operation": "restore",
                        "status": "rejected_security_validation",
                        "preview_only": preview_only,
                        "skipped_or_failed": [{"component": "archive", "reason": str(exc)}],
                    }
                )
                return {"ok": False, "status": "rejected_security_validation", "error": str(exc), "audit": aud}

            manifest = verified["manifest"]
            compat = self.inspect_target_compatibility(manifest, simulated_target_hardware=simulated_target_hardware)

            available_sections = list(manifest.get("selections", {}).get("sections") or [])
            requested = [c for c in (components_to_restore or available_sections) if c in available_sections]

            # Detect duplicate/existing project files before writing (§234)
            duplicate_paths: list[str] = []
            proj_ext = ext_dir / "projects_and_files"
            if proj_ext.is_dir():
                for f in proj_ext.rglob("*"):
                    if f.is_file():
                        rel = f.relative_to(proj_ext)
                        if (self.workspace_dir / rel).exists():
                            duplicate_paths.append(rel.as_posix())

            if preview_only:
                aud = self.db.record_migration_audit(
                    {
                        "operation": "restore_preview",
                        "status": "preview_ready",
                        "preview_only": True,
                        "hardware_adaptations": compat["hardware_adaptations"],
                        "detail": {"would_restore": requested, "existing_conflicts": duplicate_paths},
                    }
                )
                return {
                    "ok": True,
                    "preview_only": True,
                    "would_restore_components": requested,
                    "duplicate_or_overwrite_candidates": duplicate_paths,
                    "compatibility": compat,
                    "audit": aud,
                }

            # Create automatic pre-restore backup for one-call rollback (§234)
            if create_pre_restore_backup and not rollback_pkg_id:
                pre_bak = self.create_migration_package(
                    output_dir=self.workspace_dir / "backups" / "pre_restore",
                    package_name="pre-restore-rollback",
                    sections=["core_data", "memory_and_knowledge", "projects_and_files"],
                    backup_kind="pre_update_restore_point",
                )
                if pre_bak.get("ok"):
                    rollback_pkg_id = pre_bak["package"]["package_id"]

            restored: list[str] = list(already_completed)
            skipped_or_failed: list[dict[str, str]] = []
            decrypted_credentials: dict[str, str] = {}
            recreated_envs: list[str] = []

            # Apply hardware adaptations locally (§231 & §235.16)
            if compat["hardware_adaptations"]:
                self.db.set_desktop_setting("hardware_adaptation_notes", compat["hardware_adaptations"])
                if compat["dimensions_compared"]["5_available_ram_mb"] < 4096:
                    self.db.set_desktop_setting("resource_profile_mode", "low_memory_adapted")

            for comp in requested:
                if comp in restored:
                    continue

                if comp == "core_data" and (ext_dir / "core_data" / "core_state.json").is_file():
                    self._restore_core_data(json.loads((ext_dir / "core_data" / "core_state.json").read_text(encoding="utf-8")))
                    restored.append("core_data")

                elif comp == "memory_and_knowledge" and (ext_dir / "memory_and_knowledge" / "memory_bundle.json").is_file():
                    self._restore_memory_and_knowledge(
                        json.loads((ext_dir / "memory_and_knowledge" / "memory_bundle.json").read_text(encoding="utf-8"))
                    )
                    restored.append("memory_and_knowledge")

                elif comp == "ai_configuration" and (ext_dir / "ai_configuration" / "ai_profiles.json").is_file():
                    self._restore_ai_configuration(
                        json.loads((ext_dir / "ai_configuration" / "ai_profiles.json").read_text(encoding="utf-8"))
                    )
                    restored.append("ai_configuration")

                elif comp == "projects_and_files" and proj_ext.is_dir():
                    for f in sorted(proj_ext.rglob("*")):
                        if f.is_file():
                            rel = f.relative_to(proj_ext)
                            dest_f = self.workspace_dir / rel
                            if dest_f.exists() and not overwrite_existing_files:
                                skipped_or_failed.append({"component": f"file:{rel.as_posix()}", "reason": "skipped_existing_file"})
                                continue
                            dest_f.parent.mkdir(parents=True, exist_ok=True)
                            shutil.copy2(f, dest_f)
                    restored.append("projects_and_files")

                elif comp == "software_and_environments" and (ext_dir / "software_and_environments" / "software_and_envs.json").is_file():
                    sw_bundle = json.loads(
                        (ext_dir / "software_and_environments" / "software_and_envs.json").read_text(encoding="utf-8")
                    )
                    for ref in sw_bundle.get("deferred_online_recreation_references") or []:
                        skipped_or_failed.append(
                            {
                                "component": f"package:{ref['package_name']}",
                                "reason": ref["reason"],
                                "install_source": ref["install_source"],
                            }
                        )
                    # Recreate project environments from saved portable profiles (§231 & §235.14)
                    for spec in sw_bundle.get("environment_profiles") or []:
                        proj_slug = str(spec.get("name") or "restored_env").lower().replace(" ", "_")
                        target_proj_dir = self.workspace_dir / "restored_environments" / proj_slug
                        rec = self.env_builder.recreate_environment_from_profile(spec, target_proj_dir)
                        if rec.get("ok"):
                            recreated_envs.append(str(target_proj_dir))
                        else:
                            skipped_or_failed.append({"component": f"env:{proj_slug}", "reason": "recreation_failed"})
                    restored.append("software_and_environments")

                elif comp == "local_models":
                    mod_ext = ext_dir / "local_models"
                    if mod_ext.is_dir():
                        if compat["dimensions_compared"]["5_available_ram_mb"] < 1024:
                            skipped_or_failed.append({"component": "local_models", "reason": "insufficient_target_ram_skipped_preload"})
                        else:
                            dest_mod = self.workspace_dir / "models"
                            dest_mod.mkdir(parents=True, exist_ok=True)
                            for mf in mod_ext.iterdir():
                                if mf.is_file():
                                    shutil.copy2(mf, dest_mod / mf.name)
                            restored.append("local_models")

                # Checkpoint support for interrupted migrations (§233 & §235.19)
                if simulate_interrupt_after_component and comp == simulate_interrupt_after_component:
                    aud_int = self.db.record_migration_audit(
                        {
                            "id": resume_audit_id or None,
                            "operation": "restore",
                            "status": "interrupted_checkpoint_saved",
                            "checkpoint": {"last_completed_component": comp, "archive_path": str(archive_path)},
                            "restored_components": restored,
                            "skipped_or_failed": skipped_or_failed,
                            "hardware_adaptations": compat["hardware_adaptations"],
                            "rollback_backup_id": rollback_pkg_id,
                        }
                    )
                    return {
                        "ok": False,
                        "status": "interrupted_checkpoint_saved",
                        "resumable_audit_id": aud_int["id"],
                        "restored_components": restored,
                        "audit": aud_int,
                    }

            # Optional encrypted credential vault transfer (§229.C, §234 & §235.17)
            vault_path = ext_dir / "credentials" / "credentials.vault.enc"
            if vault_path.is_file():
                if credential_passphrase:
                    try:
                        dec_raw = MigrationVaultCipher.decrypt_bytes(vault_path.read_bytes(), credential_passphrase)
                        decrypted_credentials = json.loads(dec_raw.decode("utf-8"))
                        restored.append("encrypted_credentials")
                    except ArchiveSecurityError as exc:
                        skipped_or_failed.append({"component": "encrypted_credentials", "reason": str(exc)})
                else:
                    skipped_or_failed.append(
                        {"component": "encrypted_credentials", "reason": "passphrase_not_supplied_kept_sealed"}
                    )

            aud_done = self.db.record_migration_audit(
                {
                    "id": resume_audit_id or None,
                    "operation": "restore",
                    "status": "completed",
                    "restored_components": restored,
                    "skipped_or_failed": skipped_or_failed,
                    "hardware_adaptations": compat["hardware_adaptations"],
                    "rollback_backup_id": rollback_pkg_id,
                    "detail": {"recreated_environments": recreated_envs},
                }
            )
            return {
                "ok": True,
                "status": "completed",
                "restored_components": restored,
                "recreated_environments": recreated_envs,
                "decrypted_credential_keys": sorted(decrypted_credentials.keys()),
                "decrypted_credentials_vault": decrypted_credentials,
                "hardware_adaptations": compat["hardware_adaptations"],
                "skipped_or_failed_components": skipped_or_failed,
                "rollback_backup_id": rollback_pkg_id,
                "audit": aud_done,
            }

    def rollback_restore(self, audit_id: str) -> dict[str, Any]:
        """§234 Roll back a previous restoration using its automatic pre-restore backup."""
        aud = self.db.get_migration_audit(audit_id)
        if aud is None or not aud.get("rollback_backup_id"):
            return {"ok": False, "status": "no_rollback_point_found"}
        pkgs = [p for p in self.db.list_migration_packages(limit=200) if p["package_id"] == aud["rollback_backup_id"]]
        if not pkgs:
            return {"ok": False, "status": "rollback_package_missing"}
        return self.restore_migration_package(
            pkgs[0]["archive_path"],
            create_pre_restore_backup=False,
        )

    # ------------------------------------------------- SQLite State Helpers

    def _export_core_data(self, *, since_timestamp: str = "") -> dict[str, Any]:
        with self.db._lock, self.db._connect() as conn:
            d_rows = [
                dict(r)
                for r in conn.execute("SELECT * FROM desktop_settings").fetchall()
                if r["key"] not in NON_PORTABLE_MACHINE_SETTING_KEYS
            ]
            t_sql = "SELECT * FROM tasks" + (" WHERE updated_at >= ?" if since_timestamp else "")
            t_rows = [dict(r) for r in conn.execute(t_sql, (since_timestamp,) if since_timestamp else ()).fetchall()]
            g_rows = [dict(r) for r in conn.execute("SELECT * FROM goals").fetchall()]
        return {"desktop_settings": d_rows, "tasks": t_rows, "goals": g_rows}

    def _restore_core_data(self, payload: dict[str, Any]) -> None:
        with self.db._lock, self.db._connect() as conn:
            for r in payload.get("desktop_settings") or []:
                if r.get("key") in NON_PORTABLE_MACHINE_SETTING_KEYS:
                    continue
                conn.execute(
                    "INSERT OR REPLACE INTO desktop_settings (key, value_json, updated_at) VALUES (?, ?, ?)",
                    (r["key"], r["value_json"], r["updated_at"]),
                )
            for g in payload.get("goals") or []:
                cols = list(g.keys())
                placeholders = ", ".join("?" for _ in cols)
                conn.execute(f"INSERT OR REPLACE INTO goals ({', '.join(cols)}) VALUES ({placeholders})", [g[c] for c in cols])

    def _export_memory_and_knowledge(self, *, since_timestamp: str = "") -> dict[str, Any]:
        with self.db._lock, self.db._connect() as conn:
            m_sql = "SELECT * FROM memory_entries" + (" WHERE updated_at >= ?" if since_timestamp else "")
            memories = [dict(r) for r in conn.execute(m_sql, (since_timestamp,) if since_timestamp else ()).fetchall()]
            procs = [dict(r) for r in conn.execute("SELECT * FROM cognition_procedures").fetchall()]
            kdocs = [dict(r) for r in conn.execute("SELECT * FROM kali_knowledge_documents").fetchall()]
        return {"memory_entries": memories, "cognition_procedures": procs, "kali_knowledge_documents": kdocs}

    def _restore_memory_and_knowledge(self, payload: dict[str, Any]) -> None:
        with self.db._lock, self.db._connect() as conn:
            for tbl in ("memory_entries", "cognition_procedures", "kali_knowledge_documents"):
                for row in payload.get(tbl) or []:
                    cols = list(row.keys())
                    placeholders = ", ".join("?" for _ in cols)
                    conn.execute(
                        f"INSERT OR REPLACE INTO {tbl} ({', '.join(cols)}) VALUES ({placeholders})",
                        [row[c] for c in cols],
                    )

    def _export_ai_configuration_secret_free(self) -> dict[str, Any]:
        with self.db._lock, self.db._connect() as conn:
            profiles = []
            for r in conn.execute("SELECT * FROM model_profiles").fetchall():
                d = dict(r)
                # Keep only env-variable reference name (e.g. NOVA_OPENAI_API_KEY), NEVER secret values!
                d.pop("raw_api_key", None)
                profiles.append(d)
        return {"model_profiles": profiles, "cloud_proprietary_weights_included": False}

    def _restore_ai_configuration(self, payload: dict[str, Any]) -> None:
        with self.db._lock, self.db._connect() as conn:
            for row in payload.get("model_profiles") or []:
                cols = list(row.keys())
                placeholders = ", ".join("?" for _ in cols)
                conn.execute(
                    f"INSERT OR REPLACE INTO model_profiles ({', '.join(cols)}) VALUES ({placeholders})",
                    [row[c] for c in cols],
                )

    @classmethod
    def _measure_filtered_bytes(cls, path: Path) -> int:
        if path.is_file():
            return 0 if path.name in SENSITIVE_CREDENTIAL_FILENAMES else path.stat().st_size
        total = 0
        for item in path.rglob("*"):
            if any(part in UniversalMigrationArchiveCodec.EXCLUDED_HEAVY_DIR_NAMES for part in item.parts):
                continue
            if item.is_file() and item.name not in SENSITIVE_CREDENTIAL_FILENAMES:
                total += item.stat().st_size
        return total

    @classmethod
    def _copy_filtered_tree(cls, src: Path, dst: Path, *, since_timestamp: str = "") -> None:
        if src.is_file():
            if src.name in SENSITIVE_CREDENTIAL_FILENAMES:
                return
            dst.parent.mkdir(parents=True, exist_ok=True)
            shutil.copy2(src, dst)
            return
        for item in sorted(src.rglob("*")):
            rel_parts = item.relative_to(src).parts
            if any(p in UniversalMigrationArchiveCodec.EXCLUDED_HEAVY_DIR_NAMES for p in rel_parts):
                continue
            if item.is_file():
                if item.name in SENSITIVE_CREDENTIAL_FILENAMES:
                    continue
                target = dst / item.relative_to(src)
                target.parent.mkdir(parents=True, exist_ok=True)
                shutil.copy2(item, target)

    @staticmethod
    def _write_json(path: Path, data: Any) -> None:
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(json.dumps(data, indent=2, default=str), encoding="utf-8")


class OneClickBackupAndRestoreEngine:
    """§232 One-Click Verified Backup, Incremental Snapshot & Pre-Update Restore Point Engine."""

    CLAIM_BACKUP_SUCCESS_BEFORE_VERIFICATION = False

    KIND_TO_SECTIONS: ClassVar[dict[str, list[str]]] = {
        "full_backup": list(MIGRATION_6_SECTIONS),
        "config_only": ["core_data", "ai_configuration"],
        "memory_only": ["memory_and_knowledge"],
        "project_only": ["projects_and_files"],
        "model_only": ["local_models"],
        "software_inventory_only": ["software_and_environments"],
        "selected_app_backup": ["core_data", "software_and_environments"],
        "encrypted_complete_backup": list(MIGRATION_6_SECTIONS),
        "incremental_backup": ["core_data", "memory_and_knowledge", "projects_and_files"],
        "scheduled_backup": ["core_data", "memory_and_knowledge", "projects_and_files"],
        "pre_update_restore_point": ["core_data", "memory_and_knowledge", "ai_configuration", "software_and_environments"],
    }

    def __init__(self, *, migration_mgr: DevMigrationManager, workspace_dir: Path):
        self.migration_mgr = migration_mgr
        self.workspace_dir = workspace_dir

    def create_verified_backup(
        self,
        backup_kind: str = "full_backup",
        *,
        passphrase: str = "",
        since_timestamp: str = "",
        selected_project_paths: list[str] | None = None,
        local_model_paths: list[str] | None = None,
    ) -> dict[str, Any]:
        """§232 Create any of the 11 backup types; never report ok=True unless checksum & manifest pass."""
        if backup_kind not in BACKUP_11_KINDS:
            raise ValueError(f"Unsupported backup_kind `{backup_kind}`. Valid: {BACKUP_11_KINDS}")
        if backup_kind == "encrypted_complete_backup" and len(passphrase) < 8:
            raise ValueError("`encrypted_complete_backup` requires a passphrase of at least 8 characters.")

        sections = self.KIND_TO_SECTIONS[backup_kind]
        return self.migration_mgr.create_migration_package(
            output_dir=self.workspace_dir / "backups",
            package_name=f"dev-{backup_kind.replace('_', '-')}",
            sections=sections,
            selected_project_paths=selected_project_paths,
            local_model_paths=local_model_paths,
            encrypt_entire_archive_passphrase=passphrase if backup_kind == "encrypted_complete_backup" else "",
            backup_kind=backup_kind,
            since_timestamp=since_timestamp if backup_kind == "incremental_backup" else "",
        )

    def create_pre_update_recovery_point(self) -> dict[str, Any]:
        """§232 Automatic verified recovery point created before major DEV updates."""
        return self.create_verified_backup("pre_update_restore_point")
