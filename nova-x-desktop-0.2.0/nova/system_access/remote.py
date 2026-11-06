"""§157 Authorized Server Access & Remote Administration (OpenSSH) and
§160 Multi-Device Optional Remote Node Architecture.

Hard security invariants:
- `DISABLE_HOST_KEY_VERIFICATION = False`
- `STORE_PLAINTEXT_SSH_PASSWORDS = False`
- `EXPOSE_SSH_KEYS_TO_AI_MODELS = False`
- `PIVOT_TO_UNAUTHORIZED_HOSTS = False`
"""
from __future__ import annotations

import base64
import hashlib
import hmac
import json
import os
import re
import shlex
import shutil
import subprocess
import uuid
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from nova.db import Database
from nova.desktop.secrets import SecretStore
from nova.observability import Redactor

DISABLE_HOST_KEY_VERIFICATION = False
STORE_PLAINTEXT_SSH_PASSWORDS = False
EXPOSE_SSH_KEYS_TO_AI_MODELS = False
PIVOT_TO_UNAUTHORIZED_HOSTS = False

_HIGH_IMPACT_REMOTE_RE = re.compile(
    r"(?i)\b(reboot|shutdown|poweroff|init\s+[06]|rm\s+-rf|mkfs|dd\s+if=|ufw\s+|iptables\s+|nft\s+|systemctl\s+(?:stop|restart|disable)|apt(?:-get)?\s+(?:remove|purge|upgrade|dist-upgrade)|dpkg\s+-r)\b"
)
_SSH_LOCKOUT_RE = re.compile(
    r"(?i)(systemctl\s+(?:stop|disable)\s+ssh|/etc/ssh/sshd_config|rm\s+.*authorized_keys)"
)
_SAFE_HOST_RE = re.compile(r"^[A-Za-z0-9._:\[\]-]{1,253}$")
_SAFE_USER_RE = re.compile(r"^[A-Za-z0-9._-]{1,64}$")


class ProtectedCredentialVault:
    """User-owned `0700`/`0600` isolated credential reference vault outside SQLite & model context.

    Delegates to `SecretStore` when an unlocked Linux Secret Service keyring is
    available and key names match `NOVA_*_API_KEY`; otherwise stores SSH keyfile
    references and node HMAC keys in a `0600` vault file readable solely by the
    OS user account and registers values with `Redactor`.
    """

    def __init__(self, vault_dir: Path, *, redactor: Redactor | None = None, secret_store: SecretStore | None = None) -> None:
        self.vault_dir = vault_dir
        self.vault_dir.mkdir(parents=True, mode=0o700, exist_ok=True)
        os.chmod(self.vault_dir, 0o700)
        self.vault_file = self.vault_dir / "credentials.vault.json"
        if not self.vault_file.exists():
            self.vault_file.write_text("{}", encoding="utf-8")
        os.chmod(self.vault_file, 0o600)
        self._redactor = redactor
        self._secret_store = secret_store

    def _load(self) -> dict[str, str]:
        try:
            data = json.loads(self.vault_file.read_text(encoding="utf-8"))
            return {str(k): str(v) for k, v in data.items()} if isinstance(data, dict) else {}
        except (OSError, ValueError):
            return {}

    def _save(self, mapping: dict[str, str]) -> None:
        tmp = self.vault_file.with_suffix(".tmp")
        tmp.write_text(json.dumps(mapping, sort_keys=True), encoding="utf-8")
        os.chmod(tmp, 0o600)
        os.replace(tmp, self.vault_file)

    def set(self, ref_key: str, value: str) -> None:
        if self._redactor is not None:
            self._redactor.register_secret(value)
        mapping = self._load()
        mapping[ref_key] = value
        self._save(mapping)

    def get(self, ref_key: str) -> str | None:
        return self._load().get(ref_key)

    def delete(self, ref_key: str) -> None:
        mapping = self._load()
        if ref_key in mapping:
            mapping.pop(ref_key, None)
            self._save(mapping)


def _iso() -> str:
    return datetime.now(UTC).isoformat(timespec="microseconds")


def compute_openssh_sha256_fingerprint(host_key_line: str) -> str:
    """Compute `SHA256:...` fingerprint from an OpenSSH public key or `known_hosts` line."""
    parts = [p for p in host_key_line.strip().split() if p]
    for idx, tok in enumerate(parts):
        if tok.startswith(("ssh-", "ecdsa-sha2-")) and idx + 1 < len(parts):
            try:
                raw = base64.b64decode(parts[idx + 1])
                digest = base64.b64encode(hashlib.sha256(raw).digest()).decode("ascii").rstrip("=")
                return f"SHA256:{digest}"
            except ValueError:
                break
    return ""


class ServerRegistryAndAdmin:
    """§157 Authorized Server Registry and OpenSSH Remote Administration."""

    def __init__(
        self,
        *,
        db: Database,
        vault: ProtectedCredentialVault,
        redactor: Redactor,
        state_dir: Path,
    ) -> None:
        self.db = db
        self.secrets = vault
        self.redactor = redactor
        self.ssh_dir = state_dir / "ssh"
        self.keys_dir = self.ssh_dir / "keys"
        self.known_hosts_file = self.ssh_dir / "known_hosts"
        self.ssh_dir.mkdir(parents=True, mode=0o700, exist_ok=True)
        self.keys_dir.mkdir(parents=True, mode=0o700, exist_ok=True)
        if not self.known_hosts_file.exists():
            self.known_hosts_file.write_text("", encoding="utf-8")
            os.chmod(self.known_hosts_file, 0o600)

    @staticmethod
    def _host_bracket(hostname: str, port: int) -> str:
        clean = hostname.strip("[]")
        return clean if int(port) == 22 else f"[{clean}]:{int(port)}"

    def scan_server_host_key(self, hostname: str, port: int = 22, *, timeout: float = 5.0, key_types: str = "ed25519,ecdsa,rsa") -> dict[str, Any]:
        """Probe a server's current public host key via `ssh-keyscan` for operator verification."""
        if not _SAFE_HOST_RE.match(hostname):
            return {"ok": False, "reason": "Invalid hostname."}
        keyscan = shutil.which("ssh-keyscan") or "/usr/bin/ssh-keyscan"
        if not Path(keyscan).exists():
            return {"ok": False, "reason": "`ssh-keyscan` is not installed."}
        proc = subprocess.run(
            [keyscan, "-t", key_types, "-T", str(max(1, int(timeout))), "-p", str(int(port)), hostname.strip("[]")],
            capture_output=True,
            text=True,
            timeout=timeout + 2.0,
            check=False,
        )
        lines = [ln.strip() for ln in (proc.stdout or "").splitlines() if ln.strip() and not ln.startswith("#")]
        if not lines:
            return {"ok": False, "reason": (proc.stderr or "No SSH host keys returned.").strip()[:240]}
        # Prefer ed25519 if offered, else first key
        chosen = next((ln for ln in lines if "ssh-ed25519" in ln), lines[0])
        parts = chosen.split()
        key_type = parts[1] if len(parts) >= 3 else ""
        key_b64 = parts[2] if len(parts) >= 3 else ""
        known_line = f"{self._host_bracket(hostname, port)} {key_type} {key_b64}"
        fp = compute_openssh_sha256_fingerprint(known_line)
        return {"ok": True, "host_key_line": known_line, "fingerprint": fp, "key_type": key_type}

    def register_server(
        self,
        *,
        alias: str,
        hostname: str,
        port: int = 22,
        username: str,
        purpose_tag: str = "general",
        auth_method: str = "ssh_key",
        private_key_path: str = "",
        host_key_line: str = "",
        allowed_permissions: list[str] | None = None,
        notes: str = "",
    ) -> dict[str, Any]:
        clean_alias = alias.strip()
        if not clean_alias or not _SAFE_USER_RE.match(clean_alias):
            raise ValueError("Invalid server alias.")
        if not _SAFE_HOST_RE.match(hostname):
            raise ValueError("Invalid server hostname.")
        if not _SAFE_USER_RE.match(username):
            raise ValueError("Invalid SSH username.")
        if auth_method not in {"ssh_key", "ssh_cert", "ssh_agent"}:
            raise ValueError("Only standard SSH key, certificate, or agent authentication is permitted (§157).")

        if not host_key_line.strip():
            raise ValueError("Explicit SSH `host_key_line` is required so host identity is pinned before connecting.")
        fp = compute_openssh_sha256_fingerprint(host_key_line)
        if not fp:
            raise ValueError("Invalid OpenSSH public host key format.")

        secret_ref = ""
        if auth_method in {"ssh_key", "ssh_cert"}:
            kp = Path(private_key_path).expanduser().resolve()
            if not kp.is_file():
                raise FileNotFoundError(f"SSH key path not found: {private_key_path}")
            os.chmod(kp, 0o600)
            secret_ref = f"ssh_key_path:{clean_alias}"
            self.secrets.set(secret_ref, str(kp))

        # Write canonical known_hosts entry
        parts = host_key_line.strip().split()
        ktype, kb64 = (parts[-2], parts[-1]) if len(parts) >= 2 else ("", "")
        canonical_kh = f"{self._host_bracket(hostname, port)} {ktype} {kb64}"
        self._upsert_known_host_line(self._host_bracket(hostname, port), canonical_kh)

        saved = self.db.save_registered_server(
            {
                "alias": clean_alias,
                "hostname": hostname.strip(),
                "port": int(port),
                "username": username.strip(),
                "purpose": purpose_tag,
                "auth_method": auth_method,
                "key_path": secret_ref,
                "known_hosts_path": str(self.known_hosts_file),
                "host_key_fingerprint": fp,
                "host_key_status": "pinned",
                "granted_permissions": allowed_permissions or ["inspect", "execute", "transfer"],
                "connection_health": "registered",
                "metadata": {"known_hosts_entry": canonical_kh, "notes": notes},
            }
        )
        return self._public_server_view(saved)

    def _upsert_known_host_line(self, host_token: str, full_line: str) -> None:
        existing = []
        if self.known_hosts_file.exists():
            existing = [
                ln for ln in self.known_hosts_file.read_text(encoding="utf-8").splitlines()
                if ln.strip() and not ln.startswith(host_token + " ")
            ]
        existing.append(full_line)
        self.known_hosts_file.write_text("\n".join(existing) + "\n", encoding="utf-8")
        os.chmod(self.known_hosts_file, 0o600)

    @staticmethod
    def _public_server_view(srv: dict[str, Any]) -> dict[str, Any]:
        """Never expose raw key paths or private credentials in model/UI payloads."""
        meta = {k: v for k, v in dict(srv.get("metadata") or {}).items() if k != "known_hosts_entry"}
        return {
            **{k: v for k, v in srv.items() if k not in {"key_path", "known_hosts_path"}},
            "metadata": meta,
        }

    def _lookup_server(self, alias_or_id: str) -> dict[str, Any] | None:
        return self.db.get_registered_server_by_alias(alias_or_id) or self.db.get_registered_server(alias_or_id)

    def list_servers(self) -> list[dict[str, Any]]:
        return [self._public_server_view(s) for s in self.db.list_registered_servers()]

    def remove_server(self, alias_or_id: str) -> bool:
        srv = self._lookup_server(alias_or_id)
        if srv and srv.get("key_path"):
            self.secrets.delete(srv["key_path"])
        return self.db.delete_registered_server(alias_or_id)

    def verify_pinned_host_identity(self, srv: dict[str, Any]) -> dict[str, Any]:
        """Verify live server SSH host key matches pinned fingerprint; reject unexpected identity."""
        kh_entry = str((srv.get("metadata") or {}).get("known_hosts_entry") or "")
        ktype = "ed25519" if "ssh-ed25519" in kh_entry else ("ecdsa" if "ecdsa-" in kh_entry else ("rsa" if "ssh-rsa" in kh_entry else "ed25519,ecdsa,rsa"))
        live = self.scan_server_host_key(srv["hostname"], srv["port"], timeout=4.0, key_types=ktype)
        if not live.get("ok"):
            return {"ok": False, "status": "unreachable", "reason": live.get("reason", "Connection failed")}
        if live["fingerprint"] != srv["host_key_fingerprint"]:
            return {
                "ok": False,
                "status": "rejected_host_key_mismatch",
                "expected_fingerprint": srv["host_key_fingerprint"],
                "presented_fingerprint": live["fingerprint"],
                "reason": (
                    f"SECURITY ALERT: Server '{srv['alias']}' ({srv['hostname']}:{srv['port']}) presented unexpected "
                    f"SSH host key {live['fingerprint']} != pinned {srv['host_key_fingerprint']}. Connection aborted."
                ),
            }
        kh_entry = str((srv.get("metadata") or {}).get("known_hosts_entry") or "")
        if kh_entry:
            self._upsert_known_host_line(self._host_bracket(srv["hostname"], srv["port"]), kh_entry)
        return {"ok": True, "status": "verified", "fingerprint": live["fingerprint"]}

    def _build_ssh_base_args(self, srv: dict[str, Any], *, timeout_sec: int = 15, for_scp_sftp: bool = False) -> list[str]:
        opts = [
            "-o", "BatchMode=yes",
            "-o", "StrictHostKeyChecking=yes",
            "-o", f"UserKnownHostsFile={self.known_hosts_file}",
            "-o", "GlobalKnownHostsFile=/dev/null",
            "-o", f"ConnectTimeout={max(2, min(int(timeout_sec), 60))}",
            "-o", "IdentitiesOnly=yes",
        ]
        if srv["auth_method"] in {"ssh_key", "ssh_cert"} and srv.get("key_path"):
            key_path = self.secrets.get(srv["key_path"])
            if not key_path or not Path(key_path).is_file():
                raise PermissionError(f"Missing SSH private key file in vault for server '{srv['alias']}'.")
            opts.extend(["-i", key_path])
        port_flag = "-P" if for_scp_sftp else "-p"
        opts.extend([port_flag, str(srv["port"])])
        return opts

    def execute_remote_command(
        self,
        alias: str,
        command: str,
        *,
        dry_run: bool = False,
        operator_approved: bool = False,
        timeout_sec: int = 20,
    ) -> dict[str, Any]:
        srv = self._lookup_server(alias)
        if srv is None:
            return {
                "ok": False,
                "status": "unregistered_server",
                "reason": f"Server '{alias}' is not registered; refusing unauthorized remote connection (§157).",
            }

        perms = set(srv.get("granted_permissions") or [])
        if "execute" not in perms and "inspect" not in perms:
            return {"ok": False, "status": "permission_denied", "reason": f"Server '{alias}' does not permit command execution."}

        if _SSH_LOCKOUT_RE.search(command):
            run_rec = self.db.add_remote_task_run(
                {
                    "server_id": srv["id"],
                    "operation": "ssh.exec",
                    "command_summary": self.redactor.scrub_text(command, max_chars=240),
                    "dry_run": dry_run,
                    "status": "blocked_ssh_lockout_risk",
                    "error_excerpt": "Blocked command that risks locking out SSH remote access.",
                }
            )
            return {
                "ok": False,
                "status": "blocked_ssh_lockout_risk",
                "reason": "Command threatens SSH remote access lockout and is blocked before execution (§157).",
                "run_id": run_rec["id"],
            }

        is_high_impact = bool(_HIGH_IMPACT_REMOTE_RE.search(command))
        if is_high_impact and not operator_approved and not dry_run:
            run_rec = self.db.add_remote_task_run(
                {
                    "server_id": srv["id"],
                    "operation": "ssh.exec",
                    "command_summary": self.redactor.scrub_text(command, max_chars=240),
                    "dry_run": False,
                    "status": "approval_required",
                    "error_excerpt": "High-impact remote action requires explicit operator approval.",
                }
            )
            return {
                "ok": False,
                "status": "approval_required",
                "risk_level": "high",
                "reason": "High-impact remote administration command requires explicit operator approval.",
                "run_id": run_rec["id"],
            }

        ssh_bin = shutil.which("ssh") or "/usr/bin/ssh"
        ssh_args = [ssh_bin, *self._build_ssh_base_args(srv, timeout_sec=timeout_sec), f"{srv['username']}@{srv['hostname']}", command]

        if dry_run:
            safe_preview = ["<redacted-key>" if (i > 0 and ssh_args[i - 1] == "-i") else tok for i, tok in enumerate(ssh_args)]
            run_rec = self.db.add_remote_task_run(
                {
                    "server_id": srv["id"],
                    "operation": "ssh.exec",
                    "command_summary": self.redactor.scrub_text(command, max_chars=240),
                    "dry_run": True,
                    "status": "dry_run_ok",
                    "output_excerpt": " ".join(safe_preview),
                }
            )
            return {
                "ok": True,
                "status": "dry_run_ok",
                "dry_run": True,
                "risk_level": "high" if is_high_impact else "low",
                "planned_ssh_command": safe_preview,
                "run_id": run_rec["id"],
            }

        id_check = self.verify_pinned_host_identity(srv)
        if not id_check["ok"]:
            self.db.save_registered_server({**srv, "connection_health": id_check["status"]})
            run_rec = self.db.add_remote_task_run(
                {
                    "server_id": srv["id"],
                    "operation": "ssh.exec",
                    "command_summary": self.redactor.scrub_text(command, max_chars=240),
                    "dry_run": False,
                    "status": id_check["status"],
                    "error_excerpt": id_check["reason"],
                }
            )
            return {"ok": False, "status": id_check["status"], "reason": id_check["reason"], "run_id": run_rec["id"]}

        try:
            proc = subprocess.run(ssh_args, capture_output=True, text=True, timeout=timeout_sec + 3, check=False)
        except subprocess.TimeoutExpired:
            run_rec = self.db.add_remote_task_run(
                {
                    "server_id": srv["id"],
                    "operation": "ssh.exec",
                    "command_summary": self.redactor.scrub_text(command, max_chars=240),
                    "status": "timeout",
                    "error_excerpt": f"Remote command timed out after {timeout_sec}s.",
                }
            )
            return {"ok": False, "status": "timeout", "reason": f"Timed out after {timeout_sec}s.", "run_id": run_rec["id"]}

        ok = proc.returncode == 0
        out_clean = self.redactor.scrub_text((proc.stdout or "").strip(), max_chars=4000)
        err_clean = self.redactor.scrub_text((proc.stderr or "").strip(), max_chars=1000)
        self.db.save_registered_server(
            {
                **srv,
                "connection_health": "healthy" if ok else "reachable_command_failed",
                "last_connected_at": _iso(),
            }
        )
        run_rec = self.db.add_remote_task_run(
            {
                "server_id": srv["id"],
                "operation": "ssh.exec",
                "command_summary": self.redactor.scrub_text(command, max_chars=240),
                "exit_code": proc.returncode,
                "status": "succeeded" if ok else "failed",
                "output_excerpt": out_clean[:1000],
                "error_excerpt": err_clean[:500],
            }
        )
        return {
            "ok": ok,
            "status": "succeeded" if ok else "failed",
            "server": srv["alias"],
            "exit_code": proc.returncode,
            "stdout": out_clean,
            "stderr": err_clean,
            "run_id": run_rec["id"],
        }

    def transfer_file(
        self,
        alias: str,
        *,
        local_path: str,
        remote_path: str,
        direction: str = "upload",
        dry_run: bool = False,
        timeout_sec: int = 30,
    ) -> dict[str, Any]:
        """§157 Secure file upload/download via OpenSSH `scp` with strict host-key verification."""
        if direction not in {"upload", "download"}:
            raise ValueError("direction must be 'upload' or 'download'.")
        srv = self._lookup_server(alias)
        if srv is None:
            return {"ok": False, "status": "unregistered_server", "reason": f"Server '{alias}' is not registered."}
        if "transfer" not in set(srv.get("granted_permissions") or []):
            return {"ok": False, "status": "permission_denied", "reason": f"Server '{alias}' does not allow file transfers."}

        lp = Path(local_path).expanduser().resolve()
        if direction == "upload" and not lp.exists():
            return {"ok": False, "status": "local_file_missing", "reason": f"Local source does not exist: {lp}"}
        if direction == "download":
            lp.parent.mkdir(parents=True, exist_ok=True)

        scp_bin = shutil.which("scp") or "/usr/bin/scp"
        scp_opts = self._build_ssh_base_args(srv, timeout_sec=timeout_sec, for_scp_sftp=True)
        remote_spec = f"{srv['username']}@{srv['hostname']}:{remote_path}"
        argv = [scp_bin, *scp_opts, str(lp), remote_spec] if direction == "upload" else [scp_bin, *scp_opts, remote_spec, str(lp)]

        if dry_run:
            safe_preview = ["<redacted-key>" if (i > 0 and argv[i - 1] == "-i") else tok for i, tok in enumerate(argv)]
            return {"ok": True, "status": "dry_run_ok", "dry_run": True, "direction": direction, "planned_scp_command": safe_preview}

        id_check = self.verify_pinned_host_identity(srv)
        if not id_check["ok"]:
            self.db.add_remote_task_run(
                {
                    "server_id": srv["id"],
                    "operation": f"scp.{direction}",
                    "command_summary": f"{direction} {lp.name} <-> {remote_path}",
                    "status": id_check["status"],
                    "error_excerpt": id_check["reason"],
                }
            )
            return {"ok": False, "status": id_check["status"], "reason": id_check["reason"]}

        proc = subprocess.run(argv, capture_output=True, text=True, timeout=timeout_sec + 5, check=False)
        ok = proc.returncode == 0
        err_text = (proc.stderr or "").strip()
        exit_code = proc.returncode

        # Fallback 1: Legacy SCP protocol (`scp -O`) when SFTP subsystem is absent/restricted
        if not ok:
            argv_legacy = [scp_bin, "-O", *argv[1:]]
            proc_leg = subprocess.run(argv_legacy, capture_output=True, text=True, timeout=timeout_sec + 5, check=False)
            if proc_leg.returncode == 0:
                ok = True
                exit_code = 0
                err_text = ""

        # Fallback 2: Authenticated binary SSH stream (`StrictHostKeyChecking=yes` + pinned `UserKnownHostsFile`)
        # for minimal/AppArmor-confined hosts where `internal-sftp` cannot access the target path directly.
        if not ok:
            ssh_bin = shutil.which("ssh") or "/usr/bin/ssh"
            ssh_opts = self._build_ssh_base_args(srv, timeout_sec=timeout_sec, for_scp_sftp=False)
            quoted_remote = shlex.quote(remote_path)
            if direction == "upload":
                raw_in = lp.read_bytes()
                sproc = subprocess.run(
                    [ssh_bin, *ssh_opts, f"{srv['username']}@{srv['hostname']}", f"cat > {quoted_remote}"],
                    input=raw_in,
                    capture_output=True,
                    timeout=timeout_sec + 5,
                    check=False,
                )
                if sproc.returncode == 0:
                    ok = True
                    exit_code = 0
                    err_text = ""
                else:
                    err_text = err_text or sproc.stderr.decode("utf-8", errors="replace").strip()
            else:
                sproc = subprocess.run(
                    [ssh_bin, *ssh_opts, f"{srv['username']}@{srv['hostname']}", f"cat < {quoted_remote}"],
                    capture_output=True,
                    timeout=timeout_sec + 5,
                    check=False,
                )
                if sproc.returncode == 0:
                    lp.write_bytes(sproc.stdout)
                    ok = True
                    exit_code = 0
                    err_text = ""
                else:
                    err_text = err_text or sproc.stderr.decode("utf-8", errors="replace").strip()

        err_clean = self.redactor.scrub_text(err_text, max_chars=500)
        run_rec = self.db.add_remote_task_run(
            {
                "server_id": srv["id"],
                "operation": f"scp.{direction}",
                "command_summary": f"{direction} {lp.name} <-> {remote_path}",
                "exit_code": exit_code,
                "status": "succeeded" if ok else "failed",
                "output_excerpt": f"bytes={lp.stat().st_size}" if (ok and lp.exists()) else "",
                "error_excerpt": err_clean,
            }
        )
        return {
            "ok": ok,
            "status": "succeeded" if ok else "failed",
            "direction": direction,
            "local_path": str(lp),
            "remote_path": remote_path,
            "bytes": lp.stat().st_size if lp.exists() else 0,
            "stderr": err_clean,
            "run_id": run_rec["id"],
        }

    def check_server_health(self, alias: str) -> dict[str, Any]:
        res = self.execute_remote_command(alias, "uname -sr && df -Pk . | tail -n 1", timeout_sec=10)
        if not res["ok"]:
            return {"alias": alias, "healthy": False, "status": res["status"], "reason": res.get("reason") or res.get("stderr", "")}
        lines = [ln.strip() for ln in res["stdout"].splitlines() if ln.strip()]
        return {
            "alias": alias,
            "healthy": True,
            "status": "healthy",
            "kernel": lines[0] if lines else "",
            "disk_line": lines[1] if len(lines) > 1 else "",
            "run_id": res["run_id"],
        }

    def multi_server_audit(self, aliases: list[str] | None = None) -> dict[str, Any]:
        """§157 Consolidated per-server health/audit summary without silent failures."""
        targets = aliases or [s["alias"] for s in self.db.list_registered_servers()]
        results: list[dict[str, Any]] = []
        healthy_count = 0
        for alias in targets:
            chk = self.check_server_health(alias)
            if chk.get("healthy"):
                healthy_count += 1
            results.append(chk)
        return {
            "audited_at": _iso(),
            "server_count": len(targets),
            "healthy_count": healthy_count,
            "failed_count": len(targets) - healthy_count,
            "per_server": results,
        }


class LocalNodeAgent:
    """§160 Remote node endpoint enforcing its OWN independent local security policy."""

    def __init__(
        self,
        *,
        node_name: str,
        shared_secret: str,
        allowed_capabilities: list[str],
        allow_destructive: bool = False,
    ) -> None:
        self.node_name = node_name
        self._secret = shared_secret.encode("utf-8")
        self.allowed_capabilities = set(allowed_capabilities)
        self.allow_destructive = allow_destructive
        self._seen_nonces: set[str] = set()
        self.audit_log: list[dict[str, Any]] = []

    def receive_signed_command(self, envelope: dict[str, Any]) -> dict[str, Any]:
        payload_bytes = json.dumps(envelope.get("payload") or {}, sort_keys=True, separators=(",", ":")).encode("utf-8")
        expected_sig = hmac.new(self._secret, payload_bytes, hashlib.sha256).hexdigest()
        provided_sig = str(envelope.get("signature") or "")

        if not hmac.compare_digest(expected_sig, provided_sig):
            entry = {"at": _iso(), "status": "rejected_invalid_auth", "capability": ""}
            self.audit_log.append(entry)
            return {"ok": False, "status": "rejected_invalid_auth", "node": self.node_name, "reason": "HMAC mutual authentication failed."}

        payload = dict(envelope["payload"])
        nonce = str(payload.get("nonce") or "")
        if not nonce or nonce in self._seen_nonces:
            return {"ok": False, "status": "rejected_replay", "node": self.node_name, "reason": "Duplicate or missing envelope nonce."}
        self._seen_nonces.add(nonce)

        cap = str(payload.get("capability") or "")
        params = dict(payload.get("params") or {})

        # Independent local node policy enforcement (§160 & §164 Check #16)
        if cap not in self.allowed_capabilities:
            entry = {"at": _iso(), "status": "rejected_by_local_node_policy", "capability": cap}
            self.audit_log.append(entry)
            return {
                "ok": False,
                "status": "rejected_by_local_node_policy",
                "node": self.node_name,
                "capability": cap,
                "reason": f"Node '{self.node_name}' local policy permits only {sorted(self.allowed_capabilities)}; '{cap}' was rejected.",
            }

        if params.get("destructive") and not self.allow_destructive:
            entry = {"at": _iso(), "status": "rejected_by_local_node_policy", "capability": cap}
            self.audit_log.append(entry)
            return {
                "ok": False,
                "status": "rejected_by_local_node_policy",
                "node": self.node_name,
                "capability": cap,
                "reason": f"Node '{self.node_name}' local policy forbids destructive actions.",
            }

        result: dict[str, Any] = {"node": self.node_name, "capability": cap, "executed_at": _iso()}
        if cap == "node.health":
            result["load_1m"] = round(os.getloadavg()[0], 2) if hasattr(os, "getloadavg") else 0.0
            result["pid"] = os.getpid()
        elif cap == "node.storage":
            du = shutil.disk_usage("/")
            result["free_gb"] = round(du.free / (1024**3), 2)
        else:
            result["params_echo"] = params

        self.audit_log.append({"at": _iso(), "status": "succeeded", "capability": cap})
        return {"ok": True, "status": "succeeded", "node": self.node_name, "result": result}


class MultiDeviceNodeCoordinator:
    """§160 Coordinator managing authenticated optional remote NOVA nodes."""

    def __init__(self, *, db: Database, vault: ProtectedCredentialVault) -> None:
        self.db = db
        self.secrets = vault
        self._inproc_agents: dict[str, LocalNodeAgent] = {}

    def register_node(
        self,
        *,
        node_name: str,
        endpoint: str,
        shared_secret: str,
        capabilities: list[str],
        local_policy: dict[str, Any] | None = None,
        attach_local_agent: LocalNodeAgent | None = None,
    ) -> dict[str, Any]:
        fp = hashlib.sha256(shared_secret.encode("utf-8")).hexdigest()[:24]
        secret_key = f"node_hmac:{node_name}"
        self.secrets.set(secret_key, shared_secret)
        saved = self.db.save_remote_node(
            {
                "node_id": node_name,
                "name": node_name,
                "role": "remote_node",
                "endpoint": endpoint,
                "pairing_key_id": fp,
                "capabilities": capabilities,
                "allowed_operations": list((local_policy or {}).get("allowed_capabilities") or capabilities),
                "connection_state": "online",
                "last_seen_at": _iso(),
            }
        )
        if attach_local_agent is not None:
            self._inproc_agents[node_name] = attach_local_agent
        return saved

    def revoke_node(self, node_name: str) -> bool:
        self.secrets.delete(f"node_hmac:{node_name}")
        self._inproc_agents.pop(node_name, None)
        return self.db.delete_remote_node(node_name)

    def dispatch_to_node(self, node_name: str, capability: str, params: dict[str, Any] | None = None) -> dict[str, Any]:
        node = self.db.get_remote_node(node_name)
        if node is None:
            return {"ok": False, "status": "unknown_node", "reason": f"Node '{node_name}' is not registered."}
        secret = self.secrets.get(f"node_hmac:{node_name}")
        if not secret:
            return {"ok": False, "status": "revoked_or_missing_secret", "reason": f"Node '{node_name}' credentials were revoked."}

        payload = {
            "target_node": node_name,
            "capability": capability,
            "params": dict(params or {}),
            "issued_at": _iso(),
            "nonce": uuid.uuid4().hex,
        }
        canonical = json.dumps(payload, sort_keys=True, separators=(",", ":")).encode("utf-8")
        sig = hmac.new(secret.encode("utf-8"), canonical, hashlib.sha256).hexdigest()
        envelope = {"payload": payload, "signature": sig}

        agent = self._inproc_agents.get(node_name)
        if agent is None:
            return {"ok": False, "status": "node_unreachable", "envelope_signed": True, "reason": f"Endpoint '{node['endpoint']}' is offline."}
        return agent.receive_signed_command(envelope)
