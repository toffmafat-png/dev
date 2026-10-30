"""§229.C, §230 & §234 Encrypted Credential Vault, TAR/Zstandard/XZ Multi-Volume Codec & Path-Traversal Defense."""
from __future__ import annotations

import hashlib
import hmac
import io
import json
import os
import secrets
import shutil
import subprocess
import tarfile
from pathlib import Path
from typing import Any

MIGRATION_FORMAT_VERSION = "nova-dev-migration-v1"
VAULT_MAGIC_AESGCM = b"NVXVLT01"
VAULT_MAGIC_STDLIB = b"NVXVLT02"
PBKDF2_ITERATIONS = 250_000


class ArchiveSecurityError(RuntimeError):
    """Raised when an untrusted migration archive fails path-traversal, link, checksum, or tamper checks."""


class MigrationVaultCipher:
    """§229.C & §234 Passphrase-based Authenticated Encryption for Credentials & Sensitive Archives."""

    @staticmethod
    def encrypt_bytes(plaintext: bytes, passphrase: str) -> bytes:
        if not isinstance(passphrase, str) or len(passphrase) < 8:
            raise ValueError("Passphrase must be at least 8 characters for encrypted migration transfer (§229/§234).")
        salt = secrets.token_bytes(16)
        key = hashlib.pbkdf2_hmac("sha256", passphrase.encode("utf-8"), salt, PBKDF2_ITERATIONS, dklen=32)

        try:
            from cryptography.hazmat.primitives.ciphers.aead import AESGCM

            nonce = secrets.token_bytes(12)
            ct = AESGCM(key).encrypt(nonce, plaintext, VAULT_MAGIC_AESGCM)
            return VAULT_MAGIC_AESGCM + salt + nonce + ct
        except ImportError:
            nonce = secrets.token_bytes(16)
            enc_key = hmac.new(key, b"enc:" + nonce, hashlib.sha256).digest()
            mac_key = hmac.new(key, b"mac:" + nonce, hashlib.sha256).digest()
            ct = MigrationVaultCipher._xor_keystream(plaintext, enc_key, nonce)
            tag = hmac.new(mac_key, VAULT_MAGIC_STDLIB + salt + nonce + ct, hashlib.sha256).digest()
            return VAULT_MAGIC_STDLIB + salt + nonce + tag + ct

    @staticmethod
    def decrypt_bytes(blob: bytes, passphrase: str) -> bytes:
        if not isinstance(passphrase, str) or not passphrase:
            raise ArchiveSecurityError("Passphrase is required to decrypt protected migration vault.")
        if len(blob) < 40:
            raise ArchiveSecurityError("Encrypted vault payload is truncated or invalid.")

        magic = blob[:8]
        salt = blob[8:24]
        key = hashlib.pbkdf2_hmac("sha256", passphrase.encode("utf-8"), salt, PBKDF2_ITERATIONS, dklen=32)

        if magic == VAULT_MAGIC_AESGCM:
            try:
                from cryptography.hazmat.primitives.ciphers.aead import AESGCM

                nonce = blob[24:36]
                ct = blob[36:]
                return AESGCM(key).decrypt(nonce, ct, VAULT_MAGIC_AESGCM)
            except Exception as exc:
                raise ArchiveSecurityError("Vault decryption or authentication tag verification failed.") from exc

        if magic == VAULT_MAGIC_STDLIB:
            nonce = blob[24:40]
            tag = blob[40:72]
            ct = blob[72:]
            enc_key = hmac.new(key, b"enc:" + nonce, hashlib.sha256).digest()
            mac_key = hmac.new(key, b"mac:" + nonce, hashlib.sha256).digest()
            expected = hmac.new(mac_key, VAULT_MAGIC_STDLIB + salt + nonce + ct, hashlib.sha256).digest()
            if not hmac.compare_digest(tag, expected):
                raise ArchiveSecurityError("Vault HMAC authentication tag verification failed.")
            return MigrationVaultCipher._xor_keystream(ct, enc_key, nonce)

        raise ArchiveSecurityError("Unrecognized encrypted migration header.")

    @staticmethod
    def _xor_keystream(data: bytes, enc_key: bytes, nonce: bytes) -> bytes:
        out = bytearray(len(data))
        counter = 0
        pos = 0
        while pos < len(data):
            block = hashlib.sha256(enc_key + nonce + counter.to_bytes(8, "big")).digest()
            chunk_len = min(32, len(data) - pos)
            for idx in range(chunk_len):
                out[pos + idx] = data[pos + idx] ^ block[idx]
            pos += chunk_len
            counter += 1
        return bytes(out)


class UniversalMigrationArchiveCodec:
    """§230 & §234 Versioned TAR (+ Zstandard / XZ / Gzip), Multi-Volume Splitting & Untrusted Archive Validator."""

    AUTO_UPLOAD_TO_CLOUD_STORAGE = False
    AUTO_EXECUTE_EMBEDDED_SCRIPTS = False

    EXCLUDED_HEAVY_DIR_NAMES: frozenset[str] = frozenset(
        {
            "node_modules",
            "__pycache__",
            ".pytest_cache",
            ".ruff_cache",
            ".mypy_cache",
            ".cache",
            ".venv",
            ".dev_env",
            "target",
            "build",
            "dist",
        }
    )

    @classmethod
    def preferred_compression(cls, requested: str = "auto") -> tuple[str, str]:
        """Return (codec_name, file_extension). Supports zstd when available, xz/gzip universally."""
        req = requested.strip().lower()
        if req in {"zstd", "auto"} and shutil.which("zstd"):
            return "zstd", ".tar.zst"
        if req == "xz":
            return "xz", ".tar.xz"
        return "gzip", ".tar.gz"

    @classmethod
    def pack_staging_directory(
        cls,
        staging_dir: Path,
        dest_archive_base: Path,
        *,
        compression: str = "auto",
        encrypt_passphrase: str = "",
        volume_max_bytes: int = 0,
    ) -> dict[str, Any]:
        """§230 Compress `staging_dir` into a checksummed TAR (.tar.zst / .tar.xz / .tar.gz), optionally encrypted & split."""
        codec, ext = cls.preferred_compression(compression)
        raw_tar_bytes = cls._create_deterministic_tar_bytes(staging_dir, codec=codec)

        encrypted = False
        if encrypt_passphrase:
            final_bytes = MigrationVaultCipher.encrypt_bytes(raw_tar_bytes, encrypt_passphrase)
            ext = ext + ".enc"
            encrypted = True
        else:
            final_bytes = raw_tar_bytes

        archive_path = dest_archive_base.with_name(dest_archive_base.name + ext)
        archive_path.parent.mkdir(parents=True, exist_ok=True)
        archive_path.write_bytes(final_bytes)
        os.chmod(archive_path, 0o600)

        overall_sha256 = hashlib.sha256(final_bytes).hexdigest()
        volumes: list[dict[str, Any]] = []
        if volume_max_bytes and volume_max_bytes >= 1024 and len(final_bytes) > volume_max_bytes:
            idx = 1
            for offset in range(0, len(final_bytes), volume_max_bytes):
                chunk = final_bytes[offset : offset + volume_max_bytes]
                vol_path = archive_path.with_name(f"{archive_path.name}.part{idx:03d}")
                vol_path.write_bytes(chunk)
                os.chmod(vol_path, 0o600)
                volumes.append(
                    {
                        "part": idx,
                        "path": str(vol_path),
                        "size_bytes": len(chunk),
                        "sha256": hashlib.sha256(chunk).hexdigest(),
                    }
                )
                idx += 1

        return {
            "archive_path": str(archive_path),
            "compression": codec,
            "encrypted": encrypted,
            "size_bytes": len(final_bytes),
            "checksum_sha256": overall_sha256,
            "volumes": volumes,
            "uploaded_to_cloud": False,
        }

    @classmethod
    def verify_and_extract_untrusted_archive(
        cls,
        archive_path: Path,
        extract_to: Path,
        *,
        expected_archive_sha256: str = "",
        decrypt_passphrase: str = "",
        volumes: list[dict[str, Any]] | None = None,
    ) -> dict[str, Any]:
        """§234 Validate checksums, decrypt if needed, reject path traversal/links, and verify every extracted file."""
        if volumes:
            assembled = bytearray()
            for vol in sorted(volumes, key=lambda v: int(v["part"])):
                vp = Path(vol["path"])
                if not vp.is_file():
                    raise ArchiveSecurityError(f"Missing migration volume part {vol['part']}: {vp}")
                vbytes = vp.read_bytes()
                if hashlib.sha256(vbytes).hexdigest() != vol["sha256"]:
                    raise ArchiveSecurityError(f"Volume {vol['part']} SHA-256 mismatch.")
                assembled.extend(vbytes)
            blob = bytes(assembled)
        else:
            if not archive_path.is_file():
                raise ArchiveSecurityError(f"Migration archive not found: {archive_path}")
            blob = archive_path.read_bytes()

        actual_archive_sha = hashlib.sha256(blob).hexdigest()
        if expected_archive_sha256 and actual_archive_sha != expected_archive_sha256:
            raise ArchiveSecurityError(
                f"Archive SHA-256 mismatch: expected {expected_archive_sha256[:16]}..., got {actual_archive_sha[:16]}..."
            )

        if blob.startswith((VAULT_MAGIC_AESGCM, VAULT_MAGIC_STDLIB)) or str(archive_path).endswith(".enc"):
            blob = MigrationVaultCipher.decrypt_bytes(blob, decrypt_passphrase)

        raw_tar = cls._decompress_if_zstd(blob)
        extract_root = extract_to.resolve()
        extract_root.mkdir(parents=True, exist_ok=True)

        with tarfile.open(fileobj=io.BytesIO(raw_tar), mode="r:*") as tf:
            members = tf.getmembers()
            for m in members:
                cls._assert_member_safe(m, extract_root)
            for m in members:
                dest = (extract_root / m.name).resolve()
                if m.isdir():
                    dest.mkdir(parents=True, exist_ok=True)
                elif m.isfile():
                    dest.parent.mkdir(parents=True, exist_ok=True)
                    src_f = tf.extractfile(m)
                    assert src_f is not None
                    dest.write_bytes(src_f.read())

        manifest_file = extract_root / "manifest.json"
        if not manifest_file.is_file():
            raise ArchiveSecurityError("Invalid migration package: missing `manifest.json`.")
        manifest = json.loads(manifest_file.read_text(encoding="utf-8"))
        if manifest.get("format_version") != MIGRATION_FORMAT_VERSION:
            raise ArchiveSecurityError(f"Unsupported migration format version: {manifest.get('format_version')!r}")

        # Verify every single file checksum recorded in manifest.json!
        file_checksums: dict[str, str] = manifest.get("file_checksums") or {}
        verified_files = 0
        for rel_path, expected_hash in file_checksums.items():
            f_target = (extract_root / rel_path).resolve()
            if not str(f_target).startswith(str(extract_root) + os.sep):
                raise ArchiveSecurityError(f"Checksum entry escapes extraction root: {rel_path}")
            if not f_target.is_file():
                raise ArchiveSecurityError(f"Missing payload file listed in manifest: {rel_path}")
            got_hash = hashlib.sha256(f_target.read_bytes()).hexdigest()
            if got_hash != expected_hash:
                raise ArchiveSecurityError(f"Payload file checksum mismatch for `{rel_path}`.")
            verified_files += 1

        return {
            "verified": True,
            "archive_sha256": actual_archive_sha,
            "verified_files_count": verified_files,
            "embedded_scripts_executed": 0,
            "manifest": manifest,
        }

    @staticmethod
    def _assert_member_safe(member: tarfile.TarInfo, extract_root: Path) -> None:
        name = member.name
        if not name or name.startswith("/") or "\\" in name:
            raise ArchiveSecurityError(f"Rejected unsafe archive path `{name}` (§234).")
        parts = Path(name).parts
        if ".." in parts:
            raise ArchiveSecurityError(f"Rejected path-traversal entry `{name}` in archive (§234).")
        if member.issym() or member.islnk() or member.ischr() or member.isblk() or member.isfifo():
            raise ArchiveSecurityError(f"Rejected special/link tar member `{name}` in untrusted archive (§234).")
        resolved = (extract_root / name).resolve()
        if resolved != extract_root and not str(resolved).startswith(str(extract_root) + os.sep):
            raise ArchiveSecurityError(f"Rejected escaping archive member `{name}` (§234).")

    @staticmethod
    def _create_deterministic_tar_bytes(staging_dir: Path, *, codec: str) -> bytes:
        tar_mode = "w:xz" if codec == "xz" else ("w" if codec == "zstd" else "w:gz")
        buf = io.BytesIO()
        with tarfile.open(fileobj=buf, mode=tar_mode) as tf:
            for item in sorted(staging_dir.rglob("*")):
                rel = item.relative_to(staging_dir).as_posix()
                ti = tarfile.TarInfo(name=rel)
                ti.mtime = 1_700_000_000
                if item.is_dir():
                    ti.type = tarfile.DIRTYPE
                    ti.mode = 0o700
                    tf.addfile(ti)
                elif item.is_file():
                    raw = item.read_bytes()
                    ti.size = len(raw)
                    ti.mode = 0o600
                    tf.addfile(ti, io.BytesIO(raw))
        raw_bytes = buf.getvalue()
        if codec == "zstd":
            proc = subprocess.run(["zstd", "-q", "-c"], input=raw_bytes, capture_output=True, timeout=15.0, check=True)
            return proc.stdout
        return raw_bytes

    @staticmethod
    def _decompress_if_zstd(blob: bytes) -> bytes:
        # Zstandard frame magic: 0xFD2FB528 little-endian -> 28 b5 2f fd
        if blob[:4] == b"\x28\xb5\x2f\xfd":
            if not shutil.which("zstd"):
                raise ArchiveSecurityError("Archive uses Zstandard compression (`zstd`), which is not installed.")
            proc = subprocess.run(["zstd", "-d", "-q", "-c"], input=blob, capture_output=True, timeout=15.0, check=True)
            return proc.stdout
        return blob
