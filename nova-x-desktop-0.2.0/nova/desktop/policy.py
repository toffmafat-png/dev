"""Command policy for the native local executor.

Routine command matching is exact token-prefix matching, never shell/glob
interpolation. Commands not explicitly trusted need a one-time approval.
"""
from __future__ import annotations

import re
import shlex
import shutil
from pathlib import Path
from typing import Any

from nova.db import Database

DEFAULT_TRUSTED_PREFIXES: list[list[str]] = [
    ["pwd"],
    ["ls"],
    ["git", "status"],
    ["git", "branch", "--show-current"],
    ["uname"],
    ["df"],
    ["free"],
    ["ip", "addr", "show"],
    ["ip", "route", "show"],
    ["ss", "-lnt"],
]

_RESTRICTED_COMMANDS = {
    "sudo", "su", "doas", "pkexec", "rm", "rmdir", "dd", "shred", "wipefs",
    "mkfs", "mkfs.ext4", "mkfs.vfat", "fdisk", "parted", "sfdisk", "mount", "umount",
    "reboot", "poweroff", "shutdown", "halt", "systemctl", "service", "apt", "apt-get",
    "dpkg", "nala", "iptables", "ip6tables", "nft", "ufw", "firewall-cmd", "chmod",
    "chown", "chgrp", "useradd", "userdel", "passwd", "modprobe", "insmod", "rmmod",
    "kill", "pkill", "killall", "crontab", "loginctl", "grub-install", "update-grub",
    "mv", "cp", "install", "truncate", "touch", "mkdir", "tar", "gzip", "bzip2",
    "xz", "pip", "pip3", "npm", "npx", "yarn", "pnpm", "curl", "wget", "ssh", "scp",
    "sftp", "nc", "ncat", "netcat", "socat", "telnet", "ftp", "rsync", "docker", "podman",
    "kubectl", "terraform", "ansible", "nmap", "masscan", "nikto", "sqlmap", "msfconsole",
    "msfvenom", "hydra", "hashcat", "john", "aircrack-ng", "wifite", "responder", "tcpdump",
    "wireshark", "burpsuite", "ettercap", "bettercap", "reaver", "wash", "airmon-ng",
    "pytest", "make", "cmake", "ninja", "gradle", "mvn", "cargo", "go", "javac", "java",
    "find", "grep", "rg", "ripgrep", "fd", "cat", "tac", "less", "more", "head", "tail",
    "sed", "awk", "strings", "xxd", "base64", "bat", "file", "wc", "diff", "cmp", "od",
    "hexdump", "sha256sum", "sha1sum", "sha512sum", "md5sum", "b2sum", "cksum", "objdump",
    "readelf", "pdftotext", "pdftohtml", "pdfinfo", "exiftool", "unzip", "zipinfo", "7z", "tree",
}
_SHELLS = {"sh", "bash", "dash", "zsh", "fish", "ksh", "csh", "tcsh"}
_PRIVILEGE_WRAPPERS = {"sudo", "su", "doas", "pkexec"}
_INTERPRETERS = {
    "python", "python2", "python3", "node", "nodejs", "ruby", "perl", "php", "lua", "luajit",
    "r", "rscript", "julia", "deno", "bun", "pwsh", "powershell", "dotnet", "ghci", "runghc",
    "gjs", "qjs", "quickjs", "tclsh", "wish", "elixir", "iex", "erl", "escript", "sqlite3",
}
_BUILD_RUNNERS = {
    "pytest", "make", "cmake", "ninja", "gradle", "mvn", "cargo", "go", "rustc", "javac", "java",
    "cc", "gcc", "g++", "clang", "clang++", "ld", "ar", "as", "nasm", "yasm", "kotlinc", "scalac",
    "sbt", "haxe",
}
_FILE_ACCESS_PROGRAMS = {
    "find", "grep", "rg", "ripgrep", "fd", "cat", "tac", "less", "more", "head", "tail", "sed", "awk",
    "strings", "xxd", "base64", "bat", "file", "wc", "diff", "cmp", "od", "hexdump", "sha256sum",
    "sha1sum", "sha512sum", "md5sum", "b2sum", "cksum", "objdump", "readelf", "pdftotext", "pdftohtml",
    "pdfinfo", "exiftool", "unzip", "zipinfo", "7z", "tree", "jq", "yq", "xmllint", "xmlstarlet",
    "csvcut", "csvgrep", "csvlook", "xsv", "qsv",
}
_FILE_MUTATION_PROGRAMS = {
    "cp", "mv", "install", "truncate", "touch", "mkdir", "rmdir", "dd", "tee", "ln", "tar", "gzip",
    "bzip2", "xz", "zip", "cpio", "unrar",
}
AGENT_BLOCKED_PROGRAMS = _INTERPRETERS | _SHELLS | _BUILD_RUNNERS | _FILE_ACCESS_PROGRAMS | _FILE_MUTATION_PROGRAMS
AGENT_ONLY_BLOCKED_PROGRAMS = {"git"}
AGENT_BLOCKED_WRAPPERS = {"env", "timeout", "nohup", "xargs", "parallel", "busybox", "chroot", "nice", "stdbuf", "setsid", "taskset", "command", "watch", "flock", "time", "script", "setpriv", "setarch", "daemon", "chpst"}
_NETWORK_OR_SECURITY_TOOLS = {"curl", "wget", "ssh", "scp", "sftp", "nc", "ncat", "netcat", "socat", "telnet", "ftp", "rsync", "nmap", "masscan", "nikto", "sqlmap", "msfconsole", "msfvenom", "hydra", "hashcat", "john", "aircrack-ng", "wifite", "responder", "tcpdump", "wireshark", "burpsuite", "ettercap", "bettercap", "reaver", "wash", "airmon-ng"}


def _is_interpreter_program(executable: str) -> bool:
    name = str(executable).lower()
    if name in _INTERPRETERS:
        return True
    return bool(re.fullmatch(r"(?:python|ruby|perl|php)\d*(?:\.\d+)*|lua\d+(?:\.\d+)*", name))
_SENSITIVE_PATH_FRAGMENTS = {
    ".ssh", ".gnupg", ".aws", ".kube", ".netrc", ".npmrc", ".pypirc", "id_rsa",
    "id_ed25519", "credentials", "secrets", "keyrings", ".env", "token.json",
}
_SENSITIVE_FLAGS = {
    "--password", "--passwd", "--token", "--api-key", "--secret", "--authorization",
    "--client-secret", "--access-token", "--refresh-token", "-H", "--header", "-u", "--user", "--auth",
}


def normalize_roots(raw_roots: Any) -> list[Path]:
    roots: list[Path] = []
    if not isinstance(raw_roots, list):
        return roots
    for item in raw_roots[:32]:
        if not isinstance(item, str) or not item.strip():
            continue
        try:
            path = Path(item).expanduser().resolve(strict=True)
            if path.is_dir() and path not in roots:
                roots.append(path)
        except (OSError, RuntimeError):
            continue
    return roots


def is_within(path: Path, roots: list[Path]) -> bool:
    try:
        resolved = path.expanduser().resolve(strict=True)
    except (OSError, RuntimeError):
        return False
    return any(resolved == root or root in resolved.parents for root in roots)


def redact_text(text: str) -> str:
    """Best-effort redaction before logs, UI, history, and model tool results."""
    value = str(text)
    patterns = (
        (r"(?i)\bBearer\s+[A-Za-z0-9._~+/=-]{8,}", "Bearer [REDACTED]"),
        (r"\bsk-[A-Za-z0-9_-]{16,}\b", "[REDACTED_API_KEY]"),
        (r"\bAIza[A-Za-z0-9_-]{20,}\b", "[REDACTED_API_KEY]"),
        (r"\bgh[pousr]_[A-Za-z0-9]{20,}\b", "[REDACTED_TOKEN]"),
        (r"\bxox[baprs]-[A-Za-z0-9-]{16,}\b", "[REDACTED_TOKEN]"),
        (r"(?is)-----BEGIN [A-Z0-9 ]*PRIVATE KEY-----.*?-----END [A-Z0-9 ]*PRIVATE KEY-----", "[REDACTED_PRIVATE_KEY]"),
        (r"(?im)(authorization\s*:\s*)[^\r\n]+", r"\1[REDACTED]"),
        (r"(?i)\b(api[_-]?key|password|passwd|token|secret|authorization)\s*[:=]\s*([^\s,;]+)", r"\1=[REDACTED]"),
    )
    for pattern, replacement in patterns:
        value = re.sub(pattern, replacement, value)
    return value


def sensitive_values_from_argv(argv: list[str]) -> list[str]:
    values: list[str] = []
    redact_next = False
    for token in argv:
        text = str(token)
        if redact_next:
            if len(text) >= 3:
                values.append(text)
            redact_next = False
            continue
        if text.lower() in _SENSITIVE_FLAGS:
            redact_next = True
            continue
        match = re.search(r"(?i)(?:api[_-]?key|password|passwd|token|secret|authorization)\s*=\s*([^\s,;]+)", text)
        if match and len(match.group(1)) >= 3:
            values.append(match.group(1).strip("'\""))
        for pattern in (r"\bsk-[A-Za-z0-9_-]{16,}\b", r"\bAIza[A-Za-z0-9_-]{20,}\b", r"\bgh[pousr]_[A-Za-z0-9]{20,}\b", r"\bxox[baprs]-[A-Za-z0-9-]{16,}\b"):
            values.extend(re.findall(pattern, text))
    return list(dict.fromkeys(value for value in values if value))


def safe_argv_for_history(argv: list[str]) -> list[str]:
    safe: list[str] = []
    redact_next = False
    for item in argv[:128]:
        text = str(item)
        if redact_next:
            safe.append("[REDACTED]")
            redact_next = False
            continue
        if text.lower() in _SENSITIVE_FLAGS:
            safe.append(text)
            redact_next = True
        elif re.search(r"(?i)(api[_-]?key|password|passwd|token|secret|authorization)\s*=", text):
            safe.append(re.sub(r"=.*$", "=[REDACTED]", text))
        else:
            safe.append(redact_text(text))
    return safe


class CommandPolicy:
    def __init__(self, database: Database):
        self.database = database

    def roots(self) -> list[Path]:
        return normalize_roots(self.database.get_desktop_setting("workspace_roots", []))

    def trusted_prefixes(self) -> list[list[str]]:
        raw = self.database.get_desktop_setting("trusted_command_prefixes", DEFAULT_TRUSTED_PREFIXES)
        if not isinstance(raw, list):
            return [list(item) for item in DEFAULT_TRUSTED_PREFIXES]
        valid: list[list[str]] = []
        for item in raw[:100]:
            if isinstance(item, list) and item and all(isinstance(token, str) and token and len(token) <= 256 for token in item[:16]):
                valid.append(list(item[:16]))
        return valid

    @staticmethod
    def validate_prefixes(raw: list[str] | list[list[str]]) -> list[list[str]]:
        if not isinstance(raw, list) or len(raw) > 100:
            raise ValueError("Use no more than 100 explicit command prefixes.")
        result: list[list[str]] = []
        for item in raw:
            if isinstance(item, str):
                try:
                    tokens = shlex.split(item)
                except ValueError as exc:
                    raise ValueError("A command prefix contains unmatched shell quoting.") from exc
            elif isinstance(item, list):
                tokens = item
            else:
                raise ValueError("Each trusted prefix must be command text or a token list.")
            if not tokens or len(tokens) > 16 or any(not isinstance(token, str) or not token or len(token) > 256 or "\x00" in token for token in tokens):
                raise ValueError("Each trusted prefix needs 1–16 non-empty tokens of at most 256 characters.")
            executable = Path(tokens[0]).name.lower()
            if _is_interpreter_program(executable):
                raise ValueError("Interpreters and code runners cannot be persistently pre-authorized; each execution needs fresh review because it can execute workspace code.")
            if executable in _RESTRICTED_COMMANDS or executable in _SHELLS or executable in AGENT_BLOCKED_PROGRAMS or executable in AGENT_BLOCKED_WRAPPERS:
                raise ValueError(f"'{executable}' is restricted and cannot be pre-authorized as an automatic command.")
            if executable == "git" and tokens not in (["git", "status"], ["git", "branch", "--show-current"]):
                raise ValueError("Only the exact read-only Git status/current-branch prefixes may be persistently pre-authorized.")
            if "/" in tokens[0] or "\\" in tokens[0]:
                raise ValueError("Trusted prefixes must use a bare program name, not an absolute executable path.")
            if any(any(marker in token for marker in (";", "&&", "||", "`", "$(", "\n", "\r")) for token in tokens):
                raise ValueError("Shell operators are not accepted in automatic command prefixes.")
            result.append(tokens)
        return result

    @staticmethod
    def _has_sensitive_path_or_flag(argv: list[str]) -> bool:
        for token in argv:
            normalized = token.replace("\\", "/").lower()
            pieces = set(normalized.split("/"))
            if pieces & _SENSITIVE_PATH_FRAGMENTS:
                return True
            if any(fragment in normalized for fragment in ("id_rsa", "id_ed25519", ".env.", "credentials.json", "/etc/shadow", "/etc/gshadow")):
                return True
        for idx, token in enumerate(argv):
            if token.lower() in _SENSITIVE_FLAGS and idx + 1 < len(argv):
                return True
            if re.search(r"(?i)(api[_-]?key|password|passwd|token|secret|authorization)\s*=", token):
                return True
        return False

    @staticmethod
    def _safe_auto_tail(prefix: list[str], argv: list[str]) -> bool:
        """Keep default diagnostic/read-only prefixes from gaining dangerous flags."""
        if prefix in (["pwd"], ["ls"], ["uname"], ["df"], ["free"], ["ss", "-lnt"], ["git", "status"], ["git", "branch", "--show-current"]):
            return len(argv) == len(prefix)
        forbidden = {"--output", "--output=", "--ext-diff", "--textconv", "--exec", "--upload-pack", "--receive-pack"}
        if any(token in forbidden or token.startswith("--output=") for token in argv[len(prefix):]):
            return False
        if prefix[:2] == ["ip", "addr"] and len(argv) > len(prefix):
            return all(token in {"dev", "lo", "eth0", "wlan0", "wlan1", "ens33", "enp0s3", "--details", "-details", "--statistics"} for token in argv[len(prefix):])
        if prefix[:2] == ["ip", "route"] and len(argv) > len(prefix):
            return all(token in {"table", "main", "default", "--details", "-details"} for token in argv[len(prefix):])
        return True

    @staticmethod
    def _is_catastrophic_command(argv: list[str]) -> str | None:
        if not argv:
            return None
        joined = " ".join(argv).strip()
        exe = Path(argv[0]).name.lower()
        if exe in {"mkfs", "wipefs", "fdisk", "parted", "sfdisk"} or exe.startswith("mkfs."):
            return f"Catastrophic disk/filesystem formatter '{exe}' is blocked from automatic execution."
        if exe == "dd" and any(tok.startswith("of=/dev/") for tok in argv[1:]):
            return "Raw block-device write via 'dd of=/dev/...' is blocked to prevent unrecoverable disk loss."
        if exe in {"rm", "shred"}:
            flags = {tok for tok in argv[1:] if tok.startswith("-")}
            targets = [tok.rstrip("/") or "/" for tok in argv[1:] if not tok.startswith("-")]
            recursive = any("r" in f.lower() for f in flags) or "--no-preserve-root" in flags
            critical = {"/", "/boot", "/etc", "/usr", "/var", "/home", "/root", "~", "*"}
            if "--no-preserve-root" in flags or (recursive and any(t in critical for t in targets)):
                return "Catastrophic recursive deletion targeting a root or critical system tree is blocked."
        if ":(){ :|:& };:" in joined:
            return "Fork bomb pattern is blocked."
        return None

    def check_personal_grant(self, argv: list[str], cwd: str, *, privileged: bool = False) -> dict[str, Any] | None:
        """Evaluate user-configured single-user personal persistent grants & power-user mode."""
        if privileged or not argv:
            return None
        if self._is_catastrophic_command(argv) is not None:
            return None
        if self._has_sensitive_path_or_flag(argv):
            return None
        executable = Path(argv[0]).name.lower()
        if executable in _PRIVILEGE_WRAPPERS:
            return None
        if executable in _SHELLS and any(item in {"-c", "--command"} for item in argv[1:]):
            return None
        executable_path = shutil.which(argv[0])
        if not executable_path:
            return None
        try:
            working_dir = Path(cwd).expanduser().resolve(strict=True)
        except (OSError, RuntimeError):
            return None
        if not working_dir.is_dir():
            return None

        # 1. Explicit persistent grants stored in SQLite by the user
        grants = self.database.list_personal_persistent_grants(active_only=True)
        for grant in grants:
            programs = [str(p).lower() for p in (grant.get("allowed_programs") or [])]
            if programs and "*" not in programs and executable not in programs:
                continue
            scope_target = str(grant.get("scope_target") or "").strip()
            scope_matched = False
            if scope_target == "*":
                scope_matched = True
            elif grant.get("domain") == "software_and_security_research":
                # Cyber lab target scope (e.g. 127.0.0.1, localhost, .lab.internal, or lab directory)
                if any(scope_target in tok for tok in argv[1:]):
                    scope_matched = True
                else:
                    try:
                        sp = Path(scope_target).expanduser().resolve(strict=False)
                        scope_matched = working_dir == sp or sp in working_dir.parents
                    except OSError:
                        scope_matched = False
            else:
                try:
                    sp = Path(scope_target).expanduser().resolve(strict=False)
                    scope_matched = working_dir == sp or sp in working_dir.parents
                except OSError:
                    scope_matched = False
            if scope_matched:
                return {
                    "action": "allow",
                    "rule": "personal_persistent_grant",
                    "grant_id": grant["grant_id"],
                    "reason": f"Authorized by persistent personal permission grant '{grant['grant_id']}' without repeated prompt.",
                    "executable": executable_path,
                    "cwd": str(working_dir),
                }

        # 2. Configured personal_power_user / cyber_lab_research profile inside workspace roots
        cfg = self.database.get_personal_policy_config()
        if cfg and cfg.get("profile_mode") in {"personal_power_user", "cyber_lab_research"}:
            from nova.personal_policy.engine import DEFAULT_POWER_USER_PROGRAMS

            roots = self.roots()
            is_power_prog = executable in DEFAULT_POWER_USER_PROGRAMS or bool(
                re.fullmatch(r"python3(?:\.\d+)?", executable)
            )
            if roots and is_within(working_dir, roots) and is_power_prog:
                return {
                    "action": "allow",
                    "rule": "personal_power_user_profile",
                    "reason": f"Authorized by '{cfg['profile_mode']}' personal policy inside owned workspace.",
                    "executable": executable_path,
                    "cwd": str(working_dir),
                }
        return None

    def evaluate(self, argv: list[str], cwd: str, *, privileged: bool = False) -> dict[str, Any]:
        if not argv or len(argv) > 128 or any(not isinstance(item, str) or "\x00" in item or len(item) > 8192 for item in argv):
            return {"action": "deny", "rule": "invalid_arguments", "reason": "Command arguments are invalid or exceed the bounded limit."}
        executable = Path(argv[0]).name.lower()
        if executable in _SHELLS and any(item in {"-c", "--command"} for item in argv[1:]):
            return {"action": "deny", "rule": "shell_command_string_blocked", "reason": "Model-supplied shell command strings are blocked; use structured program arguments or a reviewed script in an authorized workspace."}
        if executable in _PRIVILEGE_WRAPPERS:
            return {"action": "deny", "rule": "privilege_wrapper_blocked", "reason": "Do not invoke sudo, su, doas, or pkexec through process.execute. Use system.run_privileged for one reviewed action and the normal polkit agent."}
        catastrophic_reason = self._is_catastrophic_command(argv)
        if catastrophic_reason is not None:
            return {"action": "deny", "rule": "catastrophic_system_modification_blocked", "reason": catastrophic_reason}
        executable_path = shutil.which(argv[0])
        if not executable_path:
            return {"action": "deny", "rule": "command_not_found", "reason": f"Command '{executable}' is not installed or not on PATH."}
        personal_grant = self.check_personal_grant(argv, cwd, privileged=privileged)
        if personal_grant is not None:
            return personal_grant
        if executable == "git" and len(argv) > 1 and argv[1].lower() in {"push", "pull", "fetch", "clone", "reset", "clean", "checkout", "restore", "rebase", "commit", "cherry-pick", "revert", "merge", "config", "remote", "submodule", "am"}:
            return {"action": "approval_required", "rule": "git_mutation_or_network", "reason": f"Git '{argv[1]}' can modify repository state or contact a remote and always needs fresh approval."}
        if executable == "ip" and (len(argv) < 3 or argv[1:3] not in (["addr", "show"], ["route", "show"], ["link", "show"], ["neigh", "show"])):
            return {"action": "approval_required", "rule": "network_configuration", "reason": "Only read-only 'ip ... show' diagnostics may be pre-authorized; network configuration changes always need fresh approval."}
        if self._has_sensitive_path_or_flag(argv):
            return {"action": "approval_required", "rule": "sensitive_argument", "reason": "This command references a sensitive path or credential-like argument and needs a one-time review. NOVA will redact its output, but avoid placing secrets in command arguments."}
        if _is_interpreter_program(executable):
            return {"action": "approval_required", "rule": "code_execution", "reason": "Interpreters can execute workspace code and always need fresh approval; persistent automatic trust is not supported."}
        if executable in _RESTRICTED_COMMANDS and not privileged:
            return {"action": "approval_required", "rule": "restricted_command", "reason": f"'{executable}' can make system-wide, destructive, or security-sensitive changes and always needs a one-time review."}
        if privileged:
            return {"action": "approval_required", "rule": "privileged_action", "reason": "Privileged operations always need fresh approval and normal polkit authentication."}
        if executable in AGENT_BLOCKED_PROGRAMS or executable in AGENT_BLOCKED_WRAPPERS:
            return {"action": "approval_required", "rule": "protected_command", "reason": f"'{executable}' cannot be persistently pre-authorized; local use needs fresh review because it can execute code or access/modify files."}
        try:
            working_dir = Path(cwd).expanduser().resolve(strict=True)
        except (OSError, RuntimeError):
            return {"action": "deny", "rule": "invalid_working_directory", "reason": "Working directory does not exist or cannot be resolved safely."}
        if not working_dir.is_dir():
            return {"action": "deny", "rule": "working_directory_not_directory", "reason": "Working directory is not a directory."}
        in_workspace = is_within(working_dir, self.roots())
        trusted = False
        bare_executable = "/" not in argv[0] and "\\" not in argv[0]
        if in_workspace and bare_executable:
            for prefix in self.trusted_prefixes():
                if len(argv) >= len(prefix) and argv[:len(prefix)] == prefix and self._safe_auto_tail(prefix, argv):
                    trusted = True
                    break
        if trusted:
            return {
                "action": "allow", "rule": "trusted_command_prefix", "reason": "Command matches a saved token-exact prefix inside a selected workspace.",
                "executable": executable_path, "cwd": str(working_dir),
            }
        return {
            "action": "approval_required", "rule": "not_pre_authorized", "reason": "Command is outside the automatic command policy or selected workspace; review the exact executable, arguments, and directory.",
            "executable": executable_path, "cwd": str(working_dir),
        }
