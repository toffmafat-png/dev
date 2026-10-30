"""Linux Secret Service key storage; refuses plaintext keyring backends."""
from __future__ import annotations

import os
import re

SERVICE_NAME = "org.nova-x.desktop"
SECRET_ENV_NAMES = {
    "openai": "NOVA_OPENAI_API_KEY",
    "openai_compatible": "NOVA_OPENAI_API_KEY",
    "anthropic": "NOVA_ANTHROPIC_API_KEY",
    "gemini": "NOVA_GEMINI_API_KEY",
    "xai": "NOVA_XAI_API_KEY",
    "deepseek": "NOVA_DEEPSEEK_API_KEY",
    "mistral": "NOVA_MISTRAL_API_KEY",
    "ollama": "NOVA_OLLAMA_API_KEY",
    "llama_cpp": "NOVA_LLAMA_CPP_API_KEY",
}
_SECRET_ALIASES = {
    "NOVA_OPENAI_API_KEY": ("NOVA_OPENAI_API_KEY", "OPENAI_API_KEY", "AI_API_KEY"),
    "NOVA_ANTHROPIC_API_KEY": ("NOVA_ANTHROPIC_API_KEY", "ANTHROPIC_API_KEY"),
    "NOVA_GEMINI_API_KEY": ("NOVA_GEMINI_API_KEY", "GEMINI_API_KEY", "GOOGLE_API_KEY"),
    "NOVA_XAI_API_KEY": ("NOVA_XAI_API_KEY", "XAI_API_KEY"),
    "NOVA_DEEPSEEK_API_KEY": ("NOVA_DEEPSEEK_API_KEY", "DEEPSEEK_API_KEY"),
    "NOVA_MISTRAL_API_KEY": ("NOVA_MISTRAL_API_KEY", "MISTRAL_API_KEY"),
    "NOVA_OLLAMA_API_KEY": ("NOVA_OLLAMA_API_KEY", "OLLAMA_API_KEY"),
    "NOVA_LLAMA_CPP_API_KEY": ("NOVA_LLAMA_CPP_API_KEY", "LLAMA_CPP_API_KEY"),
    "NOVA_TAVILY_API_KEY": ("NOVA_TAVILY_API_KEY", "TAVILY_API_KEY"),
}
_SECRET_NAME = re.compile(r"^NOVA_[A-Z0-9_]{2,60}_API_KEY$")


class SecretStoreError(RuntimeError):
    pass


class SecretStore:
    """Stores API credentials in a verified Secret Service-compatible backend."""

    def __init__(self, keyring_module=None, service_name: str = SERVICE_NAME):
        self._keyring = keyring_module
        self.service_name = service_name
        self._activated: dict[str, str | None] = {}
        if self._keyring is None:
            try:
                import keyring as keyring_module_import
                self._keyring = keyring_module_import
            except ImportError:
                self._keyring = None

    def backend_status(self) -> dict[str, str | bool]:
        if self._keyring is None:
            return {"available": False, "backend": "missing", "detail": "Install python3-keyring and an unlocked Linux Secret Service provider."}
        try:
            backend = self._keyring.get_keyring()
            module = type(backend).__module__.lower()
            name = type(backend).__name__
            safe_backend = "secretservice" in module or "secretstorage" in module or "secret service" in name.lower()
            if not safe_backend or float(getattr(backend, "priority", 0)) <= 0:
                return {"available": False, "backend": name, "detail": "The active keyring backend is not a verified Secret Service backend; plaintext and fallback stores are refused."}
            return {"available": True, "backend": name, "detail": "Linux Secret Service backend detected. It may prompt to unlock the desktop keyring."}
        except Exception as exc:
            return {"available": False, "backend": "unavailable", "detail": f"Secret Service could not be reached ({type(exc).__name__})."}

    def _require_backend(self) -> None:
        status = self.backend_status()
        if not status["available"]:
            raise SecretStoreError(str(status["detail"]))

    @staticmethod
    def _validate_name(name: str) -> None:
        if not isinstance(name, str) or not _SECRET_NAME.fullmatch(name):
            raise ValueError("Credential reference is not an approved NOVA keyring name.")

    def set_secret(self, name: str, secret: str) -> None:
        self._validate_name(name)
        if not isinstance(secret, str) or not secret.strip() or len(secret) > 8192:
            raise ValueError("Credential value must be non-empty and at most 8192 characters.")
        self._require_backend()
        try:
            self._keyring.set_password(self.service_name, name, secret.strip())
        except Exception as exc:
            raise SecretStoreError(f"Secret Service could not save the credential ({type(exc).__name__}).") from None

    def get_secret(self, name: str) -> str | None:
        self._validate_name(name)
        self._require_backend()
        try:
            return self._keyring.get_password(self.service_name, name)
        except Exception as exc:
            raise SecretStoreError(f"Secret Service could not retrieve the credential ({type(exc).__name__}).") from None

    def delete_secret(self, name: str) -> bool:
        self._validate_name(name)
        self._require_backend()
        try:
            self._keyring.delete_password(self.service_name, name)
            return True
        except Exception as exc:
            if type(exc).__name__ in {"PasswordDeleteError", "PasswordNotFoundError"}:
                return False
            raise SecretStoreError(f"Secret Service could not delete the credential ({type(exc).__name__}).") from None

    def has_secret(self, name: str) -> bool:
        return bool(self.get_secret(name))

    def activate_environment(self) -> None:
        """Expose only keyring-managed credentials to this process while it is active."""
        for name in {alias for aliases in _SECRET_ALIASES.values() for alias in aliases}:
            self._activated.setdefault(name, os.environ.get(name))
            os.environ.pop(name, None)
        self._require_backend()
        for stored_name, aliases in _SECRET_ALIASES.items():
            secret = self.get_secret(stored_name)
            if not secret:
                continue
            for name in aliases:
                os.environ[name] = secret

    def deactivate_environment(self) -> None:
        for name, previous in self._activated.items():
            if previous is None:
                os.environ.pop(name, None)
            else:
                os.environ[name] = previous
        self._activated.clear()

    def configured_status(self) -> dict[str, bool]:
        status = self.backend_status()
        if not status["available"]:
            return dict.fromkeys(SECRET_ENV_NAMES, False)
        result: dict[str, bool] = {}
        for provider, name in SECRET_ENV_NAMES.items():
            try:
                result[provider] = bool(self.get_secret(name))
            except SecretStoreError:
                result[provider] = False
        return result
