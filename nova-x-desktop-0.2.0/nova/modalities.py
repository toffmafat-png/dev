"""§99 Visual understanding & screen awareness and §107 Modular voice/speech layer.

Enforces strict epistemic and authorization boundaries across non-text modalities:

* **§99 Visual:** Screenshots are captured on explicit authorized request only —
  never continuously — and are never uploaded without explicit permission. Every
  visual output is marked ``epistemic_kind='visual_observation'`` and
  ``verified_system_fact=False`` so screenshots are never mistaken for ground-truth
  system state.
* **§107 Voice:** Speech recognition and synthesis are modular and optional with
  an always-on typed-input fallback, explicit microphone indicator, push-to-talk,
  barge-in interruption, and identical planner/permission routing to typed
  commands. Voice or speaker identity can never authorize privileged operations
  (``SPEAKER_ID_AUTHORIZES_PRIVILEGED = False``).
"""
from __future__ import annotations

import hashlib
import os
import re
import shutil
import struct
import subprocess
from collections.abc import Callable
from dataclasses import dataclass, field
from datetime import UTC, datetime
from pathlib import Path
from typing import Any, Protocol

CONTINUOUS_SCREEN_CAPTURE = False
SPEAKER_ID_AUTHORIZES_PRIVILEGED = False

_VISIBLE_ERROR_PATTERNS = re.compile(
    r"\b(error|exception|traceback|fatal|failed|permission denied|segmentation fault|connection refused)\b",
    re.IGNORECASE,
)


def _iso() -> str:
    return datetime.now(UTC).isoformat(timespec="microseconds")


def inspect_image_dimensions(data: bytes) -> tuple[str, int, int]:
    """Read format, width & height for PNG / GIF / PPM headers in pure Python."""
    if len(data) >= 24 and data[:8] == b"\x89PNG\r\n\x1a\n" and data[12:16] == b"IHDR":
        width, height = struct.unpack(">II", data[16:24])
        return "png", int(width), int(height)
    if len(data) >= 10 and data[:6] in {b"GIF87a", b"GIF89a"}:
        width, height = struct.unpack("<HH", data[6:10])
        return "gif", int(width), int(height)
    if data.startswith(b"P6") or data.startswith(b"P3"):
        tokens = data[:128].split()
        if len(tokens) >= 3 and tokens[1].isdigit() and tokens[2].isdigit():
            return "ppm", int(tokens[1]), int(tokens[2])
    return "unknown", 0, 0


# ------------------------------------------------------- §99 Visual Assistant


@dataclass
class VisualAssistant:
    """§99 Optional, explicit-consent screenshot, OCR and before/after diff helper."""

    workspace_root: Path
    vision_analyzer: Callable[[bytes, str], dict[str, Any]] | None = None
    upload_authorizer: Callable[[int], bool] | None = None

    def __post_init__(self) -> None:
        self.workspace_root = Path(self.workspace_root).resolve()

    @staticmethod
    def _wrap_visual_observation(payload: dict[str, Any]) -> dict[str, Any]:
        return {
            "epistemic_kind": "visual_observation",
            "verified_system_fact": False,
            "continuous_capture_enabled": CONTINUOUS_SCREEN_CAPTURE,
            "consequential_verification_note": (
                "Visual observations may not reflect complete application state; verify consequential "
                "operations via direct API, process exit code or accessible system state."
            ),
            **payload,
        }

    def capabilities(self) -> dict[str, Any]:
        has_display = bool(os.environ.get("DISPLAY") or os.environ.get("WAYLAND_DISPLAY"))
        capture_tool = next((b for b in ("grim", "scrot", "import") if shutil.which(b)), "")
        ocr_tool = shutil.which("tesseract") or ""
        return {
            "display_session_detected": has_display,
            "capture_binary": capture_tool,
            "capture_available": bool(has_display and capture_tool),
            "ocr_available": bool(ocr_tool),
            "vision_model_attached": self.vision_analyzer is not None,
            "continuous_capture_enabled": CONTINUOUS_SCREEN_CAPTURE,
        }

    def capture_screenshot_on_request(self, output_rel_path: str, *, operator_authorized: bool = False) -> dict[str, Any]:
        if not operator_authorized:
            return self._wrap_visual_observation(
                {"captured": False, "reason": "explicit operator authorization is required before capturing the screen"}
            )
        caps = self.capabilities()
        if not caps["capture_available"]:
            return self._wrap_visual_observation(
                {
                    "captured": False,
                    "reason": "no active X11/Wayland display session or screenshot utility (grim/scrot) is available",
                    "capabilities": caps,
                }
            )
        dest = (self.workspace_root / output_rel_path).resolve()
        if not dest.is_relative_to(self.workspace_root):
            raise PermissionError("Screenshot output path escapes workspace_root")
        dest.parent.mkdir(parents=True, exist_ok=True)
        binary = shutil.which(caps["capture_binary"])
        assert binary is not None
        proc = subprocess.run([binary, str(dest)], capture_output=True, text=True, timeout=10, check=False)
        if proc.returncode != 0 or not dest.is_file():
            return self._wrap_visual_observation(
                {"captured": False, "reason": proc.stderr.strip() or f"{caps['capture_binary']} exited {proc.returncode}"}
            )
        return self._wrap_visual_observation({"captured": True, "path": output_rel_path, "bytes": dest.stat().st_size})

    def extract_text_ocr(self, image_rel_path: str) -> dict[str, Any]:
        target = (self.workspace_root / image_rel_path).resolve()
        if not target.is_relative_to(self.workspace_root) or not target.is_file():
            return self._wrap_visual_observation({"ok": False, "reason": "image file not found inside workspace"})
        tesseract = shutil.which("tesseract")
        if not tesseract:
            return self._wrap_visual_observation(
                {"ok": False, "reason": "tesseract OCR binary is not installed; refusing to guess image text"}
            )
        proc = subprocess.run([tesseract, str(target), "stdout"], capture_output=True, text=True, timeout=20, check=False)
        text = proc.stdout.strip()
        errors = sorted({m.group(0) for m in _VISIBLE_ERROR_PATTERNS.finditer(text)})
        return self._wrap_visual_observation({"ok": proc.returncode == 0, "text": text, "visible_error_terms": errors})

    def compare_screenshots(self, before_rel_path: str, after_rel_path: str) -> dict[str, Any]:
        """Compare before-and-after images in pure Python without uploading anything (§99)."""
        before_p = (self.workspace_root / before_rel_path).resolve()
        after_p = (self.workspace_root / after_rel_path).resolve()
        for p in (before_p, after_p):
            if not p.is_relative_to(self.workspace_root) or not p.is_file():
                return self._wrap_visual_observation({"ok": False, "reason": f"missing image '{p.name}'"})
        b_bytes = before_p.read_bytes()
        a_bytes = after_p.read_bytes()
        b_fmt, b_w, b_h = inspect_image_dimensions(b_bytes)
        a_fmt, a_w, a_h = inspect_image_dimensions(a_bytes)
        identical = hashlib.sha256(b_bytes).digest() == hashlib.sha256(a_bytes).digest()
        min_len = min(len(b_bytes), len(a_bytes))
        max_len = max(len(b_bytes), len(a_bytes), 1)
        differing_bytes = sum(1 for x, y in zip(b_bytes[:min_len], a_bytes[:min_len], strict=False) if x != y) + (max_len - min_len)
        change_ratio = round(differing_bytes / max_len, 4)
        return self._wrap_visual_observation(
            {
                "ok": True,
                "before": {"path": before_rel_path, "format": b_fmt, "width": b_w, "height": b_h},
                "after": {"path": after_rel_path, "format": a_fmt, "width": a_w, "height": a_h},
                "visible_change_detected": not identical,
                "byte_change_ratio": 0.0 if identical else change_ratio,
            }
        )

    def inspect_with_vision_model(self, image_rel_path: str, prompt: str, *, external_upload_authorized: bool = False) -> dict[str, Any]:
        target = (self.workspace_root / image_rel_path).resolve()
        if not target.is_relative_to(self.workspace_root) or not target.is_file():
            return self._wrap_visual_observation({"ok": False, "reason": "image not found in workspace"})
        if self.vision_analyzer is None:
            return self._wrap_visual_observation({"ok": False, "reason": "no compatible vision model is configured"})
        raw = target.read_bytes()
        if not external_upload_authorized or (self.upload_authorizer is not None and not self.upload_authorizer(len(raw))):
            return self._wrap_visual_observation(
                {"ok": False, "reason": "uploading screenshots to an external vision model requires explicit authorization"}
            )
        analysis = self.vision_analyzer(raw, prompt)
        return self._wrap_visual_observation({"ok": True, "analysis": analysis})

    def correlate_with_logs(self, observed_text: str, terminal_logs: list[str]) -> dict[str, Any]:
        errors = [m.group(0).lower() for m in _VISIBLE_ERROR_PATTERNS.finditer(observed_text or "")]
        corroborated = [
            line
            for line in terminal_logs
            if any(tok in line.lower() for tok in errors) or _VISIBLE_ERROR_PATTERNS.search(line)
        ]
        return self._wrap_visual_observation(
            {
                "visible_error_indicators": sorted(set(errors)),
                "corroborating_log_lines": corroborated[:20],
                "corroborated_by_logs": bool(corroborated),
            }
        )


# ------------------------------------------------- §107 Modular Voice & Speech


class SpeechRecognizer(Protocol):
    engine_id: str
    is_local: bool

    def available(self) -> bool: ...
    def transcribe(self, audio_bytes: bytes, *, language: str, vocabulary: tuple[str, ...]) -> str: ...


class SpeechSynthesizer(Protocol):
    engine_id: str
    is_local: bool

    def available(self) -> bool: ...
    def synthesize(self, text: str, *, language: str) -> bytes: ...


@dataclass
class DeterministicLoopbackRecognizer:
    """Offline test/fallback recognizer decoding UTF-8 marker frames when supplied."""

    engine_id: str = "loopback-local-stt"
    is_local: bool = True
    is_available: bool = True

    def available(self) -> bool:
        return self.is_available

    def transcribe(self, audio_bytes: bytes, *, language: str, vocabulary: tuple[str, ...]) -> str:
        text = audio_bytes.decode("utf-8", errors="ignore").strip()
        for word in vocabulary:
            if word.lower() in text.lower():
                text = re.sub(re.escape(word), word, text, flags=re.IGNORECASE)
        return text


@dataclass
class DeterministicLoopbackSynthesizer:
    engine_id: str = "loopback-local-tts"
    is_local: bool = True
    is_available: bool = True

    def available(self) -> bool:
        return self.is_available

    def synthesize(self, text: str, *, language: str) -> bytes:
        return f"[{language}] {text}".encode()


@dataclass
class VoiceLayer:
    """§107 Pluggable STT/TTS coordinator with consent, barge-in and planner parity."""

    prefer_local: bool = True
    wake_word_enabled: bool = False
    consent_granted: bool = False
    retain_audio_recordings: bool = False
    selected_language: str = "en"
    custom_vocabulary: tuple[str, ...] = ("Kali", "NOVA", "pytest", "bubblewrap")
    recognizers: list[SpeechRecognizer] = field(default_factory=list)
    synthesizers: list[SpeechSynthesizer] = field(default_factory=list)
    _push_to_talk_active: bool = field(default=False, init=False)
    _speaking: bool = field(default=False, init=False)
    _interrupted_count: int = field(default=0, init=False)

    def select_recognizer(self) -> SpeechRecognizer | None:
        usable = [r for r in self.recognizers if r.available()]
        if not usable:
            return None
        if self.prefer_local:
            usable.sort(key=lambda r: (0 if r.is_local else 1, r.engine_id))
        return usable[0]

    def select_synthesizer(self) -> SpeechSynthesizer | None:
        usable = [s for s in self.synthesizers if s.available()]
        if not usable:
            return None
        if self.prefer_local:
            usable.sort(key=lambda s: (0 if s.is_local else 1, s.engine_id))
        return usable[0]

    @property
    def microphone_indicator(self) -> dict[str, Any]:
        return {
            "microphone_active": self._push_to_talk_active,
            "mode": "push_to_talk" if self._push_to_talk_active else ("wake_word_armed" if (self.wake_word_enabled and self.consent_granted) else "muted"),
            "typed_input_fallback_available": True,
        }

    def start_push_to_talk(self) -> dict[str, Any]:
        if not self.consent_granted:
            return {"started": False, "reason": "microphone consent has not been granted; use typed input or grant consent", **self.microphone_indicator}
        if self._speaking:
            self.interrupt_speech()
        self._push_to_talk_active = True
        return {"started": True, **self.microphone_indicator}

    def stop_push_to_talk(self) -> dict[str, Any]:
        self._push_to_talk_active = False
        return {"stopped": True, **self.microphone_indicator}

    def interrupt_speech(self) -> dict[str, Any]:
        was_speaking = self._speaking
        self._speaking = False
        if was_speaking:
            self._interrupted_count += 1
        return {"interrupted": was_speaking, "total_interruptions": self._interrupted_count}

    def transcribe_audio(self, audio_bytes: bytes) -> dict[str, Any]:
        if not self.consent_granted:
            return {"ok": False, "reason": "voice processing requires explicit user consent", "typed_fallback_available": True}
        engine = self.select_recognizer()
        if engine is None:
            return {"ok": False, "reason": "no speech-recognition engine is configured; use typed input", "typed_fallback_available": True}
        transcript = engine.transcribe(audio_bytes, language=self.selected_language, vocabulary=self.custom_vocabulary)
        return {
            "ok": True,
            "engine": engine.engine_id,
            "is_local": engine.is_local,
            "language": self.selected_language,
            "transcript": transcript,
            "audio_retained": bool(self.retain_audio_recordings),
        }

    def submit_voice_request(
        self,
        transcript: str,
        *,
        planner_submit: Callable[[str], dict[str, Any]],
    ) -> dict[str, Any]:
        """Route a transcribed command through the exact same planner & permission engine as typed input (§107)."""
        cleaned = (transcript or "").strip()
        if not cleaned:
            return {"submitted": False, "reason": "empty transcript"}
        task = planner_submit(cleaned)
        return {
            "submitted": True,
            "input_modality": "voice_transcribed",
            "entered_standard_planner_and_policy": True,
            "task": task,
        }

    @staticmethod
    def authorize_privileged_by_voice() -> dict[str, Any]:
        """§107 Speaker identity / voice biometrics may never authorize privileged actions."""
        return {
            "authorized": False,
            "speaker_biometrics_accepted": SPEAKER_ID_AUTHORIZES_PRIVILEGED,
            "reason": "voice or speaker recognition is never sufficient to authorize privileged actions; use explicit policy/session confirmation",
        }

    def speak_task_status(self, task_id: str, state: str, summary: str = "") -> dict[str, Any]:
        spoken = f"Task {task_id} is {state.replace('_', ' ')}." + (f" {summary}" if summary else "")
        synth = self.select_synthesizer()
        if synth is None:
            return {"spoken": False, "text": spoken, "reason": "no speech synthesizer configured"}
        self._speaking = True
        audio = synth.synthesize(spoken, language=self.selected_language)
        self._speaking = False
        return {"spoken": True, "engine": synth.engine_id, "text": spoken, "audio_bytes": len(audio)}

    def status(self) -> dict[str, Any]:
        rec = self.select_recognizer()
        syn = self.select_synthesizer()
        return {
            "consent_granted": self.consent_granted,
            "prefer_local": self.prefer_local,
            "wake_word_enabled": self.wake_word_enabled,
            "retain_audio_recordings": self.retain_audio_recordings,
            "language": self.selected_language,
            "selected_recognizer": rec.engine_id if rec else None,
            "selected_synthesizer": syn.engine_id if syn else None,
            "speaker_id_authorizes_privileged": SPEAKER_ID_AUTHORIZES_PRIVILEGED,
            **self.microphone_indicator,
        }


__all__ = [
    "CONTINUOUS_SCREEN_CAPTURE",
    "SPEAKER_ID_AUTHORIZES_PRIVILEGED",
    "DeterministicLoopbackRecognizer",
    "DeterministicLoopbackSynthesizer",
    "SpeechRecognizer",
    "SpeechSynthesizer",
    "VisualAssistant",
    "VoiceLayer",
    "inspect_image_dimensions",
]
