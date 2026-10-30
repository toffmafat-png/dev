"""Local loopback ASGI companion entry point for DEV / NOVA X on Kali Linux.

DEV is a locally hosted autonomous AI desktop platform powered by cloud frontier
intelligence. It is never deployed to Hugging Face Spaces or run as an externally
hosted primary web application; by default this companion surface binds strictly
to 127.0.0.1 loopback for local IPC, CLI, and native desktop inspection.
"""
from __future__ import annotations

import os

import uvicorn

from nova.main import app

__all__ = ["app"]


if __name__ == "__main__":
    host = os.getenv("NOVA_HOST", "127.0.0.1")
    port = int(os.getenv("NOVA_PORT", os.getenv("PORT", "8000")))
    uvicorn.run("nova.main:app", host=host, port=port)
