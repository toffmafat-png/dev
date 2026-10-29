"""Terminal entry point: ``python -m nova.cognition``.

Lives in its own module so running the evaluation suite does not re-import
``nova.cognition.evaluation`` as ``__main__`` on top of the package import.
"""
from __future__ import annotations

from nova.cognition.evaluation import main

if __name__ == "__main__":  # pragma: no cover - terminal entry point
    raise SystemExit(main())
