"""§108 Advanced data and knowledge workspace.

Provides streaming, low-RAM profiling, schema inspection, filtering, grouping,
statistics, chart-series specs, document comparison, citation extraction, and
reproducible Python script export for CSV/TSV, JSON/JSONL, Markdown, logs and
source code — without forcing pandas or Polars into the baseline installation.

Generated analytical results are always separated from source metadata and
include the exact ``analysis_method`` so the operator can inspect or reproduce
every number.
"""
from __future__ import annotations

import csv
import difflib
import json
import math
import re
import statistics
from collections.abc import Iterator
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

MAX_STREAM_ROWS = 50_000
SAMPLE_RESERVOIR = 2_000

_HEADING_RE = re.compile(r"^(#{1,6})\s+(.+)$")
_MARKDOWN_LINK_RE = re.compile(r"\[([^\]]+)\]\((https?://[^)\s]+)\)")
_BRACKET_CITATION_RE = re.compile(r"\[(\d+|[A-Za-z]+\d{4})\]")


def _iso() -> str:
    return datetime.now(UTC).isoformat(timespec="microseconds")


def _try_float(raw: Any) -> float | None:
    if raw is None or isinstance(raw, bool):
        return None
    text = str(raw).strip()
    if not text:
        return None
    try:
        val = float(text)
        return val if math.isfinite(val) else None
    except ValueError:
        return None


def _iter_records(path: Path, *, max_rows: int = MAX_STREAM_ROWS) -> tuple[str, list[str], Iterator[dict[str, Any]]]:
    suffix = path.suffix.lower()
    if suffix in {".pdf", ".docx", ".xlsx", ".pptx", ".odt"}:
        raise ValueError(
            f"'{suffix}' binary document parsing requires an optional extractor not installed in the lightweight core"
        )
    if suffix in {".csv", ".tsv"}:
        delimiter = "\t" if suffix == ".tsv" else ","

        def _csv_gen() -> Iterator[dict[str, Any]]:
            with path.open("r", encoding="utf-8", errors="replace", newline="") as handle:
                reader = csv.DictReader(handle, delimiter=delimiter)
                for idx, row in enumerate(reader):
                    if idx >= max_rows:
                        break
                    yield dict(row)

        with path.open("r", encoding="utf-8", errors="replace", newline="") as peek:
            header = list(next(csv.reader(peek, delimiter=delimiter), []))
        return ("tsv" if suffix == ".tsv" else "csv"), header, _csv_gen()

    if suffix == ".jsonl":
        cols: list[str] = []
        with path.open("r", encoding="utf-8", errors="replace") as peek:
            for line in peek:
                if line.strip():
                    first = json.loads(line)
                    if isinstance(first, dict):
                        cols = list(first.keys())
                    break

        def _jsonl_gen() -> Iterator[dict[str, Any]]:
            with path.open("r", encoding="utf-8", errors="replace") as handle:
                for idx, line in enumerate(handle):
                    if idx >= max_rows:
                        break
                    if line.strip():
                        obj = json.loads(line)
                        if isinstance(obj, dict):
                            yield obj

        return "jsonl", cols, _jsonl_gen()

    if suffix == ".json":
        loaded = json.loads(path.read_text(encoding="utf-8"))
        rows = loaded if isinstance(loaded, list) else ([loaded] if isinstance(loaded, dict) else [{"value": loaded}])
        dict_rows = [r for r in rows[:max_rows] if isinstance(r, dict)]
        cols = sorted({k for r in dict_rows[:100] for k in r})
        return "json", cols, iter(dict_rows)

    # Logs / Markdown / source fallback: line-oriented stream
    def _line_gen() -> Iterator[dict[str, Any]]:
        with path.open("r", encoding="utf-8", errors="replace") as handle:
            for idx, raw_line in enumerate(handle, start=1):
                if idx > max_rows:
                    break
                stripped = raw_line.rstrip("\n")
                level = "INFO" if "INFO" in stripped else ("ERROR" if "ERROR" in stripped else ("WARN" if "WARN" in stripped else "TEXT"))
                yield {"line": idx, "level": level, "length": len(stripped), "text": stripped[:240]}

    return "line_stream", ["line", "level", "length", "text"], _line_gen()


@dataclass
class DataWorkspace:
    """§108 Workspace-scoped structured & semi-structured data analyzer."""

    workspace_root: Path

    def __post_init__(self) -> None:
        self.workspace_root = Path(self.workspace_root).resolve()
        self.workspace_root.mkdir(parents=True, exist_ok=True)

    def _resolve(self, relative_path: str) -> Path:
        cleaned = (relative_path or "").strip()
        if not cleaned or cleaned.startswith("/") or "\x00" in cleaned:
            raise PermissionError("Data workspace paths must be relative to workspace_root")
        resolved = (self.workspace_root / cleaned).resolve()
        if not resolved.is_relative_to(self.workspace_root):
            raise PermissionError("Path escapes workspace_root")
        if not resolved.is_file():
            raise FileNotFoundError(f"File not found: {relative_path}")
        return resolved

    def profile_dataset(self, relative_path: str) -> dict[str, Any]:
        """Stream-profile schema, missingness, distinct counts and numeric summary statistics."""
        target = self._resolve(relative_path)
        fmt, columns, iterator = _iter_records(target)

        row_count = 0
        nulls: dict[str, int] = dict.fromkeys(columns, 0)
        distinct: dict[str, set[str]] = {c: set() for c in columns}
        numerics: dict[str, list[float]] = {c: [] for c in columns}

        for row in iterator:
            row_count += 1
            for col in columns:
                val = row.get(col)
                if val is None or str(val).strip() == "":
                    nulls[col] = nulls.get(col, 0) + 1
                    continue
                if len(distinct[col]) < 200:
                    distinct[col].add(str(val))
                num = _try_float(val)
                if num is not None and len(numerics[col]) < SAMPLE_RESERVOIR:
                    numerics[col].append(num)

        schema: dict[str, Any] = {}
        for col in columns:
            non_null = row_count - nulls[col]
            nums = numerics[col]
            is_numeric = non_null > 0 and len(nums) == min(non_null, SAMPLE_RESERVOIR)
            col_entry: dict[str, Any] = {
                "inferred_type": "numeric" if is_numeric else "string",
                "null_count": nulls[col],
                "distinct_sampled": len(distinct[col]),
            }
            if is_numeric and nums:
                col_entry["statistics"] = {
                    "count": len(nums),
                    "min": round(min(nums), 6),
                    "max": round(max(nums), 6),
                    "mean": round(statistics.fmean(nums), 6),
                    "median": round(statistics.median(nums), 6),
                    "stdev": round(statistics.pstdev(nums), 6) if len(nums) > 1 else 0.0,
                }
            schema[col] = col_entry

        return {
            "source_metadata": {
                "path": relative_path,
                "format": fmt,
                "bytes": target.stat().st_size,
                "columns": columns,
            },
            "generated_analysis": {
                "generated_at": _iso(),
                "is_generated_output": True,
                "analysis_method": f"streaming_python_dict_profiler(reservoir={SAMPLE_RESERVOIR})",
                "rows_scanned": row_count,
                "schema_and_statistics": schema,
            },
        }

    def filter_and_group(
        self,
        relative_path: str,
        *,
        group_by: str,
        value_column: str = "",
        filter_column: str = "",
        filter_equals: str = "",
    ) -> dict[str, Any]:
        """Filter & group tabular data and emit a chart-ready visualization series (§108)."""
        target = self._resolve(relative_path)
        fmt, _columns, iterator = _iter_records(target)

        groups_count: dict[str, int] = {}
        groups_sum: dict[str, float] = {}
        matched_rows = 0

        for row in iterator:
            if filter_column and str(row.get(filter_column, "")) != filter_equals:
                continue
            matched_rows += 1
            key = str(row.get(group_by, "(null)"))
            groups_count[key] = groups_count.get(key, 0) + 1
            if value_column:
                num = _try_float(row.get(value_column))
                if num is not None:
                    groups_sum[key] = groups_sum.get(key, 0.0) + num

        summary_rows = []
        for key in sorted(groups_count):
            cnt = groups_count[key]
            total = round(groups_sum.get(key, 0.0), 6)
            entry: dict[str, Any] = {group_by: key, "count": cnt}
            if value_column:
                entry[f"sum_{value_column}"] = total
                entry[f"mean_{value_column}"] = round(total / cnt, 6) if cnt else 0.0
            summary_rows.append(entry)

        return {
            "source_metadata": {"path": relative_path, "format": fmt},
            "generated_analysis": {
                "generated_at": _iso(),
                "is_generated_output": True,
                "analysis_method": "streaming_filter_and_groupby",
                "matched_rows": matched_rows,
                "groups": summary_rows,
                "visualization": {
                    "chart_type": "bar",
                    "x_label": group_by,
                    "y_label": f"sum({value_column})" if value_column else "count",
                    "labels": [row[group_by] for row in summary_rows],
                    "values": [row[f"sum_{value_column}"] if value_column else row["count"] for row in summary_rows],
                },
                "reproducible_script": self.generate_reproducible_script(
                    relative_path,
                    group_by=group_by,
                    value_column=value_column,
                    filter_column=filter_column,
                    filter_equals=filter_equals,
                ),
            },
        }

    @staticmethod
    def generate_reproducible_script(
        relative_path: str,
        *,
        group_by: str,
        value_column: str = "",
        filter_column: str = "",
        filter_equals: str = "",
    ) -> str:
        """Emit a standalone stdlib Python script reproducing the exact aggregation (§108)."""
        return (
            "import csv, collections\n"
            f"counts = collections.Counter()\n"
            f"sums = collections.defaultdict(float)\n"
            f"with open({relative_path!r}, newline='', encoding='utf-8') as fh:\n"
            "    for row in csv.DictReader(fh):\n"
            + (f"        if row.get({filter_column!r}) != {filter_equals!r}:\n            continue\n" if filter_column else "")
            + f"        k = row.get({group_by!r}, '(null)')\n"
            "        counts[k] += 1\n"
            + (f"        sums[k] += float(row[{value_column!r}] or 0)\n" if value_column else "")
            + "print(dict(counts))\n"
        )

    def compare_documents(self, left_rel_path: str, right_rel_path: str) -> dict[str, Any]:
        left = self._resolve(left_rel_path).read_text(encoding="utf-8", errors="replace")
        right = self._resolve(right_rel_path).read_text(encoding="utf-8", errors="replace")
        matcher = difflib.SequenceMatcher(None, left.splitlines(), right.splitlines())
        diff = list(
            difflib.unified_diff(
                left.splitlines(keepends=True),
                right.splitlines(keepends=True),
                fromfile=left_rel_path,
                tofile=right_rel_path,
            )
        )
        return {
            "source_metadata": {"left": left_rel_path, "right": right_rel_path},
            "generated_analysis": {
                "is_generated_output": True,
                "analysis_method": "difflib.SequenceMatcher+unified_diff",
                "identical": left == right,
                "similarity_ratio": round(matcher.ratio(), 4),
                "diff": "".join(diff)[:12_000],
            },
        }

    def extract_knowledge_and_citations(self, relative_path: str) -> dict[str, Any]:
        target = self._resolve(relative_path)
        lines = target.read_text(encoding="utf-8", errors="replace").splitlines()
        headings: list[dict[str, Any]] = []
        citations: list[dict[str, Any]] = []
        for idx, line in enumerate(lines, start=1):
            h_match = _HEADING_RE.match(line.strip())
            if h_match:
                headings.append({"level": len(h_match.group(1)), "title": h_match.group(2).strip(), "citation": f"{relative_path}:{idx}"})
            for label, url in _MARKDOWN_LINK_RE.findall(line):
                citations.append({"kind": "url", "label": label, "target": url, "location": f"{relative_path}:{idx}"})
            for ref_id in _BRACKET_CITATION_RE.findall(line):
                citations.append({"kind": "reference", "ref": ref_id, "location": f"{relative_path}:{idx}"})
        return {
            "source_metadata": {"path": relative_path, "lines": len(lines)},
            "generated_analysis": {
                "is_generated_output": True,
                "analysis_method": "markdown_heading_and_citation_scanner",
                "headings": headings,
                "citations": citations,
            },
        }


__all__ = [
    "MAX_STREAM_ROWS",
    "SAMPLE_RESERVOIR",
    "DataWorkspace",
]
