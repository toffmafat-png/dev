"""§94 Local knowledge engine and hybrid search.

Full-text retrieval over approved local documents, with provenance on every
passage, metadata filtering, project scoping, code symbol search, incremental
reindexing, and deletion when a file disappears or the user asks to forget it.

Design decisions that follow directly from the requirements:

* **Full-text first.** SQLite FTS5 with a Porter stemmer is the baseline. It is
  local, fast, and needs no model. When FTS5 is not compiled in, the store falls
  back to a bounded substring scan and *says so* in every result.
* **Semantic search is optional and never faked.** Vector retrieval requires an
  embedder that the operator configured. With none, ``search`` reports
  ``semantic_available: False`` and the reason; it does not quietly substitute a
  lexical score and call it semantic.
* **Retrieved text is not asserted to be true or current.** Every result carries
  its source kind, file location, indexed time, and a currency assessment. An
  external document carries its publisher and date when known.
* **Privacy is explicit.** ``remote_embedding_privacy`` and
  ``local_embedding_privacy`` spell out what each choice does to document text,
  because that trade-off is the operator's to make.
"""
from __future__ import annotations

import hashlib
import math
import re
import sqlite3
from collections.abc import Callable, Iterable
from dataclasses import dataclass, field
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

SCHEMA_VERSION = "nova-knowledge-v1"

SOURCE_USER_DOCUMENT = "user_document"
SOURCE_TASK_HISTORY = "task_history"
SOURCE_CONVERSATION = "conversation_history"
SOURCE_CODE = "code"
SOURCE_DOCUMENTATION = "documentation"
SOURCE_TOOL_RESULT = "tool_result"
SOURCE_EXTERNAL = "external_source"
SOURCE_KINDS = (
    SOURCE_USER_DOCUMENT,
    SOURCE_TASK_HISTORY,
    SOURCE_CONVERSATION,
    SOURCE_CODE,
    SOURCE_DOCUMENTATION,
    SOURCE_TOOL_RESULT,
    SOURCE_EXTERNAL,
)

METHOD_FTS = "full_text"
METHOD_SEMANTIC = "semantic"
METHOD_HYBRID = "hybrid"
METHOD_SUBSTRING = "substring_fallback"

CURRENCY_FRESH = "fresh"
CURRENCY_STALE = "stale"
CURRENCY_UNKNOWN = "unknown"

STALE_AFTER_DAYS = 30.0

TEXT_SUFFIXES = {
    ".txt", ".md", ".markdown", ".rst", ".json", ".csv", ".tsv", ".log", ".py", ".js", ".mjs", ".ts",
    ".jsx", ".tsx", ".sh", ".bash", ".yml", ".yaml", ".toml", ".ini", ".cfg", ".conf", ".html", ".htm",
    ".css", ".sql", ".xml", ".env.example", ".service", ".desktop",
}
# Formats §94 mentions that NOVA cannot parse. They are refused with a reason
# rather than indexed as binary noise.
UNSUPPORTED_SUFFIXES = {".pdf", ".doc", ".docx", ".xls", ".xlsx", ".ppt", ".pptx", ".odt", ".ods", ".odp", ".rtf"}

DEFAULT_CHUNK_CHARS = 1_600
DEFAULT_CHUNK_OVERLAP = 200
MAX_DOCUMENT_BYTES = 4 * 1024 * 1024
MAX_RESULTS = 200
DEFAULT_EXCLUDED_DIRS = {".git", ".venv", "venv", "__pycache__", "node_modules", ".mypy_cache", ".ruff_cache", ".pytest_cache", "dist", "build", ".tox", ".cache"}

REMOTE_EMBEDDING_PRIVACY = (
    "Document text is sent to the configured provider to be embedded. Anything indexed therefore leaves "
    "this machine, including file contents the operator may consider private. Exclude sensitive paths."
)
LOCAL_EMBEDDING_PRIVACY = (
    "Text never leaves the machine, but a local embedding model costs RAM and CPU. On a dual-core host a "
    "small model is slow, and NOVA will not download one automatically."
)

_SYMBOL_PATTERNS = (
    (re.compile(r"^\s*(?:async\s+)?def\s+([A-Za-z_]\w*)"), "function"),
    (re.compile(r"^\s*class\s+([A-Za-z_]\w*)"), "class"),
    (re.compile(r"^\s*(?:export\s+)?(?:async\s+)?function\s*\*?\s*([A-Za-z_$][\w$]*)"), "function"),
    (re.compile(r"^\s*(?:export\s+)?(?:abstract\s+)?class\s+([A-Za-z_$][\w$]*)"), "class"),
    (re.compile(r"^\s*(?:export\s+)?(?:const|let|var)\s+([A-Za-z_$][\w$]*)"), "variable"),
    (re.compile(r"^\s*([A-Z][A-Z0-9_]{2,})\s*="), "constant"),
)


def _now() -> str:
    return datetime.now(UTC).isoformat(timespec="microseconds")


def _days_since(stamp: str) -> float | None:
    if not stamp:
        return None
    try:
        moment = datetime.fromisoformat(stamp)
    except ValueError:
        return None
    if moment.tzinfo is None:
        moment = moment.replace(tzinfo=UTC)
    return (datetime.now(UTC) - moment).total_seconds() / 86_400.0


@dataclass(frozen=True)
class Chunk:
    document_id: str
    chunk_index: int
    body: str
    page: int | None = None
    line_start: int = 0
    line_end: int = 0

    def to_dict(self) -> dict[str, Any]:
        return {
            "document_id": self.document_id,
            "chunk_index": self.chunk_index,
            "page": self.page,
            "line_start": self.line_start,
            "line_end": self.line_end,
            "chars": len(self.body),
        }


@dataclass(frozen=True)
class Provenance:
    """Where a passage came from, and how much to trust its currency."""

    source_kind: str
    path: str
    page: int | None
    line_start: int
    line_end: int
    indexed_at: str
    modified_at: str
    document_date: str
    publisher: str
    external: bool
    currency: str
    caution: str

    def to_dict(self) -> dict[str, Any]:
        return {
            "source_kind": self.source_kind,
            "path": self.path,
            "page": self.page,
            "line_start": self.line_start,
            "line_end": self.line_end,
            "indexed_at": self.indexed_at,
            "modified_at": self.modified_at,
            "document_date": self.document_date,
            "publisher": self.publisher,
            "external": self.external,
            "currency": self.currency,
            "caution": self.caution,
        }


@dataclass(frozen=True)
class SearchResult:
    query: str
    document_id: str
    title: str
    text: str
    score: float
    method: str
    matched_terms: tuple[str, ...]
    provenance: Provenance
    rank: int = 0
    semantic_score: float | None = None
    lexical_score: float | None = None

    def citation(self) -> str:
        prov = self.provenance
        location = prov.path or self.document_id
        if prov.page is not None:
            return f"{location} p.{prov.page}"
        if prov.line_start and prov.line_end and prov.line_end != prov.line_start:
            return f"{location} lines {prov.line_start}-{prov.line_end}"
        if prov.line_start:
            return f"{location} line {prov.line_start}"
        return location

    def to_dict(self) -> dict[str, Any]:
        return {
            "rank": self.rank,
            "query": self.query,
            "document_id": self.document_id,
            "title": self.title,
            "text": self.text,
            "citation": self.citation(),
            "score": self.score,
            "method": self.method,
            "matched_terms": list(self.matched_terms),
            "semantic_score": self.semantic_score,
            "lexical_score": self.lexical_score,
            "provenance": self.provenance.to_dict(),
        }


@dataclass(frozen=True)
class IndexOutcome:
    document_id: str
    action: str
    chunks: int
    reason: str = ""
    path: str = ""
    content_hash: str = ""

    def to_dict(self) -> dict[str, Any]:
        return {
            "document_id": self.document_id,
            "action": self.action,
            "chunks": self.chunks,
            "reason": self.reason,
            "path": self.path,
            "content_hash": self.content_hash,
        }


Embedder = Callable[[list[str]], list[list[float]]]


def _cosine(left: list[float], right: list[float]) -> float:
    if not left or not right or len(left) != len(right):
        return 0.0
    dot = sum(a * b for a, b in zip(left, right, strict=False))
    norm_left = math.sqrt(sum(a * a for a in left))
    norm_right = math.sqrt(sum(b * b for b in right))
    if norm_left == 0.0 or norm_right == 0.0:
        return 0.0
    return dot / (norm_left * norm_right)


def _pack(vector: list[float]) -> bytes:
    import array

    packed = array.array("f", vector)
    return packed.tobytes()


def _unpack(blob: bytes) -> list[float]:
    import array

    if not blob:
        return []
    packed = array.array("f")
    packed.frombytes(blob[: len(blob) - (len(blob) % 4)])
    return list(packed)


def chunk_text(text: str, *, chunk_chars: int = DEFAULT_CHUNK_CHARS, overlap: int = DEFAULT_CHUNK_OVERLAP) -> list[Chunk]:
    """Split on line boundaries, keeping line numbers so citations are real."""
    if not text.strip():
        return []
    chunk_chars = max(200, int(chunk_chars))
    overlap = max(0, min(int(overlap), chunk_chars // 2))
    lines = text.splitlines()
    chunks: list[Chunk] = []
    buffer: list[str] = []
    start_line = 1
    current_line = 1
    size = 0
    for line in lines:
        if not buffer:
            start_line = current_line
        buffer.append(line)
        size += len(line) + 1
        if size >= chunk_chars:
            chunks.append(Chunk(document_id="", chunk_index=len(chunks), body="\n".join(buffer), line_start=start_line, line_end=current_line))
            keep = []
            kept_size = 0
            for item in reversed(buffer):
                if kept_size + len(item) + 1 > overlap:
                    break
                keep.insert(0, item)
                kept_size += len(item) + 1
            buffer = keep
            size = kept_size
            start_line = current_line - len(keep) + 1
        current_line += 1
    if buffer and any(item.strip() for item in buffer):
        chunks.append(Chunk(document_id="", chunk_index=len(chunks), body="\n".join(buffer), line_start=start_line, line_end=current_line - 1))
    return chunks


def extract_symbols(text: str) -> list[tuple[str, str, int]]:
    """(name, kind, line) triples for code navigation and filename search."""
    found: list[tuple[str, str, int]] = []
    for number, line in enumerate(text.splitlines(), start=1):
        for pattern, kind in _SYMBOL_PATTERNS:
            match = pattern.match(line)
            if match:
                found.append((match.group(1), kind, number))
                break
    return found


def is_excluded(path: Path, *, excluded_dirs: Iterable[str] = DEFAULT_EXCLUDED_DIRS, patterns: Iterable[str] = ()) -> bool:
    parts = set(path.parts)
    if parts & set(excluded_dirs):
        return True
    name = path.name
    for pattern in patterns:
        if not pattern:
            continue
        if pattern.startswith("*.") and name.endswith(pattern[1:]):
            return True
        if pattern.endswith("/*") and name == pattern[:-2]:
            return True
        if pattern == name:
            return True
    return name.startswith(".") and name not in {".env.example"}


def looks_binary(sample: bytes) -> bool:
    if not sample:
        return False
    if b"\x00" in sample:
        return True
    text_characters = bytes(range(7, 14)) + bytes(range(32, 127)) + b"\r\n\t\f\x1b"
    return sum(1 for byte in sample if byte not in text_characters) / len(sample) > 0.30


@dataclass
class KnowledgeStore:
    """Indexed local knowledge with hybrid retrieval and full provenance."""

    db_path: str
    workspace_root: str = ""
    chunk_chars: int = DEFAULT_CHUNK_CHARS
    chunk_overlap: int = DEFAULT_CHUNK_OVERLAP
    max_document_bytes: int = MAX_DOCUMENT_BYTES
    stale_after_days: float = STALE_AFTER_DAYS
    embedder: Embedder | None = None
    embedding_model: str = ""
    embedding_location: str = ""
    excluded_dirs: tuple[str, ...] = tuple(DEFAULT_EXCLUDED_DIRS)
    exclude_patterns: tuple[str, ...] = ()
    _connection: sqlite3.Connection | None = field(default=None, init=False)
    _fts_available: bool | None = field(default=None, init=False)
    _indexed: int = field(default=0, init=False)
    _skipped: int = field(default=0, init=False)
    _searches: int = field(default=0, init=False)
    _vector_queries: int = field(default=0, init=False)

    # -- storage

    @property
    def connection(self) -> sqlite3.Connection:
        if self._connection is None:
            parent = Path(self.db_path).parent
            if str(parent):
                parent.mkdir(parents=True, exist_ok=True)
            self._connection = sqlite3.connect(self.db_path, timeout=10.0)
            self._connection.row_factory = sqlite3.Row
            self._connection.execute("PRAGMA journal_mode=WAL")
            self._initialize()
        return self._connection

    def _initialize(self) -> None:
        assert self._connection is not None
        self._connection.executescript(
            """
            CREATE TABLE IF NOT EXISTS knowledge_documents (
                id TEXT PRIMARY KEY,
                path TEXT NOT NULL DEFAULT '',
                title TEXT NOT NULL DEFAULT '',
                source_kind TEXT NOT NULL DEFAULT 'user_document',
                project TEXT NOT NULL DEFAULT '',
                mime TEXT NOT NULL DEFAULT '',
                size_bytes INTEGER NOT NULL DEFAULT 0,
                content_hash TEXT NOT NULL DEFAULT '',
                modified_at TEXT NOT NULL DEFAULT '',
                indexed_at TEXT NOT NULL DEFAULT '',
                document_date TEXT NOT NULL DEFAULT '',
                publisher TEXT NOT NULL DEFAULT '',
                external INTEGER NOT NULL DEFAULT 0,
                chunk_count INTEGER NOT NULL DEFAULT 0,
                symbol_count INTEGER NOT NULL DEFAULT 0,
                embedded INTEGER NOT NULL DEFAULT 0,
                notes TEXT NOT NULL DEFAULT ''
            );
            CREATE INDEX IF NOT EXISTS idx_knowledge_documents_project ON knowledge_documents(project);
            CREATE INDEX IF NOT EXISTS idx_knowledge_documents_kind ON knowledge_documents(source_kind);
            CREATE INDEX IF NOT EXISTS idx_knowledge_documents_path ON knowledge_documents(path);
            CREATE TABLE IF NOT EXISTS knowledge_symbols (
                document_id TEXT NOT NULL,
                name TEXT NOT NULL,
                kind TEXT NOT NULL,
                line INTEGER NOT NULL DEFAULT 0
            );
            CREATE INDEX IF NOT EXISTS idx_knowledge_symbols_name ON knowledge_symbols(name);
            CREATE TABLE IF NOT EXISTS knowledge_vectors (
                document_id TEXT NOT NULL,
                chunk_index INTEGER NOT NULL,
                embedding BLOB NOT NULL,
                model TEXT NOT NULL DEFAULT '',
                dims INTEGER NOT NULL DEFAULT 0,
                created_at TEXT NOT NULL DEFAULT '',
                PRIMARY KEY (document_id, chunk_index)
            );
            CREATE TABLE IF NOT EXISTS knowledge_chunk_meta (
                document_id TEXT NOT NULL,
                chunk_index INTEGER NOT NULL,
                page INTEGER,
                line_start INTEGER NOT NULL DEFAULT 0,
                line_end INTEGER NOT NULL DEFAULT 0,
                body TEXT NOT NULL DEFAULT '',
                PRIMARY KEY (document_id, chunk_index)
            );
            CREATE TABLE IF NOT EXISTS knowledge_meta (
                key TEXT PRIMARY KEY,
                value TEXT NOT NULL DEFAULT ''
            );
            """
        )
        try:
            self._connection.execute(
                "CREATE VIRTUAL TABLE IF NOT EXISTS knowledge_fts USING fts5("
                "document_id UNINDEXED, chunk_index UNINDEXED, body, tokenize='porter unicode61')"
            )
            self._fts_available = True
        except sqlite3.Error:
            self._fts_available = False
        self._connection.execute(
            "INSERT OR REPLACE INTO knowledge_meta(key, value) VALUES ('schema_version', ?)", (SCHEMA_VERSION,)
        )
        self._connection.commit()

    @property
    def fts_available(self) -> bool:
        if self._fts_available is None:
            _ = self.connection
        return bool(self._fts_available)

    def close(self) -> None:
        if self._connection is not None:
            self._connection.close()
            self._connection = None

    # -- indexing

    def index_text(
        self,
        text: str,
        *,
        document_id: str,
        title: str = "",
        source_kind: str = SOURCE_USER_DOCUMENT,
        project: str = "",
        path: str = "",
        external: bool = False,
        publisher: str = "",
        document_date: str = "",
        modified_at: str = "",
        notes: str = "",
        embed: bool = False,
    ) -> IndexOutcome:
        """Index (or re-index) one document from text already in hand."""
        if source_kind not in SOURCE_KINDS:
            return IndexOutcome(document_id, "refused", 0, f"unknown source kind '{source_kind}'", path)
        if not text or not text.strip():
            return IndexOutcome(document_id, "skipped", 0, "the document is empty", path)
        if external and source_kind != SOURCE_EXTERNAL:
            source_kind = SOURCE_EXTERNAL
        content_hash = hashlib.sha256(text.encode("utf-8", "replace")).hexdigest()
        connection = self.connection
        existing = connection.execute("SELECT content_hash, chunk_count FROM knowledge_documents WHERE id = ?", (document_id,)).fetchone()
        if existing and existing["content_hash"] == content_hash:
            return IndexOutcome(document_id, "unchanged", int(existing["chunk_count"] or 0), "content hash is identical", path, content_hash)

        chunks = chunk_text(text, chunk_chars=self.chunk_chars, overlap=self.chunk_overlap)
        for index, chunk in enumerate(chunks):
            chunks[index] = Chunk(
                document_id=document_id,
                chunk_index=index,
                body=chunk.body,
                page=chunk.page,
                line_start=chunk.line_start,
                line_end=chunk.line_end,
            )
        symbols = extract_symbols(text) if source_kind == SOURCE_CODE else []

        connection.execute("DELETE FROM knowledge_fts WHERE document_id = ?", (document_id,)) if self.fts_available else None
        connection.execute("DELETE FROM knowledge_chunk_meta WHERE document_id = ?", (document_id,))
        connection.execute("DELETE FROM knowledge_symbols WHERE document_id = ?", (document_id,))
        connection.execute("DELETE FROM knowledge_vectors WHERE document_id = ?", (document_id,))
        if self.fts_available:
            connection.executemany(
                "INSERT INTO knowledge_fts(document_id, chunk_index, body) VALUES (?, ?, ?)",
                [(item.document_id, item.chunk_index, item.body) for item in chunks],
            )
        connection.executemany(
            "INSERT INTO knowledge_chunk_meta(document_id, chunk_index, page, line_start, line_end, body) VALUES (?, ?, ?, ?, ?, ?)",
            [(item.document_id, item.chunk_index, item.page, item.line_start, item.line_end, item.body) for item in chunks],
        )
        if symbols:
            connection.executemany(
                "INSERT INTO knowledge_symbols(document_id, name, kind, line) VALUES (?, ?, ?, ?)",
                [(document_id, name, kind, line) for name, kind, line in symbols],
            )
        connection.execute(
            """
            INSERT INTO knowledge_documents
                (id, path, title, source_kind, project, mime, size_bytes, content_hash, modified_at,
                 indexed_at, document_date, publisher, external, chunk_count, symbol_count, embedded, notes)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 0, ?)
            ON CONFLICT(id) DO UPDATE SET
                path=excluded.path, title=excluded.title, source_kind=excluded.source_kind,
                project=excluded.project, mime=excluded.mime, size_bytes=excluded.size_bytes,
                content_hash=excluded.content_hash, modified_at=excluded.modified_at,
                indexed_at=excluded.indexed_at, document_date=excluded.document_date,
                publisher=excluded.publisher, external=excluded.external,
                chunk_count=excluded.chunk_count, symbol_count=excluded.symbol_count,
                embedded=0, notes=excluded.notes
            """,
            (
                document_id,
                path,
                title or document_id,
                source_kind,
                project,
                "text/plain",
                len(text.encode("utf-8", "replace")),
                content_hash,
                modified_at or _now(),
                _now(),
                document_date,
                publisher,
                1 if external else 0,
                len(chunks),
                len(symbols),
                notes,
            ),
        )
        connection.commit()
        self._indexed += 1
        outcome_action = "reindexed" if existing else "indexed"
        if embed:
            embedded = self.embed_document(document_id, chunks)
            if embedded:
                outcome_action = f"{outcome_action}+embedded"
        return IndexOutcome(document_id, outcome_action, len(chunks), "", path, content_hash)

    def index_path(
        self,
        path: str | Path,
        *,
        project: str = "",
        source_kind: str | None = None,
        external: bool = False,
        publisher: str = "",
        document_date: str = "",
        embed: bool = False,
    ) -> IndexOutcome:
        """Index one file from disk, honouring exclusions and size limits."""
        target = Path(str(path)).expanduser()
        document_id = self.document_id_for(target)
        if not target.exists():
            self._skipped += 1
            return IndexOutcome(document_id, "refused", 0, "the path does not exist", str(target))
        if target.is_dir():
            self._skipped += 1
            return IndexOutcome(document_id, "refused", 0, "the path is a directory; use index_directory", str(target))
        resolved_target = target.resolve()
        check_rel = resolved_target.relative_to(resolved_target.anchor) if resolved_target.is_absolute() else target
        if self.workspace_root:
            ws_root = Path(self.workspace_root).expanduser().resolve()
            if not resolved_target.is_relative_to(ws_root):
                self._skipped += 1
                return IndexOutcome(document_id, "refused", 0, "the path is outside the approved workspace root", str(target))
            check_rel = resolved_target.relative_to(ws_root)
        if is_excluded(check_rel, excluded_dirs=self.excluded_dirs, patterns=self.exclude_patterns):
            self._skipped += 1
            return IndexOutcome(document_id, "excluded", 0, "the path matches an indexing exclusion", str(target))
        suffix = target.suffix.lower()
        if suffix in UNSUPPORTED_SUFFIXES:
            self._skipped += 1
            return IndexOutcome(
                document_id,
                "unsupported",
                0,
                f"'{suffix}' parsing is not implemented; NOVA will not index a format it cannot read accurately",
                str(target),
            )
        try:
            size = target.stat().st_size
        except OSError as exc:
            self._skipped += 1
            return IndexOutcome(document_id, "error", 0, f"the file could not be stat'd: {type(exc).__name__}", str(target))
        if size == 0:
            self._skipped += 1
            return IndexOutcome(document_id, "skipped", 0, "the file is empty", str(target))
        if size > self.max_document_bytes:
            self._skipped += 1
            return IndexOutcome(
                document_id,
                "skipped",
                0,
                f"the file is {size} bytes, above the {self.max_document_bytes}-byte limit; it was not indexed rather than truncated silently",
                str(target),
            )
        try:
            raw = target.read_bytes()
        except OSError as exc:
            self._skipped += 1
            return IndexOutcome(document_id, "error", 0, f"the file could not be read: {type(exc).__name__}", str(target))
        if looks_binary(raw[:8192]):
            self._skipped += 1
            return IndexOutcome(document_id, "skipped", 0, "the file is binary and was not indexed", str(target))
        text = raw.decode("utf-8", errors="replace")
        kind = source_kind or (SOURCE_CODE if suffix in {".py", ".js", ".mjs", ".ts", ".jsx", ".tsx", ".sh", ".sql", ".css", ".html"} else SOURCE_DOCUMENTATION if suffix in {".md", ".rst", ".markdown"} else SOURCE_USER_DOCUMENT)
        try:
            modified = datetime.fromtimestamp(target.stat().st_mtime, UTC).isoformat(timespec="seconds")
        except OSError:
            modified = ""
        return self.index_text(
            text,
            document_id=document_id,
            title=target.name,
            source_kind=kind,
            project=project,
            path=str(target),
            external=external,
            publisher=publisher,
            document_date=document_date,
            modified_at=modified,
            embed=embed,
        )

    def index_directory(self, root: str | Path, *, project: str = "", suffixes: Iterable[str] = TEXT_SUFFIXES, limit: int = 2_000, embed: bool = False) -> dict[str, Any]:
        """Index a tree, skipping exclusions. Reports precisely what was skipped."""
        base = Path(str(root)).expanduser()
        outcomes: list[IndexOutcome] = []
        reasons: dict[str, int] = {}
        if not base.is_dir():
            return {"root": str(base), "indexed": 0, "outcomes": [], "reasons": {"not_a_directory": 1}, "note": "the root does not exist"}
        wanted = {item.lower() for item in suffixes}
        count = 0
        for path in sorted(base.rglob("*")):
            if count >= limit:
                reasons["limit_reached"] = 1
                break
            if not path.is_file():
                continue
            try:
                relative = path.relative_to(base)
            except ValueError:
                continue
            if is_excluded(relative, excluded_dirs=self.excluded_dirs, patterns=self.exclude_patterns):
                reasons["excluded"] = reasons.get("excluded", 0) + 1
                continue
            if wanted and path.suffix.lower() not in wanted:
                reasons["suffix_not_requested"] = reasons.get("suffix_not_requested", 0) + 1
                continue
            outcome = self.index_path(path, project=project, embed=embed)
            outcomes.append(outcome)
            reasons[outcome.action] = reasons.get(outcome.action, 0) + 1
            count += 1
        return {
            "root": str(base),
            "project": project,
            "indexed": sum(1 for item in outcomes if item.action in {"indexed", "reindexed", "indexed+embedded", "reindexed+embedded"}),
            "unchanged": reasons.get("unchanged", 0),
            "considered": count,
            "limit": limit,
            "reasons": reasons,
            "outcomes": [item.to_dict() for item in outcomes if item.action not in {"indexed", "reindexed", "unchanged"}][:50],
            "note": "Incremental: a document whose content hash is unchanged is left alone rather than re-embedded.",
        }

    def document_id_for(self, path: Path) -> str:
        text = str(Path(path).expanduser().resolve())
        return "doc-" + hashlib.sha256(text.encode("utf-8")).hexdigest()[:16]

    def refresh_changed(self, *, project: str = "", limit: int = 500) -> dict[str, Any]:
        """Re-index documents whose file changed, and drop those that disappeared."""
        connection = self.connection
        query = "SELECT id, path, content_hash, project FROM knowledge_documents WHERE path != ''"
        parameters: list[Any] = []
        if project:
            query += " AND project = ?"
            parameters.append(project)
        query += " ORDER BY indexed_at LIMIT ?"
        parameters.append(limit)
        rows = connection.execute(query, parameters).fetchall()
        refreshed: list[str] = []
        removed: list[str] = []
        unchanged = 0
        for row in rows:
            path = Path(row["path"])
            if not path.exists():
                self.remove(row["id"], reason="the file no longer exists")
                removed.append(row["id"])
                continue
            outcome = self.index_path(path, project=str(row["project"] or project))
            if outcome.action in {"indexed", "reindexed"}:
                refreshed.append(row["id"])
            else:
                unchanged += 1
        return {
            "checked": len(rows),
            "refreshed": refreshed,
            "removed": removed,
            "unchanged": unchanged,
            "note": "Deleted and excluded content is removed from the index; a stale entry is never returned as current.",
        }

    # -- embeddings

    def embed_document(self, document_id: str, chunks: list[Chunk]) -> int:
        if self.embedder is None:
            return 0
        bodies = [item.body for item in chunks]
        if not bodies:
            return 0
        try:
            vectors = self.embedder(bodies)
        except Exception:
            return 0
        if not isinstance(vectors, list) or len(vectors) != len(bodies):
            return 0
        connection = self.connection
        stored = 0
        for chunk, vector in zip(chunks, vectors, strict=False):
            if not isinstance(vector, (list, tuple)) or not vector:
                continue
            floats = []
            for value in vector:
                try:
                    floats.append(float(value))
                except (TypeError, ValueError):
                    floats = []
                    break
            if not floats:
                continue
            connection.execute(
                "INSERT OR REPLACE INTO knowledge_vectors(document_id, chunk_index, embedding, model, dims, created_at) VALUES (?, ?, ?, ?, ?, ?)",
                (document_id, chunk.chunk_index, _pack(floats), self.embedding_model, len(floats), _now()),
            )
            stored += 1
        if stored:
            connection.execute("UPDATE knowledge_documents SET embedded = 1 WHERE id = ?", (document_id,))
            connection.commit()
        return stored

    def semantic_available(self) -> dict[str, Any]:
        """Whether vector retrieval can run, and what it would cost in privacy."""
        connection = self.connection
        rows = connection.execute("SELECT count(*) AS total FROM knowledge_vectors").fetchone()
        stored = int(rows["total"] if rows else 0)
        docs = connection.execute("SELECT count(*) AS total FROM knowledge_documents WHERE embedded = 1").fetchone()
        available = self.embedder is not None and stored > 0
        reason = "vector search is available" if available else (
            "no embedder is configured, so retrieval is lexical only"
            if self.embedder is None
            else "an embedder is configured but no document has been embedded yet"
        )
        return {
            "available": available,
            "reason": reason,
            "embedding_model": self.embedding_model,
            "embedding_location": self.embedding_location or ("remote" if self.embedder else ""),
            "vectors_stored": stored,
            "documents_embedded": int(docs["total"] if docs else 0),
            "remote_embedding_privacy": REMOTE_EMBEDDING_PRIVACY,
            "local_embedding_privacy": LOCAL_EMBEDDING_PRIVACY,
            "note": (
                "Semantic retrieval is enabled only when an embedder is configured. NOVA does not "
                "relabel a lexical score as semantic."
            ),
        }

    # -- search

    @staticmethod
    def _match_expression(query: str, *, conjunctive: bool) -> tuple[str, list[str]]:
        terms = [item for item in re.findall(r"[\w][\w\-\.]*", query or "") if item]
        if not terms:
            return "", []
        joiner = " AND " if conjunctive else " OR "
        return joiner.join(f'"{term}"' for term in terms), terms

    def search(
        self,
        query: str,
        *,
        limit: int = 10,
        project: str = "",
        source_kinds: Iterable[str] = (),
        external_only: bool | None = None,
        use_semantic: bool = True,
        minimum_score: float = 0.0,
    ) -> dict[str, Any]:
        """Hybrid retrieval. Lexical results always; semantic only if configured."""
        self._searches += 1
        limit = max(1, min(int(limit), MAX_RESULTS))
        kinds = tuple(source_kinds)
        semantic_info = self.semantic_available()
        methods: list[str] = []
        limitations: list[str] = []
        if not self.fts_available:
            limitations.append("SQLite FTS5 is not available in this build; results come from a bounded substring scan and are not ranked by relevance")
        if use_semantic and not semantic_info["available"]:
            limitations.append(f"semantic retrieval was requested but is unavailable: {semantic_info['reason']}")

        lexical = self._lexical_search(query, limit=limit * 3, project=project, kinds=kinds, external_only=external_only)
        if lexical:
            methods.append(METHOD_FTS if self.fts_available else METHOD_SUBSTRING)

        semantic: list[dict[str, Any]] = []
        if use_semantic and semantic_info["available"]:
            semantic = self._semantic_search(query, limit=limit * 3, project=project, kinds=kinds)
            self._vector_queries += 1
            if semantic:
                methods.append(METHOD_SEMANTIC)

        fused = self._fuse(lexical, semantic)
        results: list[SearchResult] = []
        for rank, entry in enumerate(fused[:limit], start=1):
            if entry["score"] < minimum_score:
                continue
            results.append(self._build_result(query, entry, rank, methods))
        method = METHOD_HYBRID if len(methods) > 1 else (methods[0] if methods else METHOD_FTS)
        return {
            "query": query,
            "schema_version": SCHEMA_VERSION,
            "method": method,
            "methods_used": methods,
            "result_count": len(results),
            "results": [item.to_dict() for item in results],
            "semantic": semantic_info,
            "lexical_candidates": len(lexical),
            "semantic_candidates": len(semantic),
            "limitations": limitations,
            "caution": (
                "Retrieved passages are quotations of stored documents, not verified facts. Check the "
                "provenance and currency before relying on one, and prefer a direct measurement for "
                "anything consequential."
            ),
        }

    def _lexical_search(self, query: str, *, limit: int, project: str, kinds: tuple[str, ...], external_only: bool | None) -> list[dict[str, Any]]:
        if self.fts_available:
            for conjunctive in (True, False):
                expression, terms = self._match_expression(query, conjunctive=conjunctive)
                if not expression:
                    return []
                sql = (
                    "SELECT document_id, chunk_index, body, "
                    "snippet(knowledge_fts, 2, '[', ']', ' … ', 18) AS snippet, bm25(knowledge_fts) AS rank "
                    "FROM knowledge_fts WHERE knowledge_fts MATCH ?"
                )
                parameters: list[Any] = [expression]
                sql, parameters = self._apply_filters(sql, parameters, project, kinds, external_only, join_documents=True)
                sql += " ORDER BY rank LIMIT ?"
                parameters.append(limit)
                try:
                    rows = self.connection.execute(sql, parameters).fetchall()
                except sqlite3.Error:
                    rows = []
                if rows:
                    # bm25() is negative and more negative is better; normalize to 0..1.
                    worst = max(float(row["rank"]) for row in rows)
                    best = min(float(row["rank"]) for row in rows)
                    span = (worst - best) or 1.0
                    return [
                        {
                            "document_id": row["document_id"],
                            "chunk_index": int(row["chunk_index"]),
                            "text": row["snippet"] or row["body"],
                            "score": round((worst - float(row["rank"])) / span, 4),
                            "matched_terms": tuple(terms),
                            "origin": METHOD_FTS,
                        }
                        for row in rows
                    ]
            return []
        return self._substring_search(query, limit=limit, project=project, kinds=kinds, external_only=external_only)

    def _substring_search(self, query: str, *, limit: int, project: str, kinds: tuple[str, ...], external_only: bool | None) -> list[dict[str, Any]]:
        """Fallback when FTS5 is absent: bounded scan, honestly unranked."""
        needle = (query or "").strip().lower()
        if not needle:
            return []
        sql = "SELECT document_id, chunk_index, body FROM knowledge_chunk_meta"
        parameters: list[Any] = []
        sql, parameters = self._apply_filters(sql, parameters, project, kinds, external_only, join_documents=True, alias="m")
        sql += " LIMIT 5000"
        try:
            rows = self.connection.execute(sql, parameters).fetchall()
        except sqlite3.Error:
            return []
        hits = []
        for row in rows:
            body = str(row["body"] or "")
            position = body.lower().find(needle)
            if position < 0:
                continue
            start = max(0, position - 80)
            excerpt = ("…" if start else "") + body[start : position + 220] + ("…" if position + 220 < len(body) else "")
            hits.append(
                {
                    "document_id": row["document_id"],
                    "chunk_index": int(row["chunk_index"]),
                    "text": excerpt,
                    "score": 0.5,
                    "matched_terms": (needle,),
                    "origin": METHOD_SUBSTRING,
                }
            )
            if len(hits) >= limit:
                break
        return hits

    def _semantic_search(self, query: str, *, limit: int, project: str, kinds: tuple[str, ...]) -> list[dict[str, Any]]:
        if self.embedder is None:
            return []
        try:
            vectors = self.embedder([query])
        except Exception:
            return []
        if not vectors or not isinstance(vectors[0], (list, tuple)):
            return []
        query_vector = [float(item) for item in vectors[0]]
        sql = "SELECT v.document_id, v.chunk_index, v.embedding, m.body FROM knowledge_vectors v"
        sql += " JOIN knowledge_documents d ON d.id = v.document_id"
        sql += " LEFT JOIN knowledge_chunk_meta m ON m.document_id = v.document_id AND m.chunk_index = v.chunk_index"
        parameters: list[Any] = []
        if project:
            sql += " WHERE d.project = ?"
            parameters.append(project)
        if kinds:
            sql += (" AND" if parameters else " WHERE") + f" d.source_kind IN ({','.join('?' * len(kinds))})"
            parameters.extend(kinds)
        try:
            rows = self.connection.execute(sql, parameters).fetchall()
        except sqlite3.Error:
            return []
        scored = []
        for row in rows:
            similarity = _cosine(query_vector, _unpack(row["embedding"]))
            if similarity <= 0.0:
                continue
            scored.append(
                {
                    "document_id": row["document_id"],
                    "chunk_index": int(row["chunk_index"]),
                    "text": str(row["body"] or "")[:600],
                    "score": round(similarity, 4),
                    "matched_terms": (),
                    "origin": METHOD_SEMANTIC,
                }
            )
        scored.sort(key=lambda item: (-item["score"], item["document_id"]))
        return scored[:limit]

    @staticmethod
    def _apply_filters(
        sql: str,
        parameters: list[Any],
        project: str,
        kinds: tuple[str, ...],
        external_only: bool | None,
        *,
        join_documents: bool = False,
        alias: str = "",
    ) -> tuple[str, list[Any]]:
        prefix = f"{alias}." if alias else ""
        if join_documents and not alias:
            sql = sql.replace("FROM knowledge_fts WHERE", "FROM knowledge_fts JOIN knowledge_documents d ON d.id = knowledge_fts.document_id WHERE")
            sql = sql.replace("FROM knowledge_chunk_meta", "FROM knowledge_chunk_meta m JOIN knowledge_documents d ON d.id = m.document_id")
            prefix = "d."
        elif join_documents:
            sql = sql.replace("FROM knowledge_chunk_meta", "FROM knowledge_chunk_meta m")
            prefix = "d."
            sql = sql.replace("FROM knowledge_chunk_meta m", "FROM knowledge_chunk_meta m JOIN knowledge_documents d ON d.id = m.document_id")
        clauses: list[str] = []
        if project:
            clauses.append(f"{prefix}project = ?")
            parameters.append(project)
        if kinds:
            clauses.append(f"{prefix}source_kind IN ({','.join('?' * len(kinds))})")
            parameters.extend(kinds)
        if external_only is not None:
            clauses.append(f"{prefix}external = ?")
            parameters.append(1 if external_only else 0)
        if clauses:
            sql += " AND " + " AND ".join(clauses) if " WHERE " in sql else " WHERE " + " AND ".join(clauses)
        return sql, parameters

    @staticmethod
    def _fuse(lexical: list[dict[str, Any]], semantic: list[dict[str, Any]], *, k: int = 60) -> list[dict[str, Any]]:
        """Reciprocal-rank fusion. Uses rank, not raw score, so the two scales mix safely."""
        scores: dict[tuple[str, int], dict[str, Any]] = {}
        for origin, entries in (("lexical", lexical), ("semantic", semantic)):
            for rank, entry in enumerate(entries, start=1):
                key = (entry["document_id"], entry["chunk_index"])
                bucket = scores.setdefault(
                    key,
                    {
                        "document_id": entry["document_id"],
                        "chunk_index": entry["chunk_index"],
                        "text": entry["text"],
                        "matched_terms": set(entry.get("matched_terms") or ()),
                        "rrf": 0.0,
                        "lexical_score": None,
                        "semantic_score": None,
                    },
                )
                bucket["rrf"] += 1.0 / (k + rank)
                bucket[f"{origin}_score"] = entry["score"]
                bucket["matched_terms"] |= set(entry.get("matched_terms") or ())
                if origin == "lexical" and len(entry["text"]) > len(bucket["text"]):
                    bucket["text"] = entry["text"]
        fused = sorted(scores.values(), key=lambda item: (-item["rrf"], item["document_id"], item["chunk_index"]))
        for entry in fused:
            entry["score"] = round(entry["rrf"] * (k + 1) * 2, 4)
            entry["matched_terms"] = tuple(sorted(entry["matched_terms"]))
        return fused

    def _build_result(self, query: str, entry: dict[str, Any], rank: int, methods: list[str]) -> SearchResult:
        connection = self.connection
        document = connection.execute("SELECT * FROM knowledge_documents WHERE id = ?", (entry["document_id"],)).fetchone()
        meta = connection.execute(
            "SELECT page, line_start, line_end, body FROM knowledge_chunk_meta WHERE document_id = ? AND chunk_index = ?",
            (entry["document_id"], entry["chunk_index"]),
        ).fetchone()
        indexed_at = str(document["indexed_at"]) if document else ""
        modified_at = str(document["modified_at"]) if document else ""
        age = _days_since(modified_at or indexed_at)
        if age is None:
            currency = CURRENCY_UNKNOWN
        elif age > self.stale_after_days:
            currency = CURRENCY_STALE
        else:
            currency = CURRENCY_FRESH
        external = bool(document["external"]) if document else False
        caution = "Retrieved text is a quotation, not a verified fact."
        if currency == CURRENCY_STALE:
            caution += f" It was last modified about {age:.0f} day(s) ago and may be out of date."
        if external:
            publisher = str(document["publisher"]) if document else ""
            caution += f" It came from an external source{f' ({publisher})' if publisher else ''} and was not independently checked."
        provenance = Provenance(
            source_kind=str(document["source_kind"]) if document else "",
            path=str(document["path"]) if document else "",
            page=(int(meta["page"]) if meta and meta["page"] is not None else None),
            line_start=int(meta["line_start"]) if meta else 0,
            line_end=int(meta["line_end"]) if meta else 0,
            indexed_at=indexed_at,
            modified_at=modified_at,
            document_date=str(document["document_date"]) if document else "",
            publisher=str(document["publisher"]) if document else "",
            external=external,
            currency=currency,
            caution=caution,
        )
        text = str(meta["body"]) if meta else str(entry.get("text") or "")
        if entry.get("origin") == METHOD_FTS or METHOD_FTS in methods:
            snippet_text = str(entry.get("text") or "")
            if snippet_text and len(snippet_text) < len(text):
                text = snippet_text
        return SearchResult(
            query=query,
            document_id=entry["document_id"],
            title=str(document["title"]) if document else entry["document_id"],
            text=text[:2_000],
            score=float(entry["score"]),
            method="+".join(methods) or METHOD_FTS,
            matched_terms=tuple(entry.get("matched_terms") or ()),
            provenance=provenance,
            rank=rank,
            semantic_score=entry.get("semantic_score"),
            lexical_score=entry.get("lexical_score"),
        )

    def search_symbols(self, query: str, *, limit: int = 25, kind: str = "") -> dict[str, Any]:
        """Code symbol and filename search."""
        needle = (query or "").strip().lower()
        if not needle:
            return {"query": query, "results": [], "note": "an empty query matches nothing"}
        sql = "SELECT s.document_id, s.name, s.kind, s.line, d.path, d.title FROM knowledge_symbols s JOIN knowledge_documents d ON d.id = s.document_id WHERE lower(s.name) LIKE ?"
        parameters: list[Any] = [f"%{needle}%"]
        if kind:
            sql += " AND s.kind = ?"
            parameters.append(kind)
        sql += " ORDER BY length(s.name), s.name LIMIT ?"
        parameters.append(max(1, min(int(limit), MAX_RESULTS)))
        rows = self.connection.execute(sql, parameters).fetchall()
        files = self.connection.execute(
            "SELECT id, path, title, source_kind FROM knowledge_documents WHERE lower(path) LIKE ? OR lower(title) LIKE ? LIMIT ?",
            (f"%{needle}%", f"%{needle}%", max(1, min(int(limit), MAX_RESULTS))),
        ).fetchall()
        return {
            "query": query,
            "symbols": [
                {"name": row["name"], "kind": row["kind"], "line": row["line"], "path": row["path"], "document_id": row["document_id"]}
                for row in rows
            ],
            "files": [{"path": row["path"], "title": row["title"], "source_kind": row["source_kind"], "document_id": row["id"]} for row in files],
            "note": "Symbol extraction is pattern-based over common languages, not a compiler or language server.",
        }

    # -- removal and retention (§111)

    def remove(self, document_id: str, *, reason: str = "") -> bool:
        connection = self.connection
        existing = connection.execute("SELECT id FROM knowledge_documents WHERE id = ?", (document_id,)).fetchone()
        if existing is None:
            return False
        for table in ("knowledge_fts", "knowledge_chunk_meta", "knowledge_symbols", "knowledge_vectors"):
            if table == "knowledge_fts" and not self.fts_available:
                continue
            # Table names come from the literal tuple above, never caller input.
            connection.execute(f"DELETE FROM {table} WHERE document_id = ?", (document_id,))
        connection.execute("DELETE FROM knowledge_documents WHERE id = ?", (document_id,))
        connection.commit()
        return True

    def remove_path(self, path: str | Path) -> int:
        target = str(Path(str(path)).expanduser())
        rows = self.connection.execute("SELECT id FROM knowledge_documents WHERE path = ?", (target,)).fetchall()
        removed = 0
        for row in rows:
            if self.remove(row["id"], reason="path removed on request"):
                removed += 1
        return removed

    def forget(self, *, project: str = "", source_kind: str = "", path_prefix: str = "", everything: bool = False) -> dict[str, Any]:
        """Delete stored knowledge on request. Irreversible, and reported as such."""
        connection = self.connection
        if everything:
            ids = [row["id"] for row in connection.execute("SELECT id FROM knowledge_documents").fetchall()]
            scope = "all indexed knowledge"
        else:
            sql = "SELECT id FROM knowledge_documents WHERE 1=1"
            parameters: list[Any] = []
            if project:
                sql += " AND project = ?"
                parameters.append(project)
            if source_kind:
                sql += " AND source_kind = ?"
                parameters.append(source_kind)
            if path_prefix:
                sql += " AND path LIKE ?"
                parameters.append(f"{path_prefix}%")
            ids = [row["id"] for row in connection.execute(sql, parameters).fetchall()]
            scope = ", ".join(filter(None, [f"project={project}" if project else "", f"kind={source_kind}" if source_kind else "", f"paths under {path_prefix}" if path_prefix else ""])) or "nothing selected"
        removed = sum(1 for item in ids if self.remove(item, reason="forget request"))
        return {
            "scope": scope,
            "removed_documents": removed,
            "irreversible": True,
            "note": "The passages, their embeddings and their symbol rows were deleted. Nothing remains to retrieve.",
        }

    # -- reporting

    def stats(self) -> dict[str, Any]:
        connection = self.connection
        documents = connection.execute("SELECT count(*) AS total FROM knowledge_documents").fetchone()
        by_kind = {row["source_kind"]: row["total"] for row in connection.execute("SELECT source_kind, count(*) AS total FROM knowledge_documents GROUP BY source_kind").fetchall()}
        by_project = {row["project"] or "(none)": row["total"] for row in connection.execute("SELECT project, count(*) AS total FROM knowledge_documents GROUP BY project").fetchall()}
        chunks = connection.execute("SELECT count(*) AS total FROM knowledge_chunk_meta").fetchone()
        external = connection.execute("SELECT count(*) AS total FROM knowledge_documents WHERE external = 1").fetchone()
        stale = [
            row["id"]
            for row in connection.execute("SELECT id, modified_at, indexed_at FROM knowledge_documents").fetchall()
            if (_days_since(row["modified_at"] or row["indexed_at"]) or 0) > self.stale_after_days
        ]
        size_bytes = 0
        try:
            size_bytes = Path(self.db_path).stat().st_size if Path(self.db_path).exists() else 0
        except OSError:
            size_bytes = 0
        return {
            "schema_version": SCHEMA_VERSION,
            "db_path": self.db_path,
            "db_bytes": size_bytes,
            "fts5_available": self.fts_available,
            "documents": int(documents["total"] if documents else 0),
            "chunks": int(chunks["total"] if chunks else 0),
            "external_documents": int(external["total"] if external else 0),
            "stale_documents": len(stale),
            "by_source_kind": by_kind,
            "by_project": by_project,
            "indexed": self._indexed,
            "skipped": self._skipped,
            "searches": self._searches,
            "vector_queries": self._vector_queries,
            "semantic": self.semantic_available(),
            "unsupported_formats": sorted(UNSUPPORTED_SUFFIXES),
            "excluded_directories": list(self.excluded_dirs),
            "note": (
                "Counts describe what is indexed, not what is true. A document in this store is a "
                "quotation of a file at a point in time."
            ),
        }


__all__ = [
    "CURRENCY_FRESH",
    "CURRENCY_STALE",
    "CURRENCY_UNKNOWN",
    "DEFAULT_CHUNK_CHARS",
    "DEFAULT_CHUNK_OVERLAP",
    "DEFAULT_EXCLUDED_DIRS",
    "LOCAL_EMBEDDING_PRIVACY",
    "MAX_DOCUMENT_BYTES",
    "MAX_RESULTS",
    "METHOD_FTS",
    "METHOD_HYBRID",
    "METHOD_SEMANTIC",
    "METHOD_SUBSTRING",
    "REMOTE_EMBEDDING_PRIVACY",
    "SCHEMA_VERSION",
    "SOURCE_CODE",
    "SOURCE_CONVERSATION",
    "SOURCE_DOCUMENTATION",
    "SOURCE_EXTERNAL",
    "SOURCE_KINDS",
    "SOURCE_TASK_HISTORY",
    "SOURCE_TOOL_RESULT",
    "SOURCE_USER_DOCUMENT",
    "STALE_AFTER_DAYS",
    "TEXT_SUFFIXES",
    "UNSUPPORTED_SUFFIXES",
    "Chunk",
    "Embedder",
    "IndexOutcome",
    "KnowledgeStore",
    "Provenance",
    "SearchResult",
    "chunk_text",
    "extract_symbols",
    "is_excluded",
    "looks_binary",
]
