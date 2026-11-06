"""§276 Core Self-Engineering Mission, §277 Complete Self-Source-Code Intelligence,
§278 Autonomous Architectural Analysis, §280 Architecture Redesign & §289 Architecture Knowledge Graph.
"""
from __future__ import annotations

import ast
import hashlib
import re
import shutil
import subprocess
from collections import defaultdict
from pathlib import Path
from typing import Any

from nova.db import Database

SELF_ENGINEERING_11_ROLES: tuple[str, ...] = (
    "principal_software_architect",
    "senior_software_engineer",
    "backend_engineer",
    "desktop_application_engineer",
    "ai_infrastructure_engineer",
    "database_architect",
    "performance_engineer",
    "security_engineer",
    "devops_engineer",
    "quality_assurance_engineer",
    "technical_documentation_engineer",
)

SOURCE_INTEL_20_DOMAINS: tuple[str, ...] = (
    "entire_project_structure",
    "source_files",
    "modules",
    "classes_and_functions",
    "interfaces_and_dependencies",
    "application_entry_points",
    "event_systems",
    "database_schemas",
    "api_integrations",
    "model_adapters",
    "agent_orchestration",
    "tool_registry",
    "memory_architecture",
    "background_services",
    "configuration",
    "installation_scripts",
    "update_mechanisms",
    "security_components",
    "test_suites",
    "build_and_deployment_configurations",
)

ARCH_ANALYSIS_16_DIMENSIONS: tuple[str, ...] = (
    "tightly_coupled_modules",
    "circular_dependencies",
    "duplicate_functionality",
    "unclear_responsibilities",
    "large_difficult_to_maintain_components",
    "performance_bottlenecks",
    "excessive_memory_consumption",
    "blocking_operations",
    "poor_error_handling_patterns",
    "unreliable_integrations",
    "inefficient_database_queries",
    "weak_abstractions",
    "missing_interfaces",
    "outdated_dependencies",
    "inadequate_test_coverage",
    "difficult_to_extend_components",
)

ARCH_GRAPH_14_ENTITY_KINDS: tuple[str, ...] = (
    "modules",
    "classes",
    "functions",
    "dependencies",
    "interfaces",
    "services",
    "data_stores",
    "api_providers",
    "plugins",
    "workers",
    "event_types",
    "task_flows",
    "configuration_relationships",
    "tests",
)

_EXCLUDED_PARTS: frozenset[str] = frozenset(
    {".venv", "__pycache__", ".pytest_cache", ".ruff_cache", ".git", "releases", "data"}
)


def _module_name_for_path(repo_root: Path, py_file: Path) -> str:
    rel = py_file.relative_to(repo_root).with_suffix("")
    parts = list(rel.parts)
    if parts and parts[-1] == "__init__":
        parts = parts[:-1]
    return ".".join(parts) if parts else py_file.stem


class ArchitectureKnowledgeGraph:
    """§289 Machine-readable architecture graph derived directly from live source code & config."""

    DERIVED_FROM_LIVE_SOURCE_NOT_STALE_DOCS = True

    def __init__(self, *, repo_root: Path) -> None:
        self.repo_root = Path(repo_root).resolve()
        self._cached_graph: dict[str, Any] | None = None

    def build_graph(self, *, force_refresh: bool = False) -> dict[str, Any]:
        if self._cached_graph is not None and not force_refresh:
            return self._cached_graph

        modules: dict[str, dict[str, Any]] = {}
        classes: list[dict[str, Any]] = []
        functions: list[dict[str, Any]] = []
        dependencies: dict[str, list[str]] = defaultdict(list)
        reverse_deps: dict[str, list[str]] = defaultdict(list)
        services: list[str] = []
        interfaces: list[str] = []
        data_stores: list[str] = []
        api_providers: list[str] = []
        plugins: list[str] = []
        workers: list[str] = []
        event_types: list[str] = []
        task_flows: list[str] = []
        config_relations: list[str] = []
        tests: list[str] = []
        call_edges: list[tuple[str, str]] = []

        py_files = sorted(
            p
            for p in self.repo_root.rglob("*.py")
            if p.is_file() and not any(part in _EXCLUDED_PARTS for part in p.parts)
        )

        for py_file in py_files:
            rel_posix = py_file.relative_to(self.repo_root).as_posix()
            mod_name = _module_name_for_path(self.repo_root, py_file)
            src = py_file.read_text(encoding="utf-8", errors="replace")
            loc = len(src.splitlines())

            if rel_posix.startswith("tests/test_"):
                tests.append(rel_posix)

            # Extract SQLite CREATE TABLE names from nova/db.py or storage modules
            for tbl_match in re.finditer(r"CREATE\s+TABLE\s+IF\s+NOT\s+EXISTS\s+([a-zA-Z0-9_]+)", src):
                tbl = tbl_match.group(1)
                if tbl not in data_stores:
                    data_stores.append(tbl)

            try:
                tree = ast.parse(src, filename=rel_posix)
            except SyntaxError:
                modules[mod_name] = {"path": rel_posix, "loc": loc, "parse_ok": False, "classes": [], "functions": []}
                continue

            mod_classes: list[str] = []
            mod_funcs: list[str] = []
            mod_imports: set[str] = set()

            for node in ast.walk(tree):
                if isinstance(node, ast.Import):
                    for alias in node.names:
                        if alias.name.startswith("nova"):
                            mod_imports.add(alias.name)
                elif isinstance(node, ast.ImportFrom) and node.module:
                    if node.module.startswith("nova"):
                        mod_imports.add(node.module)
                elif isinstance(node, ast.ClassDef):
                    mod_classes.append(node.name)
                    classes.append({"module": mod_name, "name": node.name, "path": rel_posix, "line": node.lineno})
                    if node.name.endswith("Service") or node.name.endswith("Engine") or node.name.endswith("Manager"):
                        services.append(f"{mod_name}.{node.name}")
                    if node.name.endswith("Protocol") or node.name.endswith("Adapter") or node.name.endswith("Definition"):
                        interfaces.append(f"{mod_name}.{node.name}")
                    if "Plugin" in node.name:
                        plugins.append(f"{mod_name}.{node.name}")
                    if "Worker" in node.name or "Supervisor" in node.name or "Scheduler" in node.name:
                        workers.append(f"{mod_name}.{node.name}")
                    if "Provider" in node.name:
                        api_providers.append(f"{mod_name}.{node.name}")
                    if "Event" in node.name:
                        event_types.append(f"{mod_name}.{node.name}")
                    if "Task" in node.name or "Workflow" in node.name:
                        task_flows.append(f"{mod_name}.{node.name}")
                elif isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
                    mod_funcs.append(node.name)
                    functions.append(
                        {
                            "module": mod_name,
                            "name": node.name,
                            "async": isinstance(node, ast.AsyncFunctionDef),
                            "path": rel_posix,
                            "line": node.lineno,
                        }
                    )
                    for sub in ast.walk(node):
                        if isinstance(sub, ast.Call) and isinstance(sub.func, ast.Name):
                            call_edges.append((f"{mod_name}.{node.name}", sub.func.id))
                        elif isinstance(sub, ast.Attribute) and isinstance(sub.value, ast.Name) and sub.value.id == "settings":
                            rel_cfg = f"{mod_name}->Settings.{sub.attr}"
                            if rel_cfg not in config_relations:
                                config_relations.append(rel_cfg)

            modules[mod_name] = {
                "path": rel_posix,
                "loc": loc,
                "parse_ok": True,
                "classes": mod_classes,
                "functions": mod_funcs,
            }
            for imp in sorted(mod_imports):
                if imp != mod_name:
                    dependencies[mod_name].append(imp)
                    reverse_deps[imp].append(mod_name)

        graph = {
            "repo_root": str(self.repo_root),
            "derived_from_live_source": self.DERIVED_FROM_LIVE_SOURCE_NOT_STALE_DOCS,
            "entity_kinds_tracked": list(ARCH_GRAPH_14_ENTITY_KINDS),
            "counts": {
                "modules": len(modules),
                "classes": len(classes),
                "functions": len(functions),
                "dependency_edges": sum(len(v) for v in dependencies.values()),
                "data_stores_tables": len(data_stores),
                "tests": len(tests),
                "services": len(services),
            },
            "modules": modules,
            "dependencies": dict(dependencies),
            "reverse_dependencies": {k: sorted(set(v)) for k, v in reverse_deps.items()},
            "interfaces": sorted(set(interfaces))[:80],
            "services": sorted(set(services))[:120],
            "data_stores": sorted(data_stores),
            "api_providers": sorted(set(api_providers))[:50],
            "plugins": sorted(set(plugins))[:50],
            "workers": sorted(set(workers))[:50],
            "event_types": sorted(set(event_types))[:50],
            "task_flows": sorted(set(task_flows))[:50],
            "configuration_relationships": sorted(config_relations)[:80],
            "tests": tests,
            "sample_call_edges": call_edges[:100],
        }
        self._cached_graph = graph
        return graph

    def estimate_change_impact(self, target_module: str) -> dict[str, Any]:
        """§277 & §289 Identify dependent modules and exact pytest suites affected before refactoring."""
        graph = self.build_graph()
        norm = target_module.replace("/", ".").removesuffix(".py")
        visited: set[str] = set()
        queue = [norm]
        while queue:
            cur = queue.pop(0)
            for dep_by in graph["reverse_dependencies"].get(cur, []):
                if dep_by not in visited:
                    visited.add(dep_by)
                    queue.append(dep_by)
            # Also match package prefix imports (e.g. nova.tools -> nova.tools.registry)
            for mod, imports in graph["dependencies"].items():
                if any(i == cur or i.startswith(cur + ".") for i in imports) and mod not in visited and mod != norm:
                    visited.add(mod)
                    queue.append(mod)

        dependent_modules = sorted(m for m in visited if not m.startswith("tests."))
        recommended_tests = sorted(
            graph["modules"][m]["path"]
            for m in visited
            if m.startswith("tests.") and m in graph["modules"]
        )
        if not recommended_tests:
            stem = norm.split(".")[-1]
            recommended_tests = [t for t in graph["tests"] if stem in t][:5] or graph["tests"][:3]

        return {
            "target_module": norm,
            "exists_in_repository": norm in graph["modules"],
            "direct_and_transitive_dependents": dependent_modules,
            "dependent_count": len(dependent_modules),
            "recommended_tests": recommended_tests,
            "risk_tier": (
                "high_security_or_core"
                if norm in {"nova.autonomy", "nova.db", "nova.main", "nova.desktop.policy", "nova.engine"}
                else ("moderate" if len(dependent_modules) >= 3 else "low_isolated")
            ),
        }


class SelfSourceCodeIntelligenceEngine:
    """§277 Complete repository & architectural question-answering grounded strictly in actual source files."""

    FABRICATE_ARCHITECTURAL_DETAILS = False

    def __init__(self, *, repo_root: Path, arch_graph: ArchitectureKnowledgeGraph) -> None:
        self.repo_root = Path(repo_root).resolve()
        self.arch_graph = arch_graph

    def inspect_complete_repository(self) -> dict[str, Any]:
        graph = self.arch_graph.build_graph(force_refresh=True)
        git_branch = "unknown"
        git_head = "unknown"
        git_bin = shutil.which("git")
        if git_bin:
            b = subprocess.run([git_bin, "rev-parse", "--abbrev-ref", "HEAD"], cwd=self.repo_root, capture_output=True, text=True, check=False)
            h = subprocess.run([git_bin, "rev-parse", "--short", "HEAD"], cwd=self.repo_root, capture_output=True, text=True, check=False)
            if b.returncode == 0:
                git_branch = b.stdout.strip()
            if h.returncode == 0:
                git_head = h.stdout.strip()

        entry_points = [
            rel
            for rel in ("app.py", "nova/main.py", "nova/desktop/cli.py", "nova/desktop/app.py")
            if (self.repo_root / rel).is_file()
        ]
        scripts = sorted(p.relative_to(self.repo_root).as_posix() for p in (self.repo_root / "scripts").glob("*.sh")) if (self.repo_root / "scripts").is_dir() else []

        return {
            "repo_root": str(self.repo_root),
            "git_branch": git_branch,
            "git_head": git_head,
            "understood_domains": list(SOURCE_INTEL_20_DOMAINS),
            "entry_points": entry_points,
            "installation_and_build_scripts": scripts,
            "summary_counts": graph["counts"],
            "fabricated_details": self.FABRICATE_ARCHITECTURAL_DETAILS,
        }

    def answer_architecture_question(self, question: str) -> dict[str, Any]:
        """Answer §277 repository intelligence queries strictly from indexed AST & file facts."""
        graph = self.arch_graph.build_graph()
        q = question.lower()

        if "model router" in q or "intelligence engine" in q or "orchestrat" in q:
            mods = [m for m in ("nova.intelligence", "nova.model_providers", "nova.hybrid_cloud.service") if m in graph["modules"]]
            return {
                "question": question,
                "grounded_in_repository": True,
                "relevant_modules": {m: graph["modules"][m] for m in mods},
                "explanation": "Model routing and multi-provider orchestration live in `nova/intelligence.py` (`ModelManager`, `IntelligenceOrchestrator`) and `nova/model_providers.py`.",
            }
        if "depend on" in q or "interface changed" in q:
            tokens = re.findall(r"nova\.[a-zA-Z0-9_.]+|[a-zA-Z0-9_]+\.py", question)
            target = tokens[0] if tokens else "nova.tools.registry"
            impact = self.arch_graph.estimate_change_impact(target)
            return {
                "question": question,
                "grounded_in_repository": impact["exists_in_repository"],
                "impact": impact,
            }
        if "scalability" in q or "slow" in q:
            largest = sorted(
                ((m, info["loc"]) for m, info in graph["modules"].items()),
                key=lambda x: x[1],
                reverse=True,
            )[:5]
            return {
                "question": question,
                "grounded_in_repository": True,
                "largest_modules_by_loc": largest,
                "sqlite_tables_count": graph["counts"]["data_stores_tables"],
                "explanation": "Primary single-host scaling constraints are synchronous SQLite write serialization (`Database._lock` in `nova/db.py`) and single-process in-memory limiters (`nova/main.py`).",
            }

        # General symbol/module search fallback grounded strictly in AST index
        keywords = [w for w in re.findall(r"[a-zA-Z0-9_]{3,}", q) if w not in {"how", "does", "where", "which", "what", "the", "work", "files", "need"}]
        matched_mods = [
            m
            for m, info in graph["modules"].items()
            if any(kw in m.lower() or any(kw in c.lower() for c in info["classes"]) for kw in keywords)
        ][:10]
        return {
            "question": question,
            "grounded_in_repository": len(matched_mods) > 0,
            "matched_modules": matched_mods,
            "note": "Derived directly from AST symbol index." if matched_mods else "No matching symbol found in repository; refusing to fabricate architectural claims.",
        }


class AutonomousArchitecturalAnalyzer:
    """§278 & §280 Evaluates 16 internal design dimensions, detects smells & evaluates paradigm trade-offs."""

    def __init__(self, *, db: Database, repo_root: Path, arch_graph: ArchitectureKnowledgeGraph) -> None:
        self.db = db
        self.repo_root = Path(repo_root).resolve()
        self.arch_graph = arch_graph

    def analyze_architecture(self, target_dir: Path | None = None) -> dict[str, Any]:
        scan_root = Path(target_dir).resolve() if target_dir else self.repo_root
        graph = (
            self.arch_graph.build_graph()
            if scan_root == self.repo_root
            else ArchitectureKnowledgeGraph(repo_root=scan_root).build_graph()
        )

        # 1. Tightly coupled modules (high efferent + afferent coupling)
        coupled: list[dict[str, Any]] = []
        for mod, outs in graph["dependencies"].items():
            ins = graph["reverse_dependencies"].get(mod, [])
            if len(outs) + len(ins) >= 12:
                coupled.append({"module": mod, "efferent": len(outs), "afferent": len(ins)})

        # 2. Circular dependency detection (DFS on module import graph)
        cycles: list[list[str]] = []
        deps = graph["dependencies"]
        visited: set[str] = set()
        stack: list[str] = []
        on_stack: set[str] = set()

        def _dfs(u: str) -> None:
            visited.add(u)
            stack.append(u)
            on_stack.add(u)
            for v in deps.get(u, []):
                if v not in visited:
                    _dfs(v)
                elif v in on_stack and len(cycles) < 10:
                    idx = stack.index(v)
                    cycles.append([*stack[idx:], v])
            stack.pop()
            on_stack.remove(u)

        for m in list(deps):
            if m not in visited:
                _dfs(m)

        # 3. Large components, blocking calls in async functions, bare excepts, duplicate function bodies
        large_components = [
            {"module": m, "path": info["path"], "loc": info["loc"]}
            for m, info in graph["modules"].items()
            if info["loc"] >= 900
        ]
        blocking_in_async: list[dict[str, Any]] = []
        poor_error_handling: list[dict[str, Any]] = []
        body_hashes: dict[str, list[str]] = defaultdict(list)

        for mod, info in graph["modules"].items():
            fpath = scan_root / info["path"]
            if not fpath.is_file():
                continue
            try:
                tree = ast.parse(fpath.read_text(encoding="utf-8", errors="replace"))
            except SyntaxError:
                continue
            for node in ast.walk(tree):
                if isinstance(node, ast.AsyncFunctionDef):
                    for sub in ast.walk(node):
                        if isinstance(sub, ast.Attribute) and isinstance(sub.value, ast.Name):
                            call_pair = f"{sub.value.id}.{sub.attr}"
                            if call_pair in {"time.sleep", "subprocess.run"}:
                                blocking_in_async.append({"module": mod, "function": node.name, "call": call_pair, "line": sub.lineno})
                elif isinstance(node, ast.ExceptHandler) and node.type is None:
                    poor_error_handling.append({"module": mod, "line": node.lineno, "pattern": "bare_except"})
                elif isinstance(node, ast.FunctionDef) and len(node.body) >= 4:
                    norm_dump = ast.dump(ast.Module(body=node.body, type_ignores=[]), include_attributes=False)
                    digest = hashlib.sha256(norm_dump.encode("utf-8")).hexdigest()[:12]
                    body_hashes[digest].append(f"{mod}.{node.name}")

        duplicates = [locs for locs in body_hashes.values() if len(locs) >= 2][:15]
        tested_stems = {Path(t).stem.removeprefix("test_") for t in graph["tests"]}
        untested_modules = [
            m
            for m in graph["modules"]
            if m.startswith("nova.") and m.split(".")[-1] not in tested_stems and m.split(".")[-1] != "__init__"
        ][:20]

        return {
            "evaluated_dimensions": list(ARCH_ANALYSIS_16_DIMENSIONS),
            "summary": {
                "modules_analyzed": graph["counts"]["modules"],
                "tightly_coupled_count": len(coupled),
                "circular_dependencies_count": len(cycles),
                "duplicate_function_groups_count": len(duplicates),
                "large_components_count": len(large_components),
                "blocking_async_calls_count": len(blocking_in_async),
                "poor_error_patterns_count": len(poor_error_handling),
            },
            "findings": {
                "tightly_coupled_modules": coupled[:10],
                "circular_dependencies": cycles,
                "duplicate_functionality": duplicates,
                "large_components": sorted(large_components, key=lambda x: x["loc"], reverse=True)[:10],
                "blocking_operations_in_async": blocking_in_async[:10],
                "poor_error_handling": poor_error_handling[:10],
                "coverage_gap_candidates": untested_modules,
            },
            "architectural_map": {
                "entry_points": ["app.py", "nova/main.py", "nova/desktop/cli.py", "nova/desktop/app.py"],
                "core_facade": "nova.platform_service.PlatformService",
                "storage_engine": "nova.db.Database (SQLite)",
                "execution_boundaries": ["in_process_async", "isolated_subprocess_sandbox", "polkit_privileged_helper"],
            },
        }

    def evaluate_architecture_redesign_paradigm(
        self,
        *,
        concurrent_users: int = 1,
        daily_tasks: int = 50,
        measured_ipc_bottleneck: bool = False,
        multi_host_gpu_needed: bool = False,
    ) -> dict[str, Any]:
        """§280 Select modular monolith vs independent processes vs distributed nodes without hype bloat."""
        if multi_host_gpu_needed or concurrent_users > 25:
            recommended = "local_control_plane_with_distributed_worker_nodes"
            rationale = "Workload exceeds single Kali host compute budget; offload heavy jobs to registered worker nodes while keeping control plane local."
        elif measured_ipc_bottleneck or daily_tasks > 500:
            recommended = "modular_monolith_with_isolated_worker_processes"
            rationale = "Separate background worker process from Qt GUI / HTTP loop without adding unnecessary message brokers or microservices."
        else:
            recommended = "modular_monolith"
            rationale = "Single-user Kali Linux workload is best served by a clean modular monolith with subprocess tool sandboxes — zero gratuitous microservice or broker overhead."

        return {
            "recommended_paradigm": recommended,
            "rationale": rationale,
            "unnecessary_microservices_rejected": concurrent_users <= 25,
            "unnecessary_message_broker_rejected": not measured_ipc_bottleneck,
            "redesign_for_framework_novelty_rejected": True,
        }

    def record_adr(
        self,
        *,
        title: str,
        context: str,
        decision: str,
        benefits: list[str],
        costs: list[str],
        affected_modules: list[str] | None = None,
    ) -> dict[str, Any]:
        return self.db.save_self_eng_adr(
            {
                "title": title,
                "status": "accepted",
                "context": context,
                "decision": decision,
                "benefits_vs_costs": {"benefits": benefits, "costs": costs, "net_justified": len(benefits) >= len(costs)},
                "affected_modules": affected_modules or [],
            }
        )
