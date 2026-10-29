# NOVA X Extension API & Developer SDK (`nova-plugin-v1`, SDK 1.0)

This guide defines the supported extension contract (§92, §109) so developers can add tools to NOVA X without modifying core modules or weakening authorization boundaries.

---

## 1. Security Boundary

Extensions **cannot** bypass NOVA's permission system:

1. `ExtensionContext` exposes only `workspace_root`, read-only `config`, `is_cancelled()`, `resolve_workspace_path()`, `log()`, and `report_error()` — it holds **no** reference to `Database`, `AutonomyPolicy`, `SecretStore`, or `ToolRegistry`.
2. `validate_extension_source_ast()` statically rejects plugin code that imports `nova.db`, `nova.autonomy`, `nova.desktop.secrets`, `nova.sandbox_child`, or `ctypes`.
3. Installing a plugin sets `enabled=False` and `granted_permissions=()`. Enabling requires explicit operator permission grants covering `manifest.required_permissions`.
4. Updating a plugin that adds new `required_permissions` automatically resets it to disabled until the new permissions are explicitly reviewed and granted.
5. External subprocess plugins execute inside `nova.sandbox.Sandbox` (`linux_namespaces` / `bubblewrap`), confining writes to declared `scoped_paths` and blocking network access unless `network_access="allowlist"` and `network.https_allowlist` is granted.

---

## 2. Manifest Specification (`plugin.json`)

Every plugin declares all eleven §92 metadata areas:

```json
{
  "schema_version": "nova-plugin-v1",
  "sdk_version": "1.0",
  "name": "example-analyzer",
  "version": "0.1.0",
  "purpose": "Inspect structured log files inside the authorized workspace.",
  "category": "data_analysis",
  "operations": [
    {
      "name": "count_errors",
      "description": "Count ERROR lines in a relative workspace log file.",
      "input_schema": {
        "type": "object",
        "required": ["path"],
        "properties": { "path": { "type": "string" } }
      },
      "output_schema": {
        "type": "object",
        "required": ["errors"],
        "properties": { "errors": { "type": "integer" } }
      },
      "autonomy_class": "routine"
    }
  ],
  "dependencies": [],
  "required_permissions": ["workspace.read"],
  "network_access": "none",
  "allowed_hosts": [],
  "filesystem_access": "read_workspace",
  "scoped_paths": [],
  "possible_side_effects": [],
  "timeout_seconds": 15.0,
  "max_memory_mb": 256,
  "entrypoint": "plugin_main.py",
  "tests": ["tests/test_plugin.py"],
  "compatibility": {
    "min_nova_version": "0.2.0",
    "min_python": "3.11",
    "platforms": ["linux"]
  },
  "trust": {
    "publisher": "local_developer",
    "sha256": "<optional-64-hex-entrypoint-digest>",
    "signed": false,
    "trusted": false
  }
}
```

---

## 3. Built-in Reference Extensions (§109)

`builtin_sdk_examples()` in `nova/plugins.py` ships four reference extensions:

1. **`readonly-fs-search`** (`research`) — Read-only case-insensitive workspace search respecting cancellation and path containment.
2. **`repo-inspector`** (`development`) — Read-only repository layout and dependency-manifest summary.
3. **`structured-data-helper`** (`data_analysis`) — Streaming CSV and JSON row/column schema inspector.
4. **`configurable-api-probe`** (`external_integration`) — HTTPS endpoint validator and request descriptor builder using scoped plugin configuration.

---

## 4. Development Mode & Candidate Staging Workflow

Before enabling a new or candidate extension:

```python
from pathlib import Path
from nova.plugins import PluginManager, validate_extension_dev_mode

pm = PluginManager(plugins_dir=Path("./data/plugins"), workspace_root=Path("./workspace"))

# Stage, AST-check, and run candidate tests inside the Linux namespace sandbox:
staged = pm.stage_candidate(manifest_dict, entrypoint_code, test_code=test_script)
assert staged["passed_checks"]

# Promote only after inspecting staged["permission_inspection"] and confirming:
pm.promote_candidate(Path(staged["candidate_dir"]), checks_passed=True, operator_approved=True)
pm.enable(manifest_dict["name"], granted_permissions=manifest_dict["required_permissions"])
```
