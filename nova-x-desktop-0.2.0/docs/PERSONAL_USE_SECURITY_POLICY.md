# DEV — Personal-Use Security and Autonomy Policy

**Deployment Model:** Privately operated, single-user personal AI system installed directly on the operator's Kali Linux computer (`single_user_personal_kali_linux`). DEV is **not** a public SaaS, enterprise multi-tenant service, or compliance-bound commercial appliance.

## 1. Security Framework Flexibility (`nova/personal_policy/engine.py`)
- External frameworks (OWASP GenAI Top 10, NIST AI RMF, CIS benchmarks) are treated strictly as **engineering references** (`strict_owasp_checklist_mandatory = False`, `enterprise_certification_required = False`).
- Multi-tenant or enterprise-only controls (e.g., mandatory local SSO/RBAC prompts, cloud tenant isolation ceremonies) are skipped when they add friction without addressing real single-user local threats.

## 2. Broad Kali Linux Personal Computing Capabilities
DEV exposes all **14** practical personal computing domains locally:
1. `terminal_and_command_execution`
2. `installed_applications`
3. `file_operations`
4. `hardware_and_driver_discovery`
5. `system_diagnostics`
6. `software_installation`
7. `development_tools`
8. `background_services`
9. `authorized_network_operations`
10. `registered_remote_servers`
11. `browser_automation`
12. `screen_capture`
13. `automation_and_scripting`
14. `software_and_security_research`

Administrative actions use normal Linux OS mechanisms (`system.run_privileged` via `pkexec` / `polkit`) rather than storing sudo passwords or running DEV as root.

## 3. Minimal Human Intervention & Persistent Permissions
- Users can configure **persistent permission grants** (`personal_persistent_grants` in SQLite) or switch to `personal_power_user` / `cyber_lab_research` profiles via CLI (`nova-x personal-policy`), Qt Desktop (`Permissions` page), `ToolRegistry`, or `/api/personal-policy/*`.
- Previously authorized commands, interpreters (`python3`, `pytest`, `ruff`), build tools, Git workflows, and lab tools inside granted scopes execute **without repeated approval dialogs**.
- Minimal intervention is never treated as unlimited authorization (`minimal_intervention_equals_unlimited_authorization = False`).

## 4. Material Risk-Proportionate Safeguards
DEV retains lightweight, real technical safeguards against the **9** material personal-computing risks:
1. **Accidental deletion / overwrite:** Automatic SHA-256 pre-mutation backups and one-step rollback (`RiskProportionateSafeguardEngine.guarded_file_operation` / `rollback_file_operation`).
2. **Credential exposure:** Hard blocks on `.ssh/id_*`, `.gnupg`, `/etc/shadow`, and secret CLI flags even under `personal_power_user` mode.
3. **Malicious downloads:** SHA-256 verification and ELF/script header inspection before activation.
4. **Compromised plugins:** Static AST/pattern inspection against undeclared subprocess/network/credential exfiltration.
5. **Dangerous AI-generated commands:** Deterministic denial of `rm -rf /`, `mkfs*`, `dd of=/dev/*`, fork bombs, and unauthenticated privilege wrappers.
6. **Unauthorized remote access:** Loopback (`127.0.0.1` / `::1`) bind enforcement unless LAN exposure is explicitly authorized.
7. **Unintended external disclosure:** Outbound secret redaction and context minimization.
8. **Unrecoverable system modifications:** Critical root/boot/etc path protection.
9. **Uncontrolled resource consumption:** Bounded process timeouts and memory budgets.

## 5. Personal Cybersecurity Research
- Supports all **8** cybersecurity engineering & research capabilities (`vulnerability_discovery`, `defensive_testing`, `controlled_exploitation_research`, `reverse_engineering`, `digital_forensics`, `application_security_assessment`, `security_tool_development`, `remediation_verification`) without artificially limiting security knowledge.
- Owned/authorized lab targets registered via `PersonalCyberResearchAuthorizer.register_persistent_lab_environment` carry standing persistent authorization so recurring lab steps run without repeated prompts, while unowned external targets remain blocked.

## 6. Local Privacy & Visible External Transfers
- Memory, files, credentials, project data, settings, and task history remain **local by default**.
- Private credentials and unrestricted host access are **never** exposed to remote AI providers.
- Every external AI provider transfer is logged in `personal_transfer_visibility_log` (inspectable via `nova-x personal-policy --transfers` and `GET /api/personal-policy/transfers`) and configurable per provider and per local-only project.

## 7. Anti-Compliance Theatre (`FrameworkFlexibilityAndAntiTheatreGuard`)
Enforces zero enterprise compliance theatre: no unnecessary single-user auth prompts, no repeated approval dialogs for granted scopes, no artificial capability blocks without concrete technical cause, working code prioritized over paperwork, and zero heavy dependencies added.
