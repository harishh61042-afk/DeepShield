# User guide

1. **Create an account:** registration grants Developer role. A password must be 12+ characters. The app requires acknowledgement of terms/privacy and age 18+.
2. **Create a project:** enter a name, optional description and primary ecosystem.
3. **Upload:** choose a supported manifest or ZIP. The app parses in memory and displays the queued scan ID.
4. **Wait for worker:** keep `python -m app.workers.scan_worker` or the Compose worker running. The scan page polls while queued/processing.
5. **Review source status:** OSV/KEV/NVD state and unresolved versions appear before interpreting findings. A partial scan cannot be treated as clean.
6. **Review components:** filter names, inspect ecosystem, version evidence, relationship and source manifest.
7. **Review findings:** official severity is distinct from DepShield priority. Expand evidence to see CVSS, KEV, score factors, fixed versions and references.
8. **Request explanation:** local Ollama is used only if enabled; otherwise the response is labelled deterministic fallback. Review advice before changing dependencies.
9. **Export:** use CycloneDX JSON, JSON report or PDF report links in scan details.
10. **Manage a project:** owners can edit details, archive/restore, delete with name confirmation, and grant/revoke Auditor access from the project page.
11. **Open Security Center:** choose the project and use the tabs below to import a CycloneDX 1.4–1.6 JSON SBOM (maximum 5 MiB), compare imported/generated inventories, or query OSV for package URLs from an imported SBOM. Import validation is bounded structural validation; it does not claim full official JSON Schema verification.
12. **Set a project policy:** configure the permitted finding priority, KEV behavior, partial-scan handling and license allow/restricted lists. Evaluate a saved scan and inspect its persisted PASS/WARNING/FAIL evidence. Use `ci/security_policy_gate.py` with the workflow in `docs/examples/depshield-policy-gate.yml` to make the same server-side decision in CI.
13. **Review remediation:** the plan groups affected findings and suggests an upgrade only when OSV provides one unambiguous fixed version and a current version is known. Download the PDF or JSON. The application never edits dependency manifests; review upgrades and test them in your own workflow.
14. **Review licenses:** refresh checks fixed public npm, PyPI or crates.io registry endpoints for at most 100 versioned components per request. Review registry evidence and unknown/ambiguous values, then export JSON/PDF. License results are not legal advice.
15. **Schedule monitoring:** owners can configure or pause a 6–720 hour project schedule. The worker re-scans the latest saved parsed inventory through the regular queue. New alerts appear in Security Center; optional email requires operator SMTP configuration and enabling the user preference.
16. **Account settings:** update display name, change password, revoke other sessions, or permanently delete the account and owned project data after entering the current password.

An Auditor can only view projects explicitly shared with that account. Administrators can inspect users, scan jobs, audit records and available service health, and change Developer/Auditor roles; create administrator accounts only with the CLI. Terminal scan snapshots older than the configured retention period are pruned by the worker once per day. Scheduled monitoring copies parsed inventory because raw uploaded files are not retained. A missing result from a partial scan is never a resolution alert.
