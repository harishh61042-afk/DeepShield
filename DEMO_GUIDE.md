# DepShield demonstration guide

This demonstration uses read-only sample manifests. Do not install their intentionally vulnerable package versions or run sample applications.

## Setup

1. Install Python 3.12+, Node.js 22.13+, 24, or 26+, PostgreSQL 16+ (or Docker), and optionally Ollama.
2. Follow the root README. Keep FastAPI and the scan worker running in separate terminals.
3. Register an account and create a project. Name it `Python dependency demo`.
4. Upload `sample-projects/python-demo/requirements.txt`.
5. Open the scan from project history and wait for the worker.
6. Review source status first. If OSV, KEV or another required resolution is unavailable, the result is partial.
7. Inspect the Django component and OSV advisory findings; expand a finding to see official severity, DepShield score, CISA state, fixed version evidence and source links.
8. Use **Explain this finding**. If Ollama is enabled it should say `Local Ollama explanation`; otherwise the label must say `Deterministic explanation`.
9. Open Components and inspect the declared/unverified status.
10. Download CycloneDX JSON, JSON report, and PDF report. Confirm the scan ID and source-coverage caveat.
11. Repeat with `sample-projects/javascript-demo/package-lock.json`, `sample-projects/java-demo/pom.xml`, `sample-projects/go-demo/go.mod`, and `sample-projects/rust-demo/Cargo.lock`.
12. Create another scan for the same project and use the Compare scan history panel; findings missing from partial scans are not described as fixed.
13. Open **Security center** and compare the generated CycloneDX SBOM with another scan, or import a CycloneDX 1.4–1.6 JSON file you already use.
14. Compare the imported/generated BOM snapshots, run the package URL vulnerability lookup, then save and evaluate the project's policy.
15. Open Remediation and License compliance, review evidence/unknown states, and download the PDF reports. Do not interpret proposed versions as automatic changes or license data as legal advice.
16. Configure a monitoring schedule, pause/resume it, and review the Alerts tab. To see scan-change alerts, let the schedule complete another scan or create a later scan with a changed inventory.

## Fixture source records

- Django 4.2.4 / `PYSEC-2023-225`: affected range before 4.2.5 according to [OSV](https://osv.dev/vulnerability/PYSEC-2023-225).
- lodash 4.17.18 / `CVE-2020-8203`: the advisory reports versions before 4.17.20 affected according to [OSV](https://osv.dev/vulnerability/CVE-2020-8203).
- Log4j Core 2.14.1 / `CVE-2021-44228`: the record identifies `log4j-core` as affected; see [OSV](https://osv.dev/vulnerability/CVE-2021-44228).
- `golang.org/x/text` v0.3.2 / `GO-2020-0015`: OSV lists a fix at 0.3.3; see [OSV](https://osv.dev/vulnerability/GO-2020-0015).
- Rust `time` 0.2.22 / `RUSTSEC-2020-0071`: OSV marks the affected range through 0.2.22; see [OSV](https://osv.dev/vulnerability/RUSTSEC-2020-0071).

Live OSV matching can return source-specific results and aliases; the fixture advisory identifiers above describe why the versions are educational examples, not predetermined expected scan counts. Do not add these findings to synthetic fixtures or present a recorded result as a live source result.

## Administrator walkthrough

Run `scripts/create_admin.py` from a local configured backend environment. Sign into the Administrator account, inspect user status/role controls, scan jobs, audit events and service health. Administrator grants are CLI-only.

## Demonstration limitations

Live scan outcomes depend on public source availability and a configured database/worker. The user-facing comparison and auditor sharing flows are available, but PostgreSQL integration, Docker, Playwright and accessibility checks have not been run in this assembly environment. Do not claim a clean scan when source status is partial.
