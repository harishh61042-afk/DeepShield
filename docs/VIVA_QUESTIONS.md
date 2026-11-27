# DepShield viva questions and concise answers

1. **What problem does DepShield address?** It organizes dependency inventory and public vulnerability evidence into repeatable scans and reports.
2. **What does SBOM mean?** Software Bill of Materials, a machine-readable inventory of software components.
3. **Which SBOM format is used?** CycloneDX JSON 1.6.
4. **What is a PURL?** A standardized Package URL that identifies a package by type, namespace, name and optionally version.
5. **Why use OSV?** It provides vulnerability records queried by package ecosystem, name and exact version.
6. **What is the purpose of NVD integration?** Best-effort CVE metadata enrichment such as CVSS and CWE, not unreliable package-name matching.
7. **What does CISA KEV mean?** It indicates a CVE is listed in CISA's Known Exploited Vulnerabilities catalog.
8. **Does absence from KEV prove a vulnerability is not exploited?** No. It means only that the available catalog did not list it.
9. **How is DepShield priority calculated?** CVSS × 6, plus KEV, directness and fixed-version factors, capped at 100.
10. **Is that score an official industry score?** No. It is a documented academic triage heuristic.
11. **How are missing CVSS values handled?** The score/priority is marked Unknown, not zero.
12. **Why not scan by package-name substring?** It risks mismatching unrelated packages; exact ecosystem/name/version matching is safer.
13. **Which file types are parsed?** requirements.txt, package-lock.json, pom.xml, go.mod, Cargo.lock and ZIP archives containing them.
14. **Why can a requirements pin still be unverified?** It expresses a declared requirement, not proof of what is installed in a running environment.
15. **How does DepShield handle Cargo directness?** Cargo.lock alone does not prove the direct dependency relationship, so directness is unknown.
16. **Does the scanner install packages?** No. It parses files and queries public data.
17. **How is ZIP Slip prevented?** Archive paths are checked and members are never extracted to a filesystem path.
18. **How are ZIP bombs limited?** Upload byte, entry count and total expanded-size limits are applied.
19. **How are XML external entities addressed?** POM files use `defusedxml` and a size cap.
20. **How are passwords stored?** As Argon2id password hashes, never plain text.
21. **How are sessions stored?** Random opaque cookie values are returned once; only an HMAC digest is stored.
22. **Why is CSRF protection needed?** Browsers automatically attach cookies; a separate token/header check protects state-changing requests.
23. **How is role-based access enforced?** FastAPI checks role and project object authorization for each protected route.
24. **What can an Auditor do?** Read only explicitly shared projects and related scans; no project mutation or upload.
25. **Why is there a separate scan worker?** It keeps long scans out of API requests and stores jobs durably in PostgreSQL.
26. **How are interrupted jobs recovered?** A worker can reclaim a stale processing job under a row lock, subject to retry limits.
27. **What does a partial scan mean?** A required source or dependency resolution was unavailable; absence of findings is not a clean result.
28. **What does Ollama add?** Optional local, structured advisory explanations; core scans work without it.
29. **How is AI fallback represented?** Deterministic text is explicitly labelled and never claimed to be AI output.
30. **How does the AI handle prompt injection?** Advisory/package data is framed as untrusted evidence, output is schema-validated, and commands/exploits are prohibited.
31. **What report types are available?** CycloneDX JSON SBOM, scan JSON and PDF.
32. **Why use PostgreSQL?** It provides relational constraints and durable multi-process scan jobs required by the project.
33. **What does Alembic do?** It versions and applies database schema migrations.
34. **How are SQL injection risks reduced?** SQLAlchemy ORM/parameterized statements are used instead of string-built SQL.
35. **What data is retained from an upload?** Parsed dependency data, file name/size/hash and scan results; the complete uploaded bytes are discarded.
36. **What remains before public deployment?** Full automated tests, production hardening, external-service validation, privacy/legal review and operations controls.
