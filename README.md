# ReconOrchestra - The Security Researcher's Recon-Orchestrator

Comprehensive repository documentation for the Recon-Orchestrator project — a responsible, defensive-focused orchestration that chains Amass → Subfinder → httpx → Nuclei and summarizes findings with an LLM. This documentation covers project overview, secure deployment, configuration, operational security (OpSec), developer guidelines, CI/CD integration, responsible-disclosure templates, and hardening checklists for keeping the repository and runs safe and auditable.

Important security reminder: This project is intended only for authorized security testing. Running reconnaissance/scanning tools or issuing payloads against systems you do not own or for which you do not have explicit written permission is illegal and unethical. This repo purposefully avoids exploit payloads and weaponized PoC instructions.

**Table of Contents**

1. Project Overview

2. Quick Start / Example Run

3. Repository layout

4. Installation & prerequisites

5. Configuration

6. Usage & commands

7. Output files & artifacts

8. Security & Hardening

9. Operational Safety (OpSec) & Legal

10. Secrets management

11. CI / CD & Automation

12. Testing & Validation

13. Contributing guide

14. Issue and disclosure templates

15. License & Attribution

16. Changelog & Release Process

17. Appendix: Example GitHub Actions workflow / Dockerfile / .gitignore

**Project Overview**

Name: ReconOrchestra

Purpose: Orchestrate common reconnaissance tooling (Amass, Subfinder, httpx, Nuclei), aggregate sanitized findings, and produce defensively-oriented summaries and disclosure artifacts using an LLM. The project intentionally prevents production of weaponized PoC payloads.

Goals:

Standardize recon pipelines and artifact formats.

Produce safe, audit-ready reporting artifacts for triage and disclosure.

Provide secure defaults and developer guidance to reduce accidental misuse.

Primary languages / tools: Python 3.8+, Bash-friendly CLI wrappers, amass, subfinder, httpx, nuclei, (LLM provider via API).


**Installation & prerequisites**
System tools (must be installed on host):

1. amass (v3+ recommended) — passive enumeration

2. subfinder (latest) — fast subdomain finding

3. httpx — HTTP probing

4. nuclei — template-based scanner

5. curl or an HTTP client for LLM API calls (or use official SDK)

##Prefer package managers or official releases. Example install links belong in repo INSTALL.md but are intentionally omitted here.##


**Python requirements (optional)**

If the repo uses Python-only helpers, include requirements.txt. Typical libs:

1. requests

2. aiohttp (if you convert to async HTTP)

3. python-dotenv (optional)

**Runtime user and privileges**

Run tooling as an unprivileged user. Do not run scanning pipelines as root unless explicitly required and you understand system risk.


**Configuration**

Configuration is intentionally minimal and externalized. Use an .env file:
(see example/example.env in Repo)


**Secure configuration best-practices**

Keep secrets out of source control; use environment variables or a secrets manager (AWS Secrets Manager, HashiCorp Vault, GCP Secret Manager, Azure Key Vault).

Lock file permissions for config files: chmod 600 example.env.

Prefer ephemeral credentials for CI/CD (short-lived tokens).

Usage & commands

The main entrypoint is orchestrator.py.

Basic usage:

python orchestrator.py <domain>

Advanced uses / flags to consider (implement as CLI options):

--config <file> — specify config file

--no-llm — run pipeline and aggregate but skip LLM calls

--limit <n> — cap hosts/targets scanned by Nuclei

--dry-run — simulate commands without executing

--threads <n> — control concurrency

--output <dir> — custom output directory

Example: safe dry run:

bash
python orchestrator.py example.com --dry-run --no-llm

Output files & artifacts

All runtime artifacts should be written to OUTPUT_DIR (default orchestrator_output/) and NEVER committed.

Typical artifacts:

findings.json — sanitized structured findings

llm_summary.json — LLM response (structured)

disclosure.md — human readable responsible-disclosure report (sanitized)

httpx_out.jsonl — raw httpx output (optional; consider removing PII)

nuclei_out.jsonl — raw nuclei output (optional; sanitize before sharing)

Sanitization guidance

Strip request/response bodies that may contain secrets.

Truncate or redact headers that include cookies, auth tokens, or other sensitive fields.

Keep exact evidence limited to: URL paths, status codes, and safe matcher metadata.
