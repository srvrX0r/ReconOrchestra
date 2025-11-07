# ReconOrchestra
A ready-to-run defensive-minded orchestrator script that chains the following household InfoSec names: -> Amass -> Subfinder -> httpx -> Nuclei , to feed the structured results into an LLM to prodiuce concise summaries, high-level impact, remediation guidance, and a responsible-disclosure / PoC skeleton THAT EXCLUDES exploit payloads.

In order words: Multi-chained recon + summarization orchestrator (safe, responsible)

Below is a ready-to-run, defensive-minded orchestrator script that chains Amass → Subfinder → httpx → Nuclei and feeds the structured results into an LLM to produce concise summaries, high-level impact, remediation guidance, and a responsible-disclosure / PoC skeleton (the PoC skeleton intentionally excludes exploit payloads and step-by-step exploit instructions).

**Important — read before running**

Only run this against targets you explicitly have permission to test. Unauthorized scanning or exploitation is illegal.

This script purposefully avoids producing exploit payloads or actionable exploit details. It is intended for authorized bug bounty / defensive reporting workflows (triage, reproducible non-exploit reproduction steps, remediation guidance, reporting templates).

Replace OPENAI_API_KEY and any tool paths as needed. Tools must be installed and available in your PATH (amass, subfinder, httpx, nuclei).

The script is Python 3.8+ and uses asyncio for concurrency.

**What the script does (high level)**

Runs Amass for passive domain enumeration (JSON output).

Runs Subfinder to find subdomains (JSON output).

Runs httpx to probe live hosts and collect response metadata (JSON output).

Runs Nuclei with safe/severity filtered templates to identify common surface issues (JSON output).

Aggregates and deduplicates findings into structured JSON.

Sends structured findings to an LLM with a carefully crafted prompt to create:

A short executive summary,

Per-finding non-actionable impact & remediation,

A responsible disclosure template,

A PoC skeleton with reproduction steps that do not include exploit payloads.

Outputs local artifacts: findings.json, summary.txt, disclosure.md.
