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
1) A short executive summary,
2) Per-finding non-actionable impact & remediation,
3) A responsible disclosure template,
4) A PoC skeleton with reproduction steps that do not include exploit payloads
5) Outputs local artifacts: findings.json, summary.txt, disclosure.md.

**How to use (quick)**

- Install tools (amass, subfinder, httpx, nuclei). Ensure they are in PATH.

- Set your OpenAI (or other LLM provider) key as an environment variable:

bash
export OPENAI_API_KEY="sk-..."   
# prefer using env var

next run:

bash
python orchestrator.py example.com

- Outputs will be under orchestrator_output/:

1) findings.json — structured sanitized findings

2) llm_summary.json — raw LLM response

3) disclosure.md — human-friendly responsible disclosure (if the LLM returned expected fields)

**Safety & Best practices (short checklist)**

- Only scan with written authorization (scope, IP range, domains).

- Limit Nuclei templates to safe / non-exploitative templates or only severity >= medium/ high for prioritized review.

- Rate-limit and schedule scans to avoid service disruption.

- When sharing reports publicly or with vendors include proof of authorization and avoid including request payloads or raw logs that contain sensitive or PII.

- Use out-of-band channels for high-severity findings (e.g., vendor security contact), and respect vendor disclosure windows.

**What I will not provide:**

- I will not generate exploit payloads, working exploit strings, SQL injection payloads, XSS payloads, or any weaponized PoC that could be copy-pasted to compromise a system.

- I will not help craft automated offensive playbooks or C2-style persistence chains.

  Hope this helps, cheers everyone!
