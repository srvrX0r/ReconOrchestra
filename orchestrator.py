#!/usr/bin/env python3
"""
orchestrator.py
Chain Amass -> Subfinder -> httpx -> Nuclei, then summarize with an LLM.
Defensive-only outputs: no exploit payloads or weaponized instructions.
"""

import asyncio
import json
import shlex
import os
import sys
from pathlib import Path
from datetime import datetime
import subprocess
from typing import List, Dict, Any

# ---------- Configuration ----------
AMASS_CMD = "amass enum -passive -d {domain} -json -"  # streams JSON to stdout
SUBFINDER_CMD = "subfinder -d {domain} -silent -oJ -"  # JSON lines
HTTPX_CMD = "httpx -l {input_file} -silent -json -o {out_file} --follow-redirects"
NUCLEI_CMD = "nuclei -l {input_file} -json -o {out_file} -severity critical,high,medium -tags safe"  # tags filter optional
# NOTE: Adjust commands to your environment / template selection. Use -timeout, -c, etc. as needed.

OUTPUT_DIR = Path("orchestrator_output")
OPENAI_API_KEY = os.getenv("OPENAI_API_KEY", "<PUT_YOUR_KEY_IN_ENV_OR_HERE>")  # recommended: set as env var
OPENAI_API_URL = "https://api.openai.com/v1/chat/completions"  # example, adapt if you use another client
LLM_MODEL = "gpt-5-thinking-mini"  # name for clarity in prompts; change if using other model via provider

# ---------- Helpers ----------
def ensure_output_dir():
    OUTPUT_DIR.mkdir(parents=True, exist_ok=True)

async def run_cmd(cmd: str, timeout: int = 300) -> str:
    """Run a shell command asynchronously and return stdout."""
    proc = await asyncio.create_subprocess_shell(cmd,
                                                 stdout=asyncio.subprocess.PIPE,
                                                 stderr=asyncio.subprocess.PIPE)
    try:
        stdout, stderr = await asyncio.wait_for(proc.communicate(), timeout=timeout)
    except asyncio.TimeoutError:
        proc.kill()
        await proc.communicate()
        raise
    if proc.returncode != 0 and stdout is None:
        raise RuntimeError(f"Command failed: {cmd}\nReturn code: {proc.returncode}\nStderr: {stderr.decode()}")
    return stdout.decode(errors="ignore")

def parse_json_lines(jlines: str) -> List[Dict[str, Any]]:
    """Parse JSON lines or a JSON array string into Python list."""
    items = []
    for line in jlines.splitlines():
        line = line.strip()
        if not line:
            continue
        try:
            obj = json.loads(line)
            items.append(obj)
        except json.JSONDecodeError:
            # try whole content (array)
            try:
                arr = json.loads(jlines)
                if isinstance(arr, list):
                    return arr
            except Exception:
                continue
    return items

# ---------- Orchestration steps ----------
async def run_amass(domain: str) -> List[Dict[str, Any]]:
    cmd = AMASS_CMD.format(domain=shlex.quote(domain))
    print(f"[+] Running Amass (passive) for {domain} ...")
    out = await run_cmd(cmd)
    results = parse_json_lines(out)
    print(f"[+] Amass -> {len(results)} records")
    return results

async def run_subfinder(domain: str) -> List[Dict[str, Any]]:
    cmd = SUBFINDER_CMD.format(domain=shlex.quote(domain))
    print(f"[+] Running Subfinder for {domain} ...")
    out = await run_cmd(cmd)
    results = parse_json_lines(out)
    print(f"[+] Subfinder -> {len(results)} records")
    return results

async def run_httpx(hosts: List[str], tag: str = "httpx") -> List[Dict[str, Any]]:
    input_file = OUTPUT_DIR / f"{tag}_hosts.txt"
    out_file = OUTPUT_DIR / f"{tag}_out.jsonl"
    input_file.write_text("\n".join(hosts))
    cmd = HTTPX_CMD.format(input_file=shlex.quote(str(input_file)),
                           out_file=shlex.quote(str(out_file)))
    print(f"[+] Running httpx against {len(hosts)} hosts ...")
    await run_cmd(cmd)
    if out_file.exists():
        data = out_file.read_text()
        items = parse_json_lines(data)
        print(f"[+] httpx -> {len(items)} records")
        return items
    return []

async def run_nuclei(hosts_or_urls: List[str], tag: str = "nuclei") -> List[Dict[str, Any]]:
    input_file = OUTPUT_DIR / f"{tag}_targets.txt"
    out_file = OUTPUT_DIR / f"{tag}_out.jsonl"
    input_file.write_text("\n".join(hosts_or_urls))
    cmd = NUCLEI_CMD.format(input_file=shlex.quote(str(input_file)),
                            out_file=shlex.quote(str(out_file)))
    print(f"[+] Running Nuclei (severity filtered) against {len(hosts_or_urls)} targets ...")
    await run_cmd(cmd)
    if out_file.exists():
        data = out_file.read_text()
        items = parse_json_lines(data)
        print(f"[+] Nuclei -> {len(items)} records")
        return items
    return []

# ---------- Aggregation ----------
def aggregate_findings(amass, subfinder, httpx, nuclei) -> Dict[str, Any]:
    """
    Aggregate and normalize outputs into a safe, structured 'findings' object.
    Each finding has: id, type, target, evidence (non-exploitable), severity_hint, metadata.
    """
    findings = []
    seen = set()

    # collect subdomains from amass and subfinder
    def add_subdomain(src, item):
        name = None
        if isinstance(item, dict):
            name = item.get("name") or item.get("host") or item.get("subdomain")
        else:
            name = str(item)
        if not name:
            return
        key = ("subdomain", name)
        if key in seen:
            return
        seen.add(key)
        findings.append({
            "id": f"subdomain-{len(findings)+1}",
            "type": "subdomain",
            "source": src,
            "target": name,
            "evidence": {},
            "severity_hint": "info",
            "metadata": item
        })

    for it in amass:
        add_subdomain("amass", it)
    for it in subfinder:
        add_subdomain("subfinder", it)

    # httpx entries -> live endpoints
    for it in httpx:
        host = it.get("url") or it.get("host") or it.get("input")
        if not host:
            continue
        key = ("httpx", host)
        if key in seen:
            continue
        seen.add(key)
        findings.append({
            "id": f"httpx-{len(findings)+1}",
            "type": "live",
            "source": "httpx",
            "target": host,
            "evidence": {
                "status_code": it.get("status"),
                "title": it.get("title"),
                "server": it.get("headers", {}).get("server"),
                "content_length": it.get("content_length"),
            },
            "severity_hint": "info",
            "metadata": it
        })

    # nuclei alerts -> issues (we sanitize by removing exploit strings)
    for it in nuclei:
        template_id = it.get("templateID") or it.get("info", {}).get("name", "unknown")
        host = it.get("host") or it.get("matched") or it.get("request", {}).get("url")
        name = it.get("name") or it.get("info", {}).get("name")
        severity = it.get("severity") or it.get("info", {}).get("severity", "medium")
        # evidence: keep safe fields only
        evidence = {
            "matched": it.get("matched"),
            "matcher_name": it.get("matcher_name"),
            "ip": it.get("ip"),
            "severity": severity,
            # do not include matched payload or request body/headers that contain injection content
        }
        key = ("nuclei", template_id, host)
        if key in seen:
            continue
        seen.add(key)
        findings.append({
            "id": f"nuclei-{len(findings)+1}",
            "type": "nuclei",
            "source": "nuclei",
            "target": host,
            "name": name or template_id,
            "evidence": evidence,
            "severity_hint": severity,
            "metadata": it
        })

    return {
        "generated_at": datetime.utcnow().isoformat() + "Z",
        "counts": {"amass": len(amass), "subfinder": len(subfinder), "httpx": len(httpx), "nuclei": len(nuclei)},
        "findings": findings
    }

# ---------- LLM integration (safe prompt) ----------
def build_llm_prompt(findings: Dict[str, Any]) -> str:
    """
    Create a defensive prompt that instructs the LLM to provide:
    - Executive summary
    - Non-actionable impact (high-level)
    - Remediation steps (safe)
    - Responsible disclosure template
    - PoC skeleton WITHOUT exploit payloads
    """
    # Keep the prompt explicit about *no exploit payloads* and that this is for authorized testing only
    prompt = f"""
You are a security summarization assistant. You will be given a structured JSON object of reconnaissance and scanning results from authorized testing tools
(Amass, Subfinder, httpx, Nuclei). Produce the following outputs in JSON:

1) executive_summary: A 2-4 sentence high-level summary of the scope & main observations.
2) findings: For each input finding, produce:
   - id (same as input)
   - title (one-line)
   - one_line_summary (non-actionable description of what was observed)
   - severity (choose from: informational, low, medium, high, critical). Use 'severity_hint' as guidance but apply judgment.
   - high_level_impact (one short paragraph describing potential impact at a conceptual level; do NOT include attack steps, payloads, proof-of-exploit data, or specific crafted requests).
   - remediation (concise developer-focused remediation steps).
   - reproduction_skeleton (a short non-actionable skeleton describing how to reproduce at a high level, e.g., "send a GET request to https://example/path with parameter X set to a redirect URL and observe redirect behavior" — do NOT include exploit strings or full payloads).
3) disclosure_template: A responsible-disclosure email/issue template with sections: Summary, Affected URLs, Severity, High-level Impact, How to Reproduce (non-exploit skeletons), Suggested Fixes, Contact, Proof-of-Authorization statement, and Request for confirmation of remediation timeline.
4) guidance: Short checklist of safe next steps for triage and remediation (logs to collect, minimal safe tests to confirm mitigation, sample headers to check, config flags to verify) — again, avoid any exploit content.

Constraints:
- This output will be embedded in a JSON file. Return strict JSON. Do NOT add exploit payloads, vulnerable request bodies, or exact injection strings.
- Assume all tests were authorized. Add a reminder in the 'disclosure_template' to include evidence of authorization when sending.
- Use the following JSON input (verbatim) marked by BEGIN_JSON and END_JSON.

BEGIN_JSON
{json_input}
END_JSON

Only produce valid JSON for the full response (no surrounding commentary). Keep fields concise.
""".strip()

    return prompt

async def call_llm_generate(payload_text: str) -> Dict[str, Any]:
    """
    Minimal LLM call via HTTP to OpenAI-style endpoint.
    This is a simple example using 'requests' via subprocess to avoid extra dependencies in this example.
    In production, use your preferred OpenAI or LLM client (openai, azure-openai, etc.)
    """
    # We'll use 'curl' to avoid adding a dependency; in real deployments prefer official SDKs.
    tmp_prompt = OUTPUT_DIR / "llm_prompt.json"
    tmp_out = OUTPUT_DIR / "llm_response.json"
    headers = {
        "Authorization": f"Bearer {OPENAI_API_KEY}",
        "Content-Type": "application/json"
    }
    # Build a simple chat-completion style payload (adjust fields for your provider)
    body = {
        "model": LLM_MODEL,
        "messages": [{"role": "user", "content": payload_text}],
        "temperature": 0.2,
        "max_tokens": 1200
    }
    tmp_prompt.write_text(json.dumps(body))
    # Use curl to call the API. If you prefer Python requests / SDK, replace this section.
    curl_cmd = (
        "curl -s -X POST "
        f"-H 'Authorization: Bearer {OPENAI_API_KEY}' "
        "-H 'Content-Type: application/json' "
        f"--data @{shlex.quote(str(tmp_prompt))} "
        f"{OPENAI_API_URL} > {shlex.quote(str(tmp_out))}"
    )
    print("[+] Calling LLM for summarization (this will send structured data to the LLM provider).")
    proc = await asyncio.create_subprocess_shell(curl_cmd, stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.PIPE)
    stdout, stderr = await proc.communicate()
    if proc.returncode != 0:
        print("LLM call failed:", stderr.decode())
        return {}
    # parse output (provider response shape may vary). This example expects a JSON with 'choices'
    raw = tmp_out.read_text()
    try:
        resp = json.loads(raw)
        # extract assistant content (this depends on provider)
        content = None
        if "choices" in resp and len(resp["choices"]) > 0:
            # Chat-completion style might put text in choices[0].message.content
            ch = resp["choices"][0]
            if "message" in ch and "content" in ch["message"]:
                content = ch["message"]["content"]
            elif "text" in ch:
                content = ch["text"]
        if content is None:
            # fallback: entire response
            content = json.dumps(resp)
        # content is expected to be a JSON string — try to parse it
        try:
            parsed = json.loads(content)
            return parsed
        except json.JSONDecodeError:
            # if the model returned JSON within text, try to extract leading JSON block
            # fallback: return raw content
            return {"raw_model_output": content, "api_response": resp}
    except Exception as ex:
        print("Failed to parse LLM response:", ex)
        return {"raw": raw}

# ---------- Main flow ----------
async def main(domain: str):
    ensure_output_dir()

    # Run enumeration concurrently
    amass_task = asyncio.create_task(run_amass(domain))
    subfinder_task = asyncio.create_task(run_subfinder(domain))

    amass = await amass_task
    subfinder = await subfinder_task

    # Extract candidate hosts (from parsed objects)
    hosts = set()
    for item in amass + subfinder:
        # many tools return dicts with 'name' or simple strings
        if isinstance(item, dict):
            name = item.get("name") or item.get("host") or item.get("subdomain") or item.get("domain")
        else:
            name = str(item)
        if name:
            hosts.add(name)

    hosts = sorted(hosts)
    if not hosts:
        print("[!] No hosts found; exiting.")
        return

    # httpx on hosts
    httpx_results = await run_httpx(hosts)

    # Build targets for nuclei: prefer URLs from httpx (url field), fallback to hostnames
    nuclei_targets = []
    for it in httpx_results:
        url = it.get("url")
        if url:
            nuclei_targets.append(url)
        else:
            input_host = it.get("input") or it.get("host")
            if input_host:
                nuclei_targets.append(input_host)
    # dedupe and limit
    nuclei_targets = list(dict.fromkeys(nuclei_targets))[:500]  # safety limit

    nuclei_results = []
    if nuclei_targets:
        nuclei_results = await run_nuclei(nuclei_targets)
    else:
        print("[*] No targets for Nuclei.")

    # Aggregate
    findings_obj = aggregate_findings(amass, subfinder, httpx_results, nuclei_results)

    # Save findings
    findings_path = OUTPUT_DIR / "findings.json"
    findings_path.write_text(json.dumps(findings_obj, indent=2))
    print(f"[+] Findings saved to {findings_path}")

    # Build LLM prompt
    prompt = build_llm_prompt(findings=json.dumps(findings_obj))
    # The helper expects to be passed the JSON as {json_input} in the prompt string above; do that:
    prompt = prompt.replace("{json_input}", json.dumps(findings_obj))

    # Call LLM
    llm_result = await call_llm_generate(prompt)
    # Save LLM output
    llm_out_path = OUTPUT_DIR / "llm_summary.json"
    llm_out_path.write_text(json.dumps(llm_result, indent=2))
    print(f"[+] LLM summary saved to {llm_out_path}")

    # Optionally produce a human-readable disclosure markdown from the LLM output (if the LLM returned structured fields)
    try:
        disclosure_md = "# Responsible Disclosure Report\n\n"
        exec_summary = llm_result.get("executive_summary", "")
        disclosure_md += f"## Executive Summary\n\n{exec_summary}\n\n"

        disclosure_md += "## Findings\n\n"
        for f in llm_result.get("findings", []):
            disclosure_md += f"### {f.get('id')} - {f.get('title')}\n"
            disclosure_md += f"- Severity: {f.get('severity')}\n"
            disclosure_md += f"- Summary: {f.get('one_line_summary')}\n"
            disclosure_md += f"- Reproduction: {f.get('reproduction_skeleton')}\n"
            disclosure_md += f"- Remediation: {f.get('remediation')}\n\n"

        disclosure_md += "## Disclosure Template\n\n"
        disclosure_md += llm_result.get("disclosure_template", "")
        disclosure_md += "\n\n---\n\n"
        disclosure_md += "Generated on: " + datetime.utcnow().isoformat() + "Z\n"
        (OUTPUT_DIR / "disclosure.md").write_text(disclosure_md)
        print(f"[+] Disclosure markdown written to {(OUTPUT_DIR / 'disclosure.md')}")
    except Exception as e:
        print("Could not produce disclosure.md:", e)

if __name__ == "__main__":
    if len(sys.argv) < 2:
        print("Usage: python orchestrator.py example.com")
        sys.exit(1)
    domain = sys.argv[1].strip()
    asyncio.run(main(domain))
