from __future__ import annotations

import json
from pathlib import Path
from typing import Any
from urllib.parse import urlsplit, urlunsplit

from .models import severity_rank
from .store import Store
from .util import canonical_json, ensure_dir, sha256_text, truncate, utc_now_iso

_NOT_TESTED = (
    "No authentication, account creation, or session-based testing",
    "No brute force, password spraying, fuzzing, or denial-of-service testing",
    "No exploitation or data access beyond the minimum evidence captured",
    "No request replay of archived URLs (they are intelligence only)",
    "No validation of discovered secrets against their providers",
    "No out-of-scope hosts, ports, or redirected destinations contacted",
    "No DELETE/PUT/PATCH requests and no state-changing actions",
)

_REMEDIATION = {
    "missing_security_headers": "Add HSTS, CSP, nosniff, frame restrictions, Referrer-Policy, and Permissions-Policy where appropriate.",
    "cookie_flags": "Set Secure, HttpOnly, and SameSite on session cookies.",
    "cors_misconfiguration": "Use a strict origin allowlist and never reflect arbitrary origins with credentials.",
    "exposed_file": "Remove sensitive files and metadata from the web root; rotate exposed credentials.",
    "secret_": "Rotate the credential, remove it from client bundles, and add secret scanning to CI.",
    "subdomain_takeover": "Remove the dangling DNS record or reclaim the third-party resource.",
    "dangling_cname": "Remove stale CNAME records and monitor targets for availability.",
    "graphql_introspection": "Disable production introspection or restrict it to authenticated developers.",
    "source_map_reference": "Exclude source maps from production builds or restrict access.",
    "tls_": "Renew certificates, disable obsolete protocols/ciphers, and automate expiry monitoring.",
    "version_disclosure": "Suppress version banners and keep the stack patched.",
    "debug_header": "Disable debug/profiler headers in production.",
    "cloud_storage_reference": "Require authenticated access and least-privilege bucket policies.",
    "archived_parameters": "Enforce server-side authorization and allowlist validation on all parameters.",
    "archived_paths": "Remove obsolete endpoints and enforce authentication on every route.",
    "interesting_subdomain": "Inventory internet-facing non-production systems and restrict access.",
}


def build_report(store: Store, run_id: str) -> dict[str, Any]:
    run = store.get_run(run_id)
    if run is None:
        raise KeyError(f"run not found: {run_id}")
    policy = run["policy"]
    assets = store.assets(run_id)
    hypotheses = store.hypotheses(run_id)
    request_stats = store.request_stats(run_id)
    artifacts = store.artifacts(run_id)
    findings = [item for item in hypotheses if item["status"] == "confirmed"]
    leads = [item for item in hypotheses if item["status"] == "lead"]
    findings.sort(key=lambda item: (-float(item["priority"]), severity_rank(item["severity"]), item["title"]))
    leads.sort(key=lambda item: (-float(item["priority"]), severity_rank(item["severity"]), item["title"]))

    stats = run.get("stats") or {}
    coverage = stats.get("coverage") or {}
    severity_counts: dict[str, int] = {}
    for item in findings:
        severity_counts[item["severity"]] = severity_counts.get(item["severity"], 0) + 1

    live_assets = [asset for asset in assets if asset.get("http_status")]
    for asset in assets:
        asset["url"] = _strip_url_query(str(asset.get("url") or ""))
    for item in findings + leads:
        item["evidence"] = _sanitize(item.get("evidence") or {})
    authorization = ((policy.get("program") or {}).get("authorization") or {})
    return {
        "schema": "bughunter.report/1",
        "generated_at": utc_now_iso(),
        "run": {
            "id": run["id"],
            "program": run["program"],
            "mode": run["mode"],
            "status": run["status"],
            "started_at": run["started_at"],
            "finished_at": run.get("finished_at"),
            "policy_path": run["policy_path"],
            "policy_sha256": run["policy_sha256"],
            "options": run.get("options") or {},
        },
        "authorization": authorization,
        "scope": policy.get("scope") or {},
        "rules": policy.get("rules") or {},
        "summary": {
            "assets": len(assets),
            "assets_in_scope": sum(1 for asset in assets if asset.get("in_scope")),
            "live_assets": len(live_assets),
            "requests": request_stats["total"],
            "requests_denied": request_stats["by_decision"].get("denied", 0),
            "confirmed": len(findings),
            "leads": len(leads),
            "severity_counts": severity_counts,
            "engine": stats.get("engine") or {},
            "session": stats.get("session") or {},
        },
        "assets": assets,
        "findings": findings,
        "leads": leads,
        "request_stats": request_stats,
        "coverage": coverage,
        "not_tested": list(_NOT_TESTED),
        "artifacts": artifacts,
    }


def _strip_url_query(url: str) -> str:
    if not url:
        return ""
    try:
        parts = urlsplit(url)
    except ValueError:
        return ""
    if not parts.scheme:
        return url
    return urlunsplit((parts.scheme, parts.netloc, parts.path or "/", "", ""))


def _sanitize(value: Any) -> Any:
    if isinstance(value, dict):
        result = {}
        for key, item in value.items():
            if isinstance(item, str) and key.lower() in {
                "authorization", "cookie", "set-cookie", "password", "secret", "token",
                "api_key", "apikey", "access_token", "private_key",
            }:
                result[key] = "[REDACTED]"
            else:
                result[key] = _sanitize(item)
        return result
    if isinstance(value, list):
        return [_sanitize(item) for item in value[:100]]
    if isinstance(value, str):
        return truncate(value, 4000)
    return value


def _cell(value: Any, limit: int = 80) -> str:
    text = str(value if value is not None else "—")
    text = text.replace("\n", " ").replace("|", "\\|")
    return truncate(text, limit)


def _evidence(evidence: dict[str, Any]) -> str:
    cleaned = _sanitize(evidence or {})
    text = json.dumps(cleaned, indent=2, ensure_ascii=False, sort_keys=True, default=str)
    if len(text) > 5000:
        text = text[:5000] + "\n... (truncated)"
    return f"```json\n{text}\n```"


def _remediation(item: dict[str, Any]) -> str:
    if item.get("remediation"):
        return str(item["remediation"])
    bug_class = str(item.get("bug_class", ""))
    for prefix, text in _REMEDIATION.items():
        if bug_class.startswith(prefix):
            return text
    return "Review the issue and apply the appropriate authorization, configuration, or patching fix."


def render_markdown(data: dict[str, Any]) -> str:
    run = data["run"]
    summary = data["summary"]
    auth = data.get("authorization") or {}
    scope = data.get("scope") or {}
    coverage = data.get("coverage") or {}
    lines: list[str] = []
    lines.append(f"# Bughunter report — {run['program']}")
    lines.append("")
    lines.append(
        "> **Authorized testing only.** This report contains automated observations and leads that "
        "require manual validation. No exploitation or data access was performed."
    )
    lines.append("")
    lines.append("## Run")
    lines.append("")
    lines.append("| Field | Value |")
    lines.append("| --- | --- |")
    lines.append(f"| Run ID | `{run['id']}` |")
    lines.append(f"| Status | **{run['status']}** |")
    lines.append(f"| Mode | {run['mode']} |")
    lines.append(f"| Started | {run['started_at']} |")
    lines.append(f"| Finished | {run.get('finished_at') or '—'} |")
    lines.append(f"| Policy | `{run['policy_path']}` |")
    lines.append(f"| Policy SHA-256 | `{run['policy_sha256']}` |")
    lines.append("")
    lines.append("## Authorization and scope")
    lines.append("")
    lines.append("| Field | Value |")
    lines.append("| --- | --- |")
    lines.append(f"| Authorization confirmed | {'YES' if auth.get('confirmed') else 'NO'} |")
    lines.append(f"| Authorized by | {_cell(auth.get('authorized_by') or '—')} |")
    lines.append(f"| Authorization date | {_cell(auth.get('date') or '—')} |")
    lines.append(f"| Program policy | {_cell(auth.get('policy_url') or '—', 120)} |")
    lines.append(f"| In-scope domains | {_cell(', '.join(scope.get('domains') or []), 200)} |")
    lines.append(f"| Exclusions | {_cell(', '.join(scope.get('exclusions') or []) or '—', 200)} |")
    lines.append(f"| IP ranges | {_cell(', '.join(scope.get('ip_ranges') or []) or '—', 120)} |")
    lines.append("")
    lines.append("## Summary")
    lines.append("")
    lines.append("| Metric | Value |")
    lines.append("| --- | --- |")
    lines.append(f"| Assets discovered | {summary['assets']} |")
    lines.append(f"| Assets in scope | {summary['assets_in_scope']} |")
    lines.append(f"| Live HTTP assets | {summary['live_assets']} |")
    lines.append(f"| Target requests | {summary['requests']} |")
    lines.append(f"| Policy-denied requests | {summary['requests_denied']} |")
    lines.append(f"| **Confirmed findings** | **{summary['confirmed']}** |")
    lines.append(f"| Leads needing review | {summary['leads']} |")
    if summary.get("severity_counts"):
        counts = ", ".join(f"{key}: {value}" for key, value in sorted(summary["severity_counts"].items()))
        lines.append(f"| Confirmed by severity | {counts} |")
    lines.append("")

    if data["findings"]:
        lines.append(f"## Confirmed findings ({len(data['findings'])})")
        lines.append("")
        for index, item in enumerate(data["findings"], 1):
            lines.append(f"### {index}. [{item['severity'].upper()}] {item['title']}")
            lines.append("")
            lines.append(f"**Asset:** `{item['asset']}`  ")
            lines.append(f"**Confidence:** {item['confidence']} · **Class:** `{item['bug_class']}` · **Priority:** {item['priority']}")
            lines.append("")
            lines.append(f"**Why it matters:** {item['rationale']}")
            lines.append("")
            lines.append(f"**Next step:** {item['next_step']}")
            lines.append("")
            lines.append(f"**Remediation:** {_remediation(item)}")
            lines.append("")
            lines.append("**Evidence:**")
            lines.append("")
            lines.append(_evidence(item.get("evidence") or {}))
            lines.append("")
    else:
        lines.append("## Confirmed findings")
        lines.append("")
        lines.append("No findings were confirmed in this run. Review the leads below.")
        lines.append("")

    if data["leads"]:
        lines.append(f"## Leads requiring manual review ({len(data['leads'])})")
        lines.append("")
        lines.append("| # | Severity | Asset | Lead | Confidence |")
        lines.append("| --- | --- | --- | --- | --- |")
        for index, item in enumerate(data["leads"], 1):
            lines.append(
                f"| {index} | {item['severity'].upper()} | `{_cell(item['asset'], 60)}` | "
                f"{_cell(item['title'], 90)} | {item['confidence']} |"
            )
        lines.append("")
        for index, item in enumerate(data["leads"], 1):
            lines.append(f"### L{index}. [{item['severity'].upper()}] {item['title']}")
            lines.append("")
            lines.append(f"**Asset:** `{item['asset']}` · **Confidence:** {item['confidence']} · **Priority:** {item['priority']}")
            lines.append("")
            lines.append(item["rationale"])
            lines.append("")
            lines.append(f"**Next step:** {item['next_step']}")
            lines.append("")
            lines.append("**Evidence:**")
            lines.append("")
            lines.append(_evidence(item.get("evidence") or {}))
            lines.append("")
    else:
        lines.append("## Leads requiring manual review")
        lines.append("")
        lines.append("No leads were generated.")
        lines.append("")

    if data["assets"]:
        lines.append("## Assets")
        lines.append("")
        lines.append("| Host | IPs | CNAME target | HTTP | Title | Technologies |")
        lines.append("| --- | --- | --- | --- | --- | --- |")
        for asset in data["assets"][:200]:
            lines.append(
                f"| `{_cell(asset['host'], 50)}` | {_cell(', '.join(asset.get('ips') or []) or '—', 45)} | "
                f"{_cell(asset.get('cname') or '—', 45)} | {asset.get('http_status') or '—'} | "
                f"{_cell(asset.get('title') or '—', 50)} | {_cell(', '.join(asset.get('tech') or []) or '—', 50)} |"
            )
        lines.append("")

    lines.append("## Coverage and limitations")
    lines.append("")
    if coverage:
        for key, value in coverage.items():
            if isinstance(value, (str, int, float, bool)):
                lines.append(f"- **{key.replace('_', ' ').title()}:** {value}")
            elif isinstance(value, list) and value:
                lines.append(f"- **{key.replace('_', ' ').title()}:** " + "; ".join(str(item) for item in value))
        lines.append("")
    lines.append("### Not tested")
    lines.append("")
    for item in data["not_tested"]:
        lines.append(f"- {item}")
    lines.append("")
    lines.append("## Audit trail")
    lines.append("")
    lines.append(f"- Audit log: `{coverage.get('audit_path', 'see .bughunter/audit/')}`")
    lines.append(f"- Database: `{coverage.get('database_path', 'see .bughunter/bughunter.db')}`")
    if data.get("artifacts"):
        lines.append(f"- Artifacts recorded: {len(data['artifacts'])}")
    lines.append("")
    lines.append("---")
    lines.append("")
    lines.append(
        "Only test assets you are explicitly authorized to test. Findings marked as leads are "
        "hypotheses, not confirmed vulnerabilities. Never use discovered secrets or access data "
        "beyond what the program permits."
    )
    lines.append("")
    return "\n".join(lines)


def write_reports(data: dict[str, Any], reports_dir: str | Path) -> dict[str, Any]:
    directory = ensure_dir(reports_dir)
    run_id = data["run"]["id"]
    markdown = render_markdown(data)
    json_text = json.dumps(data, indent=2, ensure_ascii=False, sort_keys=True, default=str)
    paths = {
        "markdown": directory / f"{run_id}.md",
        "json": directory / f"{run_id}.json",
    }
    hashes = {}
    for kind, path in paths.items():
        temporary = path.with_suffix(path.suffix + ".tmp")
        temporary.write_text(markdown if kind == "markdown" else json_text, encoding="utf-8")
        temporary.replace(path)
        hashes[kind] = sha256_text(markdown if kind == "markdown" else json_text)
    return {"paths": {key: str(path) for key, path in paths.items()}, "hashes": hashes}


__all__ = ["build_report", "render_markdown", "write_reports", "canonical_json"]
