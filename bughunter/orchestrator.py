from __future__ import annotations

import re
import secrets
import traceback
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any
from urllib.parse import urlsplit, urlunsplit

from rich.console import Console
from rich.panel import Panel
from rich.table import Table

from . import __version__
from .analyze.fingerprint import (
    analyze_html,
    cookie_technologies,
    fingerprint_response,
    parse_cookies,
    PageInfo,
)
from .analyze.hypotheses import (
    HypothesisEngine,
    archive_param_signal,
    archive_path_signal,
    cloud_signal,
    dangling_cname_signal,
    endpoint_signal,
    secret_signal,
    source_map_signal,
    subdomain_signal,
)
from .analyze.secrets import extract_intel, interesting_path
from .audit import AuditLog
from .checks import cors as cors_check
from .checks import exposed as exposed_check
from .checks import graphql as graphql_check
from .checks import headers as header_check
from .checks import takeover as takeover_check
from .checks import tls as tls_check
from .dnsutil import DnsInfo, Resolver
from .errors import PolicyDenied
from .models import Observation, Severity, Signal
from .net import Capture, FetchResult, GatedSession, PassiveClient
from .policy import Policy
from .recon.crtsh import discover_subdomains
from .recon.wayback import discover_urls
from .report import build_report, write_reports
from .scope import check_host, check_target, check_url
from .store import Store
from .util import dedupe, ensure_dir, host_of, normalize_host, slugify, truncate, utc_now_iso

_STATIC_SUFFIXES = (
    ".js", ".mjs", ".css", ".map", ".png", ".jpg", ".jpeg", ".gif", ".svg", ".webp",
    ".ico", ".woff", ".woff2", ".ttf", ".eot", ".mp4", ".webm", ".pdf", ".zip",
    ".tar", ".gz", ".exe", ".dmg",
)
_INTERESTING_WEIGHTS = {
    "admin": 10, "administrator": 10, "internal": 9, "debug": 9, "actuator": 9,
    "jenkins": 8, "gitlab": 8, "jira": 8, "confluence": 7, "grafana": 8,
    "kibana": 8, "prometheus": 7, "staging": 7, "stage": 6, "dev": 6,
    "test": 5, "qa": 5, "uat": 5, "preprod": 6, "beta": 5, "old": 6,
    "legacy": 6, "api": 5, "graphql": 5, "rest": 4, "upload": 5,
    "files": 4, "auth": 4, "sso": 4, "oauth": 4, "backup": 7, "vpn": 6,
    "portal": 4, "billing": 5, "payment": 5,
}


def _wrap_columns(table: Table) -> Table:
    for column in table.columns:
        if not getattr(column, "no_wrap", False):
            column.overflow = "fold"
    return table


@dataclass
class HuntOptions:
    dry_run: bool = False
    passive_only: bool = False
    no_wayback: bool = False
    max_hosts: int | None = None
    max_requests: int | None = None
    targets: tuple[str, ...] = ()
    quiet: bool = False


@dataclass
class AssetState:
    host: str
    sources: set[str] = field(default_factory=set)
    priority: int = 0
    score: int = 0
    ips: tuple[str, ...] = ()
    cname_chain: tuple[str, ...] = ()
    dns_error: str | None = None
    target_error: str | None = None
    wildcard: bool = False
    in_scope: bool = True
    preferred_url: str = ""
    scheme: str = ""
    url: str = ""
    status: int | None = None
    title: str = ""
    server: str = ""
    tech: list[str] = field(default_factory=list)
    endpoints: set[str] = field(default_factory=set)

    @property
    def cname(self) -> str:
        return self.cname_chain[-1] if self.cname_chain else ""

    def as_store_dict(self) -> dict[str, Any]:
        return {
            "host": self.host,
            "source": ",".join(sorted(self.sources)),
            "ips": list(self.ips),
            "cname": self.cname,
            "cname_chain": list(self.cname_chain),
            "scheme": self.scheme,
            "url": self.url,
            "http_status": self.status,
            "title": self.title,
            "server": self.server,
            "tech": self.tech,
            "in_scope": self.in_scope,
            "wildcard": self.wildcard,
        }


class Hunter:
    def __init__(
        self,
        policy: Policy,
        *,
        data_dir: str | Path = ".bughunter",
        reports_dir: str | Path = "reports",
        options: HuntOptions | None = None,
        console: Console | None = None,
    ):
        self.policy = policy
        self.data_dir = Path(data_dir).expanduser()
        self.reports_dir = Path(reports_dir).expanduser()
        self.options = options or HuntOptions()
        self.console = console or Console(highlight=False, soft_wrap=True)
        self.run_id = ""
        self.store: Store | None = None
        self.audit: AuditLog | None = None
        self.session: GatedSession | None = None
        self.passive: PassiveClient | None = None
        self.resolver = Resolver(timeout=policy.rules.request_timeout_seconds / 2)
        self.engine: HypothesisEngine | None = None
        self.assets: dict[str, AssetState] = {}
        self.seed_hosts: set[str] = set()
        self.archive_urls: dict[str, list[str]] = {}
        self.wildcard_bases: dict[str, DnsInfo] = {}
        self.seen_js: set[str] = set()
        self.seen_pages: set[str] = set()
        self.passive_log: list[dict[str, Any]] = []
        self.notes: list[str] = []
        self.ignored_out_of_scope = 0
        self.dropped_over_cap = 0
        self.active_checked = 0
        self.deep_checked = 0
        self.exposed_checked = 0
        self.failure = ""
        self.report_data: dict[str, Any] | None = None
        self._host_cap = min(
            policy.rules.max_hosts,
            self.options.max_hosts if self.options.max_hosts is not None else policy.rules.max_hosts,
        )
        self._request_cap = min(
            policy.rules.max_total_requests,
            self.options.max_requests if self.options.max_requests is not None else policy.rules.max_total_requests,
        )

    # --------------------------------------------------------------- entry
    def run(self) -> dict[str, Any]:
        self._validate_targets()
        plan = self._build_plan()
        if self.options.dry_run:
            self._print_plan(plan)
            return plan
        self.policy.assert_authorized()

        ensure_dir(self.data_dir)
        ensure_dir(self.reports_dir)
        self.run_id = self._new_run_id()
        self.store = Store(self.data_dir)
        self.store.create_run(
            self.run_id,
            program=self.policy.program_name,
            policy_path=str(self.policy.path),
            policy_sha256=self.policy.sha256,
            policy_json=self.policy.to_dict(),
            mode=self.policy.mode,
            options={
                "passive_only": self.options.passive_only,
                "no_wayback": self.options.no_wayback,
                "max_hosts": self._host_cap,
                "max_requests": self._request_cap,
                "targets": list(self.options.targets),
            },
        )
        self.audit = AuditLog(
            self.data_dir / "audit" / f"{self.run_id}.jsonl",
            self.run_id,
            {
                "program": self.policy.program_name,
                "mode": self.policy.mode,
                "policy_sha256": self.policy.sha256,
                "authorized_by": self.policy.authorization.authorized_by,
                "tool_version": __version__,
            },
        )
        self.session = GatedSession(
            self.policy,
            self.store,
            self.audit,
            self.run_id,
            resolver=self.resolver,
            stop_file=self.data_dir / "STOP",
            max_total_requests=self._request_cap,
        )
        self.engine = HypothesisEngine(self.store, self.run_id)
        self.passive = PassiveClient(
            audit=self.audit,
            cache_dir=self.data_dir / "cache",
            user_agent=f"Bughunter/{__version__} (+authorized bug bounty testing; contact: {self.policy.contact})",
        )
        status = "completed"
        try:
            self._print_header()
            self._seed_assets()
            self._passive_phase()
            self._resolve_assets()
            self._active_phase()
        except KeyboardInterrupt:
            status = "interrupted"
            self.failure = "interrupted by user"
            self.notes.append("The run was interrupted; the report contains partial results.")
            if not self.options.quiet:
                self.console.print("[yellow]Interrupted. Writing partial report...[/yellow]")
        except Exception as exc:  # keep partial results and a readable report
            status = "failed"
            self.failure = f"{type(exc).__name__}: {exc}"
            self.notes.append(f"Unexpected failure: {self.failure}")
            if not self.options.quiet:
                self.console.print_exception()
        finally:
            try:
                self._finalize(status)
            finally:
                self._close()
        if self.report_data is not None:
            return self.report_data
        return {
            "schema": "bughunter.run/1",
            "run": {"id": self.run_id, "status": status},
            "error": self.failure or "report not available",
            "plan": plan,
        }

    def _close(self) -> None:
        if self.session:
            self.session.close()
        if self.passive:
            self.passive.close()
        if self.audit:
            self.audit.close()
        if self.store:
            self.store.close()

    def _new_run_id(self) -> str:
        stamp = datetime.now(timezone.utc).strftime("%Y%m%d-%H%M%S")
        return f"{stamp}-{slugify(self.policy.program_name)}-{secrets.token_hex(2)}"

    def _validate_targets(self) -> None:
        for target in self.options.targets:
            decision = check_target(self.policy, target)
            if not decision.allowed:
                raise PolicyDenied(f"target {target!r} is not permitted by policy: {decision.reason}", host=decision.host)

    # -------------------------------------------------------------- public
    def _phase(self, title: str) -> None:
        if not self.options.quiet:
            self.console.rule(f"[bold cyan]{title}[/bold cyan]")
        if self.audit:
            self.audit.record({"event": "phase", "phase": title})

    def _print_header(self) -> None:
        if self.options.quiet:
            return
        table = Table(title=f"Bughunter {__version__} - {self.policy.program_name}", show_header=False, box=None)
        table.add_column("field", style="dim", no_wrap=True)
        table.add_column("value")
        for key, value in self.policy.summary_rows():
            table.add_row(key, value)
        self.console.print(_wrap_columns(table))
        for warning in self.policy.warnings:
            self.console.print(f"[yellow]warning:[/yellow] {warning}")
        self.console.print(
            f"[dim]Run {self.run_id} | cap {self._request_cap} requests | "
            f"kill switch: {self.data_dir / 'STOP'}[/dim]\n"
        )

    def _build_plan(self) -> dict[str, Any]:
        active = self.policy.mode == "safe-active" and self.policy.rules.active_checks.enabled and not self.options.passive_only
        per_host = 1
        if active:
            per_host += 1 + self.policy.rules.max_pages_per_host + self.policy.rules.max_js_files_per_host
            if self.policy.rules.active_checks.exposed_files:
                per_host += self.policy.rules.max_paths_per_host
            if self.policy.rules.active_checks.cors:
                per_host += 6
            per_host += 1
        estimated = min(self._request_cap, max(1, self._host_cap) * per_host) if active else 0
        steps = [
            ("1. Intake", "Load and validate the policy, authorization, scope, exclusions, and limits."),
            ("2. Passive intake", "Certificate transparency and Wayback URL mining. These queries go to public sources, never to the target."),
            ("3. Surface map", "Resolve DNS, detect wildcard DNS, rank interesting names, and flag dangling CNAMEs."),
            ("4. Signal extraction", "Fetch a small number of pages and same-scope JavaScript files; extract endpoints, source maps, cloud references, and secrets (redacted)."),
            ("5. Safe validation", "Check headers/cookies/TLS, CORS reflection, exposed-file signatures, GraphQL introspection (opt-in), and takeover fingerprints."),
            ("6. Triage", "Dedupe, score, separate confirmed findings from leads, and write Markdown + JSON reports with an audit trail."),
        ]
        if not active:
            steps = steps[:3] + [
                ("4. Passive analysis", "Mine archived parameters and paths; do not send any packets to the target."),
                ("5. Triage", "Rank leads and write the report. Active checks are disabled by policy."),
            ]
        return {
            "program": self.policy.program_name,
            "run_id": None,
            "mode": self.policy.mode,
            "active": active,
            "targets": list(self.options.targets) or list(self.policy.scope.domains),
            "host_cap": self._host_cap,
            "request_cap": self._request_cap,
            "estimated_target_requests": estimated,
            "steps": steps,
            "warnings": list(self.policy.warnings),
            "authorized": self.policy.authorization.confirmed,
        }

    def _print_plan(self, plan: dict[str, Any]) -> None:
        self.console.print(
            Panel.fit(
                f"[bold]{plan['program']}[/bold]\n"
                f"Mode: {plan['mode']} | host cap: {plan['host_cap']} | request cap: {plan['request_cap']}\n"
                f"Estimated target requests: {plan['estimated_target_requests'] or 'none (passive)'}",
                title="Hunt plan (dry run - no network)",
            )
        )
        table = Table(show_header=False, box=None)
        table.add_column("step", style="bold cyan", no_wrap=True)
        table.add_column("detail")
        for title, detail in plan["steps"]:
            table.add_row(title, detail)
        self.console.print(_wrap_columns(table))
        for warning in plan["warnings"]:
            self.console.print(f"[yellow]warning:[/yellow] {warning}")
        if not plan.get("authorized"):
            self.console.print(
                "[yellow]Authorization is not confirmed.[/yellow] This dry run is safe, but a real "
                "hunt will refuse to run until authorization.confirmed is true."
            )
        self.console.print("\n[dim]No requests were made. Remove --dry-run to execute.[/dim]")

    # --------------------------------------------------------------- assets
    def _base_for(self, host: str) -> str:
        for base in sorted(self.policy.discovery_domains, key=len, reverse=True):
            if host == base or host.endswith("." + base):
                return base
        return ""

    def _add_asset(self, host: str, source: str, *, preferred_url: str = "", explicit: bool = False) -> None:
        host = normalize_host(host)
        if not host:
            return
        decision = check_host(self.policy, host, check_port=False)
        if not decision.allowed:
            self.ignored_out_of_scope += 1
            return
        asset = self.assets.get(host)
        if asset is None:
            asset = AssetState(host=host)
            self.assets[host] = asset
        asset.sources.add(source)
        if explicit:
            asset.priority = max(asset.priority, 100)
            self.seed_hosts.add(host)
        if preferred_url:
            asset.preferred_url = preferred_url

    def _seed_assets(self) -> None:
        for entry in self.policy.scope.domains:
            if entry.startswith("*."):
                continue
            self._add_asset(entry[2:] if entry.startswith("*.") else entry, "policy", explicit=True)
        for target in self.options.targets:
            if "://" in target:
                host = normalize_host(urlsplit(target).hostname or "")
                self._add_asset(host, "cli", preferred_url=target, explicit=True)
            else:
                self._add_asset(target, "cli", explicit=True)
        self._observe("scope", self.policy.program_name, "seeded_hosts", sorted(self.seed_hosts), source="policy")

    def _name_score(self, host: str) -> int:
        label = host
        base = self._base_for(host)
        if base and host.endswith("." + base):
            label = host[: -(len(base) + 1)]
        tokens = [token for token in re.split(r"[-._]", label.lower()) if token]
        return sum(_INTERESTING_WEIGHTS.get(token, 0) for token in tokens)

    # -------------------------------------------------------------- passive
    def _passive_phase(self) -> None:
        self._phase("Passive intake")
        for domain in self.policy.discovery_domains:
            if self.policy.rules.passive_sources.crtsh:
                if not self.options.quiet:
                    self.console.print(f"[cyan]crt.sh[/cyan] {domain} ...")
                hosts, error = discover_subdomains(
                    self.passive, domain, limit=self.policy.rules.passive_sources.max_crtsh_results
                )
                for host in hosts:
                    self._add_asset(host, "crt.sh")
                self.passive_log.append(
                    {"source": "crt.sh", "domain": domain, "hosts": len(hosts), "error": error}
                )
                self._observe(
                    "passive_source",
                    domain,
                    "crtsh",
                    {"hosts": len(hosts), "error": error},
                    source="crt.sh",
                )
                if error:
                    self.notes.append(f"crt.sh error for {domain}: {error}")
                if not self.options.quiet and hosts:
                    self.console.print(f"  [dim]{len(hosts)} hostname(s)[/dim]")
            if self.policy.rules.passive_sources.wayback and not self.options.no_wayback:
                if not self.options.quiet:
                    self.console.print(f"[cyan]wayback[/cyan] {domain} ...")
                urls, error = discover_urls(
                    self.passive, domain, limit=self.policy.rules.passive_sources.max_wayback_urls
                )
                in_scope = 0
                for url in urls:
                    try:
                        parts = urlsplit(url)
                    except ValueError:
                        continue
                    if parts.scheme not in {"http", "https"}:
                        continue
                    host = normalize_host(parts.hostname or "")
                    if not host or not check_host(self.policy, host, check_port=False).allowed:
                        self.ignored_out_of_scope += 1
                        continue
                    in_scope += 1
                    self._add_asset(host, "wayback")
                    bucket = self.archive_urls.setdefault(host, [])
                    if len(bucket) < 1000:
                        bucket.append(url)
                self.passive_log.append(
                    {"source": "wayback", "domain": domain, "urls": len(urls), "in_scope": in_scope, "error": error}
                )
                self._observe(
                    "passive_source",
                    domain,
                    "wayback",
                    {"urls": len(urls), "in_scope": in_scope, "error": error},
                    source="wayback",
                )
                if error:
                    self.notes.append(f"Wayback error for {domain}: {error}")
                if not self.options.quiet and urls:
                    self.console.print(f"  [dim]{in_scope} in-scope URL(s)[/dim]")
        if not self.options.quiet:
            self.console.print(
                f"[dim]{len(self.assets)} unique host(s) discovered; "
                f"{self.ignored_out_of_scope} out-of-scope entries ignored.[/dim]\n"
            )

    def _resolve_assets(self) -> None:
        self._phase("Surface map")
        for base in self.policy.discovery_domains:
            info = self.resolver.wildcard_probe(base)
            if info is not None:
                self.wildcard_bases[base] = info
                self._observe(
                    "dns_wildcard",
                    base,
                    "wildcard",
                    {"ips": list(info.ips), "cname_chain": list(info.cname_chain)},
                    source="dns",
                )
                if not self.options.quiet:
                    self.console.print(f"[yellow]wildcard DNS[/yellow] {base} -> {', '.join(info.ips) or info.cname}")
        ordered = sorted(
            self.assets.values(),
            key=lambda item: (-item.priority, -self._name_score(item.host), item.host),
        )
        kept = ordered[: self._host_cap]
        self.dropped_over_cap = max(0, len(ordered) - len(kept))
        self.assets = {asset.host: asset for asset in kept}
        for index, asset in enumerate(kept, 1):
            info = self.resolver.resolve(asset.host)
            asset.ips = info.ips
            asset.cname_chain = info.cname_chain
            asset.dns_error = info.error
            asset.target_error = info.target_error
            base = self._base_for(asset.host)
            asset.wildcard = bool(base and base in self.wildcard_bases and asset.host not in self.seed_hosts)
            asset.score = self._name_score(asset.host) + (2 if info.ips else 0) + (1 if info.cname_chain else 0)
            if self.store:
                self.store.upsert_asset(self.run_id, asset.as_store_dict())
            self._observe(
                "dns",
                asset.host,
                "resolve",
                {
                    "ips": list(info.ips),
                    "cname_chain": list(info.cname_chain),
                    "error": info.error,
                    "target_error": info.target_error,
                    "wildcard": asset.wildcard,
                },
                source="dns",
            )
            if not self.options.quiet and (index % 10 == 0 or index == len(kept)):
                self.console.print(f"  [dim]resolved {index}/{len(kept)}[/dim]")
            signal = subdomain_signal(asset.host, self.policy.discovery_domains, wildcard=asset.wildcard)
            if signal:
                self.engine.emit(signal)
            if (info.error or info.target_error) and info.cname_chain and not asset.wildcard:
                cname_signal = dangling_cname_signal(asset.host, info.cname_chain, info.target_error or info.error)
                if cname_signal:
                    self.engine.emit(cname_signal)
            self._archive_intel(asset)
        if self.dropped_over_cap:
            self.notes.append(f"{self.dropped_over_cap} discovered host(s) were dropped at the host cap ({self._host_cap}).")
        if not self.options.quiet:
            resolved = sum(1 for asset in kept if asset.ips)
            self.console.print(
                f"[dim]{len(kept)} host(s) kept | {resolved} resolved | "
                f"{len(self.wildcard_bases)} wildcard base(s)[/dim]\n"
            )

    def _archive_intel(self, asset: AssetState) -> None:
        urls = self.archive_urls.get(asset.host, [])
        if not urls:
            return
        param = archive_param_signal(asset.host, urls)
        if param:
            self.engine.emit(param)
        paths = archive_path_signal(asset.host, urls)
        if paths:
            self.engine.emit(paths)
        added = 0
        for url in urls:
            try:
                path = urlsplit(url).path or "/"
            except ValueError:
                continue
            if not interesting_path(path):
                continue
            endpoint = self._clean_endpoint(url)
            if endpoint and check_url(self.policy, endpoint).allowed:
                asset.endpoints.add(endpoint)
                added += 1
                if added >= 30:
                    break
        self._observe("archive", asset.host, "urls", {"count": len(urls), "interesting_endpoints": added}, source="wayback")

    # --------------------------------------------------------------- active
    def _active_phase(self) -> None:
        if self.policy.mode != "safe-active" or not self.policy.rules.active_checks.enabled:
            self.notes.append("Active target probing skipped: policy mode is passive or active_checks is disabled.")
            return
        if self.options.passive_only:
            self.notes.append("Active target probing skipped by --passive.")
            return
        self._phase("Active surface mapping and safe validation")
        hosts = sorted(
            [asset for asset in self.assets.values() if asset.in_scope],
            key=lambda item: (-item.priority, -item.score, item.host),
        )
        deep_limit = min(self.policy.rules.max_hosts_for_deep_checks, len(hosts))
        exposed_limit = min(self.policy.rules.max_hosts_for_exposed_checks, len(hosts))
        total = len(hosts)
        for index, asset in enumerate(hosts):
            if self.session.budget_exhausted:
                self.notes.append("Request budget exhausted before all hosts were checked.")
                break
            if self.session.stop_file and self.session.stop_file.exists():
                self.notes.append("Kill switch STOP file detected; active phase stopped.")
                break
            if not self.options.quiet:
                self.console.print(
                    f"[bold]({index + 1}/{total})[/bold] {asset.host} "
                    f"[dim]{'deep' if index < deep_limit else 'root-only'}[/dim]"
                )
            try:
                self._probe_asset(asset, deep=index < deep_limit, exposed=index < exposed_limit)
                self.active_checked += 1
            except PolicyDenied as exc:
                self._observe("policy_denied", asset.host, "active", {"reason": exc.reason}, source="gate")
                if self.session.budget_exhausted:
                    self.notes.append("Request budget exhausted during active checks.")
                    break
            except Exception as exc:
                self._observe(
                    "error",
                    asset.host,
                    "active",
                    {"error": f"{type(exc).__name__}: {exc}"},
                    source="orchestrator",
                    detail=traceback.format_exc(),
                )
                if not self.options.quiet:
                    self.console.print(f"  [yellow]host error: {type(exc).__name__}: {exc}[/yellow]")
        if not self.options.quiet:
            self.console.print("")

    def _probe_root(self, asset: AssetState) -> FetchResult | None:
        candidates: list[str] = []
        if asset.preferred_url:
            candidates.append(asset.preferred_url)
        ports = self.policy.rules.allowed_ports
        if 443 in ports:
            candidates.append(f"https://{asset.host}/")
        if 80 in ports:
            candidates.append(f"http://{asset.host}/")
        extras = [port for port in ports if port not in (80, 443)][:2]
        for port in extras:
            candidates.append(f"https://{asset.host}:{port}/")
            candidates.append(f"http://{asset.host}:{port}/")
        last: FetchResult | None = None
        for url in dedupe(candidates):
            try:
                result = self.session.request(
                    "GET",
                    url,
                    purpose="root",
                    capture=Capture.TEXT,
                    max_bytes=self.policy.rules.max_body_bytes,
                    follow_redirects=True,
                )
            except PolicyDenied:
                raise
            last = result
            if result.blocked:
                return result
            if result.error:
                continue
            return result
        return last

    def _probe_asset(self, asset: AssetState, *, deep: bool, exposed: bool) -> None:
        result = self._probe_root(asset)
        if result is None:
            self._observe("http_error", asset.host, "root", {"error": "no candidate URL"}, source="http")
            return
        if result.blocked:
            self._observe(
                "policy_blocked",
                asset.host,
                "root",
                {"reason": result.block_reason, "redirects": result.redirects},
                source="gate",
            )
            return
        if result.error:
            self._observe("http_error", asset.host, "root", {"error": result.error}, source="http")
            self._tls_check(asset)
            return

        asset.url = result.final_url or result.url
        asset.scheme = urlsplit(asset.url).scheme or urlsplit(result.url).scheme
        asset.status = result.status
        cookies = parse_cookies(result.raw_headers)
        page: PageInfo | None = None
        ctype = (result.content_type or "").lower()
        if result.text and ("html" in ctype or "<html" in result.text[:2000].lower()):
            page = analyze_html(asset.url, result.body or b"", result.content_type)
            asset.title = page.title
        fingerprint = fingerprint_response(result.headers, page)
        asset.server = fingerprint.server
        asset.tech = dedupe([*fingerprint.technologies, *cookie_technologies(cookies)])
        self._observe(
            "http_root",
            asset.host,
            asset.url,
            {
                "status": result.status,
                "final_url": asset.url,
                "content_type": result.content_type,
                "bytes": len(result.body or b""),
                "elapsed_ms": result.elapsed_ms,
                "scheme": asset.scheme,
            },
            source="http",
        )
        self._observe(
            "headers",
            asset.host,
            "response",
            self._safe_headers(result.headers),
            source="headers",
        )
        if cookies:
            self._observe(
                "cookies",
                asset.host,
                "set-cookie",
                [
                    {
                        "name": cookie.get("name"),
                        "secure": cookie.get("secure"),
                        "httponly": cookie.get("httponly"),
                        "samesite": cookie.get("samesite"),
                        "prefix": cookie.get("prefix"),
                        "domain": cookie.get("domain"),
                        "path": cookie.get("path"),
                    }
                    for cookie in cookies
                ],
                source="headers",
            )
        active = self.policy.rules.active_checks
        if active.enabled and (active.security_headers or active.cookies):
            signals = header_check.evaluate(asset.url, result.headers, cookies)
            for signal in signals:
                if signal.bug_class == "missing_security_headers" and not active.security_headers:
                    continue
                if signal.bug_class == "cookie_flags" and not active.cookies:
                    continue
                self.engine.emit(signal)

        scripts: list[str] = []
        if page:
            self._observe(
                "page",
                asset.host,
                asset.url,
                {
                    "title": page.title,
                    "generator": page.generator,
                    "has_password_form": page.has_password_form,
                    "script_count": len(page.scripts),
                    "link_count": len(page.links),
                    "form_count": len(page.forms),
                    "comment_count": len(page.comments),
                },
                source="html",
            )
            scripts = self._process_page(asset, result, page)
        elif result.text:
            self._observe("body", asset.host, asset.url, {"content_type": result.content_type}, source="http")
            self._scan_intel_text(asset, result.text, asset.url)

        if deep:
            scripts = self._crawl(asset, page, scripts)
            self._load_js(asset, scripts)
            self._emit_endpoint_signals(asset)
            self._cors_and_graphql_checks(asset)
            self.deep_checked += 1
        if exposed and active.enabled and active.exposed_files:
            self._exposed_check(asset)
            self.exposed_checked += 1
        if active.enabled and active.takeover_fingerprints and asset.cname_chain:
            signal = takeover_check.evaluate(
                asset.host,
                asset.cname_chain,
                result.text,
                status=result.status,
                content_type=result.content_type,
            )
            if signal:
                self.engine.emit(signal)
        self._tls_check(asset)
        if self.store:
            self.store.upsert_asset(self.run_id, asset.as_store_dict())

    def _safe_headers(self, headers: dict[str, str]) -> dict[str, str]:
        wanted = (
            "server", "x-powered-by", "content-type", "via", "vary", "strict-transport-security",
            "content-security-policy", "x-frame-options", "x-content-type-options", "referrer-policy",
            "permissions-policy", "cf-ray", "x-vercel-id", "x-amz-cf-id", "x-azure-ref",
            "x-github-request-id", "x-aspnet-version", "x-runtime",
        )
        return {key: truncate(headers[key], 1200) for key in wanted if headers.get(key)}

    def _process_page(self, asset: AssetState, result: FetchResult, page: PageInfo) -> list[str]:
        for form in page.forms[:10]:
            action = self._clean_endpoint(form.action)
            self._observe(
                "form",
                asset.host,
                action or page.url,
                {
                    "action": action,
                    "method": form.method,
                    "inputs": form.inputs[:40],
                },
                source="html",
            )
            if action and interesting_path(urlsplit(action).path) and check_url(self.policy, action).allowed:
                asset.endpoints.add(action)
        for link in page.links:
            try:
                path = urlsplit(link).path or "/"
            except ValueError:
                continue
            if interesting_path(path):
                clean = self._clean_endpoint(link)
                if clean and check_url(self.policy, clean).allowed:
                    asset.endpoints.add(clean)
        if page.comments:
            self._observe("comments", asset.host, page.url, {"count": len(page.comments)}, source="html")
        if result.text:
            self._scan_intel_text(asset, result.text, page.url)
        return page.scripts

    def _crawl(self, asset: AssetState, page: PageInfo | None, scripts: list[str]) -> list[str]:
        if page is None:
            return scripts
        queue: list[str] = []
        for link in dedupe(page.links):
            if len(queue) >= self.policy.rules.max_pages_per_host:
                break
            try:
                parts = urlsplit(link)
            except ValueError:
                continue
            if parts.scheme not in {"http", "https"}:
                continue
            if normalize_host(parts.hostname or "") != asset.host:
                continue
            if (parts.path or "/").lower().endswith(_STATIC_SUFFIXES):
                continue
            if link in self.seen_pages or link == page.url:
                continue
            decision = check_url(self.policy, link)
            if not decision.allowed:
                continue
            queue.append(link)
        for link in queue:
            if link in self.seen_pages:
                continue
            self.seen_pages.add(link)
            try:
                result = self.session.request(
                    "GET",
                    link,
                    purpose="crawl",
                    capture=Capture.TEXT,
                    max_bytes=self.policy.rules.max_body_bytes,
                    follow_redirects=True,
                )
            except PolicyDenied:
                raise
            if result.blocked or result.error or not result.text or result.status is None:
                continue
            ctype = (result.content_type or "").lower()
            if "html" not in ctype and "<html" not in result.text[:1000].lower():
                continue
            child = analyze_html(result.final_url or link, result.body or b"", result.content_type)
            self._observe(
                "crawl",
                asset.host,
                link,
                {"status": result.status, "title": child.title, "forms": len(child.forms), "links": len(child.links)},
                source="crawl",
            )
            scripts.extend(child.scripts)
        return dedupe(scripts)

    def _load_js(self, asset: AssetState, scripts: list[str]) -> None:
        queue = [
            url for url in dedupe(scripts)
            if urlsplit(url).scheme in {"http", "https"} and check_url(self.policy, url).allowed
        ]
        loaded = 0
        for url in queue:
            if loaded >= self.policy.rules.max_js_files_per_host:
                break
            if url in self.seen_js:
                continue
            self.seen_js.add(url)
            try:
                result = self.session.request(
                    "GET",
                    url,
                    purpose="javascript",
                    capture=Capture.TEXT,
                    max_bytes=min(self.policy.rules.max_body_bytes, 1_500_000),
                    follow_redirects=True,
                )
            except PolicyDenied:
                raise
            if result.blocked or result.error or not result.text:
                continue
            loaded += 1
            intel = self._scan_intel_text(asset, result.text, result.final_url or url)
            self._observe(
                "javascript",
                asset.host,
                url,
                {
                    "status": result.status,
                    "bytes": len(result.body or b""),
                    "endpoints": len(intel.endpoints),
                    "secrets": len(intel.secret_hits),
                    "source_maps": len(intel.source_maps),
                },
                source="js",
            )

    def _scan_intel_text(self, asset: AssetState, text: str, source: str):
        intel = extract_intel(text, source, source=source)
        for hit in intel.secret_hits:
            self.engine.emit(secret_signal(hit, asset.host))
        for reference in intel.cloud_references:
            self.engine.emit(cloud_signal(reference, source))
        for map_url in intel.source_maps:
            if check_url(self.policy, map_url).allowed:
                self.engine.emit(source_map_signal(map_url, source))
        for endpoint in intel.endpoints:
            if check_url(self.policy, endpoint).allowed:
                asset.endpoints.add(self._clean_endpoint(endpoint))
        return intel

    def _emit_endpoint_signals(self, asset: AssetState) -> None:
        candidates = [
            endpoint for endpoint in sorted(asset.endpoints)
            if interesting_path(urlsplit(endpoint).path or "/")
        ]
        for endpoint in candidates[:25]:
            self.engine.emit(endpoint_signal(endpoint, asset.host, found_in=asset.url))

    def _cors_and_graphql_checks(self, asset: AssetState) -> None:
        active = self.policy.rules.active_checks
        same_host = [url for url in asset.endpoints if host_of(url) == asset.host]
        if active.cors and same_host:
            candidates = [asset.url]
            candidates.extend(
                url for url in same_host
                if any(token in url.lower() for token in ("/api", "graphql", "rest", "/v1", "/v2"))
            )
            for signal in cors_check.probe(self.session, dedupe(candidates), max_endpoints=6):
                self.engine.emit(signal)
        if active.graphql_introspection and "POST" in self.policy.rules.allowed_methods:
            graphql_urls = [url for url in same_host if "graphql" in url.lower()]
            for signal in graphql_check.probe(self.session, graphql_urls, max_endpoints=2):
                self.engine.emit(signal)

    def _exposed_check(self, asset: AssetState) -> None:
        parts = urlsplit(asset.url) if asset.url else None
        netloc = parts.netloc if parts and parts.netloc else asset.host
        base = f"{asset.scheme or 'https'}://{netloc}/"
        for signal in exposed_check.check_exposed(
            self.session, base, limit=self.policy.rules.max_paths_per_host
        ):
            self.engine.emit(signal)

    def _tls_check(self, asset: AssetState) -> None:
        active = self.policy.rules.active_checks
        if not active.enabled or not active.tls:
            return
        if not asset.ips:
            return
        parts = urlsplit(asset.url) if asset.url else None
        port = (parts.port if parts and parts.port else 443) if asset.scheme == "https" else 443
        if port not in self.policy.rules.allowed_ports:
            return
        try:
            info = self.session.probe_tls(asset.host, port)
        except PolicyDenied as exc:
            self._observe("policy_denied", asset.host, "tls", {"reason": exc.reason}, source="gate")
            return
        self._observe(
            "tls",
            asset.host,
            "443",
            {
                "protocol": info.protocol,
                "cipher": info.cipher,
                "issuer": info.issuer,
                "not_after": info.not_after,
                "days_left": info.days_left,
                "trusted": info.trusted,
                "error": info.error,
            },
            source="tls",
        )
        for signal in tls_check.evaluate(asset.host, info):
            self.engine.emit(signal)

    def _clean_endpoint(self, url: str) -> str:
        try:
            parts = urlsplit(url)
        except ValueError:
            return ""
        if parts.scheme not in {"http", "https"} or not parts.hostname:
            return ""
        return urlunsplit((parts.scheme, parts.netloc, parts.path or "/", "", ""))

    # ------------------------------------------------------------- finalize
    def _observe(self, kind: str, asset: str, key: str, value: Any, *, source: str = "", detail: str = "") -> None:
        if not self.store:
            return
        self.store.add_observation(self.run_id, Observation(kind=kind, asset=asset, key=key, value=value, source=source, detail=detail))

    def _finalize(self, status: str) -> None:
        if not self.store or not self.audit or not self.session:
            return
        self.notes.append("Archived URLs were treated as intelligence and were not replayed.")
        self.notes.append("Discovered secrets are redacted and were not validated against providers.")
        coverage = {
            "passive_sources": self.passive_log,
            "assets_ignored_out_of_scope": self.ignored_out_of_scope,
            "assets_dropped_over_cap": self.dropped_over_cap,
            "active_hosts_checked": self.active_checked,
            "deep_checked": self.deep_checked,
            "exposed_checked": self.exposed_checked,
            "wildcard_dns": {base: list(info.ips) for base, info in self.wildcard_bases.items()},
            "target_requests": self.session.stats,
            "notes": self.notes,
            "failure": self.failure,
            "audit_path": str(self.data_dir / "audit" / f"{self.run_id}.jsonl"),
            "database_path": str(self.store.path),
            "report_markdown_path": str(self.reports_dir / f"{self.run_id}.md"),
            "report_json_path": str(self.reports_dir / f"{self.run_id}.json"),
        }
        stats = {
            "engine": {"emitted": self.engine.stats.emitted if self.engine else 0, "new": self.engine.stats.new if self.engine else 0},
            "session": self.session.stats,
            "coverage": coverage,
        }
        try:
            data = build_report(self.store, self.run_id)
            data["run"]["status"] = status
            data["run"]["finished_at"] = utc_now_iso()
            data["coverage"] = coverage
            data["summary"]["engine"] = stats["engine"]
            data["summary"]["session"] = stats["session"]
            paths = write_reports(data, self.reports_dir)
            for kind, path in paths["paths"].items():
                self.store.add_artifact(
                    self.run_id,
                    kind=kind,
                    name=Path(path).name,
                    path=path,
                    sha256=paths["hashes"][kind],
                )
            self.report_data = data
        except Exception as exc:
            self.failure = self.failure or f"report generation failed: {exc}"
            self.notes.append(self.failure)
            if not self.options.quiet:
                self.console.print(f"[red]Report generation failed:[/red] {exc}")
        self.store.finish_run(self.run_id, status, stats)
        self.audit.record(
            {
                "event": "run_finished",
                "status": status,
                "stats": stats,
                "failure": self.failure,
                "report": str(self.reports_dir / f"{self.run_id}.md"),
            }
        )
        self._print_summary(status)

    def _print_summary(self, status: str) -> None:
        if not self.report_data:
            return
        summary = self.report_data["summary"]
        if self.options.quiet:
            self.console.print(
                f"{status}: {summary['confirmed']} confirmed, {summary['leads']} leads, "
                f"{summary['requests']} requests"
            )
            return
        table = Table(title=f"Run {self.run_id} - {status}", show_header=True, header_style="bold")
        table.add_column("Severity")
        table.add_column("Asset")
        table.add_column("Finding / lead", max_width=70)
        rows = [
            *[("CONFIRMED", item) for item in self.report_data["findings"][:5]],
            *[("lead", item) for item in self.report_data["leads"][:5]],
        ]
        for label, item in rows:
            table.add_row(
                f"{item['severity'].upper()}" + (" [confirmed]" if label == "CONFIRMED" else ""),
                item["asset"],
                truncate(item["title"], 90),
            )
        if rows:
            self.console.print(_wrap_columns(table))
        self.console.print(
            f"\n[bold]{summary['confirmed']}[/bold] confirmed | [bold]{summary['leads']}[/bold] leads | "
            f"{summary['requests']} requests ({summary['requests_denied']} denied by policy)"
        )
        self.console.print(f"Markdown: [green]{self.reports_dir / (self.run_id + '.md')}[/green]")
        self.console.print(f"JSON:     {self.reports_dir / (self.run_id + '.json')}")
        self.console.print(
            f"Audit:    {self.data_dir / 'audit' / (self.run_id + '.jsonl')}\n"
            "[dim]Leads are hypotheses. Validate manually before reporting. No exploitation was performed.[/dim]"
        )


__all__ = ["Hunter", "HuntOptions", "AssetState"]
