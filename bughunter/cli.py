from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path
from typing import Any

from rich.console import Console
from rich.panel import Panel
from rich.table import Table

from . import __version__
from .audit import AuditLog
from .errors import BughunterError
from .orchestrator import Hunter, HuntOptions
from .policy import Policy, load_policy
from .report import build_report, render_markdown, write_reports
from .scope import check_target
from .store import Store
from .util import slugify, truncate

_TEMPLATE = """# Bughunter policy for {name}
# Fill in the scope and authorization details, then run:
#   bughunter validate <this-file>.yaml
#   bughunter hunt <this-file>.yaml --dry-run
#   bughunter hunt <this-file>.yaml
#
# Set authorization.confirmed to true ONLY after you have verified that you are
# permitted to test every asset in scope. Bughunter refuses to run otherwise.

program:
  name: {name_yaml}
  platform: ""
  policy_url: ""
  contact: "security@example.com"
  authorization:
    confirmed: false
    authorized_by: ""
    date: ""
    policy_url: ""

scope:
  # A bare domain covers the apex and all subdomains.
  # "*.example.com" covers subdomains only (not the apex).
  domains:
    - example.com
  exclusions:
    - "status.example.com"
  ip_ranges: []

rules:
  # passive      = public passive sources only, no packets to the target
  # safe-active  = allow the low-impact checks below, under strict limits
  mode: passive
  allowed_methods: [GET, HEAD]
  allowed_ports: [80, 443]
  max_requests_per_host_per_minute: 20
  max_total_requests: 400
  max_runtime_seconds: 1200
  request_timeout_seconds: 15
  max_hosts: 150
  max_pages_per_host: 3
  max_js_files_per_host: 15
  max_paths_per_host: 12
  max_hosts_for_exposed_checks: 8
  max_hosts_for_deep_checks: 15
  max_body_bytes: 2000000
  max_redirects: 4
  respect_robots_txt: true
  allow_private_addresses: false
  allow_out_of_scope_redirects: false
  forbidden_paths:
    - "/logout*"
    - "/signout*"
    - "/delete*"
    - "/remove*"
    - "/admin/delete*"
    - "/api/*/delete*"
    - "/checkout*"
    - "/purchase*"
    - "/unsubscribe*"

  passive_sources:
    crtsh: true
    wayback: true
    max_crtsh_results: 1000
    max_wayback_urls: 2000

  active_checks:
    enabled: false
    security_headers: true
    cookies: true
    cors: true
    exposed_files: true
    graphql_introspection: false
    takeover_fingerprints: true
    tls: true

metadata:
  owner: ""
  notes: "No denial-of-service, brute force, or destructive testing."
"""


def _console() -> Console:
    return Console(highlight=False, soft_wrap=True)


def _wrap_columns(table: Table) -> Table:
    for column in table.columns:
        if not getattr(column, "no_wrap", False):
            column.overflow = "fold"
    return table


def _policy_table(policy: Policy) -> Table:
    table = Table(title=f"Policy - {policy.program_name}", show_header=False, box=None)
    table.add_column("field", style="dim", no_wrap=True)
    table.add_column("value")
    for key, value in policy.summary_rows():
        table.add_row(key, value)
    return _wrap_columns(table)


def cmd_init(args: argparse.Namespace) -> int:
    console = _console()
    slug = slugify(args.name)
    path = Path(args.path) if args.path else Path("policies") / f"{slug}.yaml"
    if path.exists() and not args.force:
        console.print(f"[red]Refusing to overwrite existing file:[/red] {path} (use --force)")
        return 2
    path.parent.mkdir(parents=True, exist_ok=True)
    content = _TEMPLATE.format(
        name=args.name,
        name_yaml=json.dumps(args.name),
        slug=slug,
    )
    path.write_text(content, encoding="utf-8")
    console.print(Panel.fit(f"Created [green]{path}[/green]", title="bughunter init"))
    console.print(
        "\n[bold]Next steps[/bold]\n"
        f"1. Edit {path}: set scope, contact, and authorization.authorized_by.\n"
        "2. Verify the program policy yourself, then set authorization.confirmed: true.\n"
        f"3. Run [cyan]bughunter validate {path}[/cyan]\n"
        f"4. Run [cyan]bughunter hunt {path} --dry-run[/cyan]\n"
        f"5. Run [cyan]bughunter hunt {path}[/cyan]\n\n"
        "[yellow]Do not set confirmed: true for assets you do not own or have permission to test.[/yellow]"
    )
    return 0


def cmd_validate(args: argparse.Namespace) -> int:
    console = _console()
    policy = load_policy(args.policy)
    console.print(_policy_table(policy))
    if policy.warnings:
        console.print("")
        for warning in policy.warnings:
            console.print(f"[yellow]warning:[/yellow] {warning}")
    if not policy.authorization.confirmed:
        console.print(
            "\n[yellow]Authorization is NOT confirmed.[/yellow] The policy is structurally valid, "
            "but hunt will refuse to run until you set authorization.confirmed: true."
        )
    else:
        console.print("\n[green]Policy valid and authorization confirmed.[/green]")
    console.print(f"[dim]Policy SHA-256: {policy.sha256}[/dim]")
    return 0


def cmd_scope(args: argparse.Namespace) -> int:
    console = _console()
    policy = load_policy(args.policy)
    table = Table(title="Scope check", header_style="bold")
    table.add_column("Target")
    table.add_column("Allowed")
    table.add_column("Reason")
    denied = 0
    for target in args.targets:
        decision = check_target(policy, target)
        if not decision.allowed:
            denied += 1
        table.add_row(
            target,
            "[green]yes[/green]" if decision.allowed else "[red]no[/red]",
            decision.reason,
        )
    console.print(_wrap_columns(table))
    return 0 if denied == 0 else 1


def cmd_hunt(args: argparse.Namespace) -> int:
    console = _console()
    if args.max_hosts is not None and args.max_hosts < 1:
        console.print("[red]--max-hosts must be >= 1[/red]")
        return 2
    if args.max_requests is not None and args.max_requests < 1:
        console.print("[red]--max-requests must be >= 1[/red]")
        return 2
    policy = load_policy(args.policy)
    options = HuntOptions(
        dry_run=args.dry_run,
        passive_only=args.passive,
        no_wayback=args.no_wayback,
        max_hosts=args.max_hosts,
        max_requests=args.max_requests,
        targets=tuple(args.target or ()),
        quiet=args.quiet,
    )
    hunter = Hunter(
        policy,
        data_dir=args.data_dir,
        reports_dir=args.reports_dir,
        options=options,
        console=console,
    )
    result = hunter.run()
    if args.dry_run:
        return 0
    status = (result.get("run") or {}).get("status") if isinstance(result, dict) else None
    if status == "interrupted":
        return 130
    if status == "failed":
        return 1
    return 0


def cmd_runs(args: argparse.Namespace) -> int:
    console = _console()
    store = Store(args.data_dir)
    try:
        runs = store.list_runs(limit=args.limit)
    finally:
        store.close()
    if not runs:
        console.print("No runs yet. Use [cyan]bughunter hunt <policy>[/cyan].")
        return 0
    console.print(f"[bold]Runs[/bold] ({len(runs)})")
    for run in runs:
        console.print(
            f"{run['id']}  [bold]{run['status']}[/bold]  "
            f"{run['confirmed']} confirmed / {run['leads']} leads / {run['requests']} requests  "
            f"[dim]{truncate(run['program'], 40)} ({run['mode']}, started {run['started_at']})[/dim]"
        )
    return 0


def cmd_show(args: argparse.Namespace) -> int:
    console = _console()
    store = Store(args.data_dir)
    try:
        data = build_report(store, args.run_id)
    finally:
        store.close()
    run = data["run"]
    summary = data["summary"]
    console.print(Panel.fit(
        f"[bold]{run['program']}[/bold]\n{run['mode']} | {run['status']} | {run['started_at']}\n"
        f"{summary['confirmed']} confirmed | {summary['leads']} leads | {summary['requests']} requests",
        title=f"Run {run['id']}",
    ))
    table = Table(show_header=True, header_style="bold")
    table.add_column("Status")
    table.add_column("Severity")
    table.add_column("Asset")
    table.add_column("Title", max_width=70)
    for item in [*data["findings"], *data["leads"][:20]]:
        table.add_row(item["status"], item["severity"].upper(), item["asset"], truncate(item["title"], 90))
    if data["findings"] or data["leads"]:
        console.print(_wrap_columns(table))
    console.print(f"\nMarkdown: {data['coverage'].get('report_markdown_path', '-')}")
    return 0


def cmd_audit(args: argparse.Namespace) -> int:
    console = _console()
    path = Path(args.data_dir) / "audit" / f"{args.run_id}.jsonl"
    ok, message = AuditLog.verify(path)
    style = "green" if ok else "red"
    console.print(f"[{style}]{'OK' if ok else 'FAILED'}[/{style}] {path}: {message}")
    return 0 if ok else 1


def cmd_report(args: argparse.Namespace) -> int:
    console = _console()
    store = Store(args.data_dir)
    try:
        data = build_report(store, args.run_id)
    finally:
        store.close()
    if args.stdout:
        if args.format == "json":
            console.print_json(json.dumps(data, default=str))
        else:
            console.print(render_markdown(data))
        return 0
    paths = write_reports(data, args.reports_dir)
    console.print(f"Markdown: [green]{paths['paths']['markdown']}[/green]")
    console.print(f"JSON:     {paths['paths']['json']}")
    return 0


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="bughunter",
        description="Policy-gated, human-like bug bounty assistant. Authorized testing only.",
    )
    parser.add_argument("--version", action="version", version=f"bughunter {__version__}")
    sub = parser.add_subparsers(dest="command", required=True)

    init = sub.add_parser("init", help="create a policy template")
    init.add_argument("name", help="program name")
    init.add_argument("--path", help="policy path (default: policies/<slug>.yaml)")
    init.add_argument("--force", action="store_true", help="overwrite an existing file")
    init.set_defaults(func=cmd_init)

    validate = sub.add_parser("validate", help="validate a policy file")
    validate.add_argument("policy")
    validate.set_defaults(func=cmd_validate)

    scope = sub.add_parser("scope", help="check whether targets are in scope")
    scope.add_argument("policy")
    scope.add_argument("targets", nargs="+", help="hostname or URL")
    scope.set_defaults(func=cmd_scope)

    hunt = sub.add_parser("hunt", help="run the hunter")
    hunt.add_argument("policy")
    hunt.add_argument("--dry-run", action="store_true", help="show the plan without network access")
    hunt.add_argument("--passive", action="store_true", help="force passive mode even if the policy allows active checks")
    hunt.add_argument("--no-wayback", action="store_true", help="skip the Wayback passive source")
    hunt.add_argument("--max-hosts", type=int, help="lower the policy host cap")
    hunt.add_argument("--max-requests", type=int, help="lower the policy request cap")
    hunt.add_argument("--target", action="append", help="limit to specific in-scope hostnames/URLs (repeatable)")
    hunt.add_argument("--quiet", action="store_true", help="minimal console output")
    hunt.add_argument("--data-dir", default=".bughunter", help="state/audit directory (default: .bughunter)")
    hunt.add_argument("--reports-dir", default="reports", help="report directory (default: reports)")
    hunt.set_defaults(func=cmd_hunt)

    runs = sub.add_parser("runs", help="list previous runs")
    runs.add_argument("--limit", type=int, default=20)
    runs.add_argument("--data-dir", default=".bughunter")
    runs.set_defaults(func=cmd_runs)

    show = sub.add_parser("show", help="show a run summary")
    show.add_argument("run_id")
    show.add_argument("--data-dir", default=".bughunter")
    show.set_defaults(func=cmd_show)

    audit = sub.add_parser("audit", help="verify the hash-chained audit log for a run")
    audit.add_argument("run_id")
    audit.add_argument("--data-dir", default=".bughunter")
    audit.set_defaults(func=cmd_audit)

    report = sub.add_parser("report", help="render a report from stored state")
    report.add_argument("run_id")
    report.add_argument("--data-dir", default=".bughunter")
    report.add_argument("--reports-dir", default="reports")
    report.add_argument("--format", choices=("md", "json"), default="md")
    report.add_argument("--stdout", action="store_true", help="print instead of writing files")
    report.set_defaults(func=cmd_report)

    return parser


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    try:
        return int(args.func(args))
    except BughunterError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2
    except KeyError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2
    except KeyboardInterrupt:
        print("interrupted", file=sys.stderr)
        return 130


if __name__ == "__main__":
    raise SystemExit(main())
