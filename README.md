# bughunter

A policy-gated, passive-first bug bounty assistant. It maps an authorized
program the way a disciplined human hunter would: collect passive
intelligence, rank the surface, fetch a small set of pages and JavaScript
bundles, extract leads, run only low-impact validation checks, and write a
report that separates confirmed findings from hypotheses.

It is **not** an exploit framework, a brute forcer, or a substitute for
reading the program policy. It will refuse to run until you confirm
authorization in the policy file.

## Safety model

- **Authorization gate.** `authorization.confirmed` must be `true` or `hunt`
  exits with an error.
- **Scope and exclusions** are checked on every request, including every
  redirect hop. `example.com` covers the apex and all subdomains.
  `*.example.com` covers subdomains only.
- **Passive-first.** `mode: passive` sends no packets to the target.
  `safe-active` is required before active checks can run, and each check is
  still opt-in under `active_checks`.
- **Hard caps.** Per-host rate limit, total request budget, runtime budget,
  host cap, page/JS/path caps, body size cap, redirect cap.
- **SSRF guard.** Hostnames that resolve to private, loopback, link-local,
  reserved, or multicast addresses are refused unless the policy explicitly
  allows private addresses. IP literals are validated too.
- **robots.txt** is respected by default.
- **Method allowlist.** Only methods listed in the policy are ever sent.
- **Kill switch.** Create the file `.bughunter/STOP` and the next request is
  denied; the active loop stops at the next host.
- **No destructive actions.** No POST bodies with data, no PUT/PATCH/DELETE,
  no credential use, no brute force, no fuzzing, no denial-of-service, no
  bucket interaction, no takeover claiming. Archived URLs are intelligence
  only and are never replayed.
- **Secrets are redacted** in reports. They are never validated against
  providers.
- **Hash-chained audit log** for every request, denial, phase, and report
  hash, in `.bughunter/audit/<run-id>.jsonl`. Verify it with
  `bughunter audit <run-id>`; any edited, deleted, or reordered record breaks
  the chain.

## What it does

Phases of a `hunt`:

1. **Intake** - validate the policy, authorization, scope, exclusions, and
   limits.
2. **Passive intake** - certificate transparency (crt.sh) and Wayback URL
   mining. These queries go to public sources, never to the target.
3. **Surface map** - DNS resolution, wildcard DNS detection, interesting-name
   ranking, dangling-CNAME detection, archived parameter/path mining.
4. **Signal extraction** - root pages, a few same-host links, and same-scope
   JavaScript files. Extracts endpoints, GraphQL endpoints, source maps,
   cloud storage references, and secrets (redacted).
5. **Safe validation** (when policy allows) - security headers, cookie flags,
   TLS protocol/certificate/cipher state, CORS reflection, exposed-file
   signatures, GraphQL introspection, subdomain-takeover fingerprints.
6. **Triage and report** - dedupe, score, upgrade leads to confirmed findings
   only when the evidence supports it, and write Markdown + JSON reports.

Checks are detection-oriented. For example, exposed-file checks read at most
a small range and rely on signatures, CORS checks send one synthetic
`Origin`, GraphQL introspection sends one minimal introspection query, and
takeover checks only match provider fingerprints (they never register or
claim resources).

## Install (Windows)

```powershell
cd D:\django\bughunter
python -m venv .venv
.\.venv\Scripts\python.exe -m pip install --upgrade pip
.\.venv\Scripts\python.exe -m pip install -e ".[dev]"
```

Verify:

```powershell
.\.venv\Scripts\bughunter.exe --version
.\.venv\Scripts\python.exe -m pytest -q
```

## Quick start

```powershell
# 1. Create a policy for the program.
.\.venv\Scripts\bughunter.exe init "Acme Corp" --path policies\acme.yaml
# 2. Edit policies\acme.yaml:
#    - set scope.domains and scope.exclusions
#    - set program.contact, policy_url, authorization.authorized_by
#    - only then set authorization.confirmed: true

# 3. Validate and check scope.
.\.venv\Scripts\bughunter.exe validate policies\acme.yaml
.\.venv\Scripts\bughunter.exe scope policies\acme.yaml api.acme.com admin.acme.com

# 4. Dry run: shows exactly what will happen, makes no requests.
.\.venv\Scripts\bughunter.exe hunt policies\acme.yaml --dry-run

# 5. Passive run (still no target packets if mode is passive).
.\.venv\Scripts\bughunter.exe hunt policies\acme.yaml

# 6. Enable safe-active in the policy, then run the low-impact checks.
#    To force passive for one run:
.\.venv\Scripts\bughunter.exe hunt policies\acme.yaml --passive
```

Useful flags:

| Flag | Meaning |
| --- | --- |
| `--dry-run` | Print the plan and exit; no network, no state directory. |
| `--passive` | Force passive mode even if the policy allows active checks. |
| `--no-wayback` | Skip the Wayback passive source. |
| `--max-hosts N` | Lower the policy host cap for this run. |
| `--max-requests N` | Lower the policy total request budget for this run. |
| `--target HOST` | Limit this run to one or more in-scope hosts/URLs (repeatable). |
| `--quiet` | Minimal console output. |

Inspect runs:

```powershell
.\.venv\Scripts\bughunter.exe runs
.\.venv\Scripts\bughunter.exe show <run-id>
.\.venv\Scripts\bughunter.exe audit <run-id>
.\.venv\Scripts\bughunter.exe report <run-id> --format md
.\.venv\Scripts\bughunter.exe report <run-id> --format json --stdout
```

## Policy reference

The YAML policy is the source of truth. Unknown keys produce a warning so
typos are visible. Key settings:

| Key | Default | Notes |
| --- | --- | --- |
| `scope.domains` | required | Bare domain = apex + subdomains; `*.domain` = subdomains only. |
| `scope.exclusions` | `[]` | Host patterns that are always denied. |
| `scope.ip_ranges` | `[]` | Optional CIDR ranges; private ranges are still blocked unless allowed. |
| `rules.mode` | `passive` | `passive` or `safe-active`. Active checks require `safe-active`. |
| `rules.allowed_methods` | `[GET, HEAD]` | Hard method allowlist. Do not add writes unless the program explicitly permits them. |
| `rules.allowed_ports` | `[80, 443]` | Any other port is denied. |
| `rules.max_requests_per_host_per_minute` | `20` | Per-host rate limit. |
| `rules.max_total_requests` | `400` | Total target request budget for the run. |
| `rules.max_runtime_seconds` | `1200` | Wall-clock budget. |
| `rules.max_hosts` | `150` | Host cap after ranking. |
| `rules.max_pages_per_host` | `3` | Extra same-host HTML pages to fetch for deep hosts. |
| `rules.max_js_files_per_host` | `15` | JavaScript files to analyze for deep hosts. |
| `rules.max_paths_per_host` | `12` | Exposed-file paths checked for the top hosts. |
| `rules.max_hosts_for_exposed_checks` | `8` | Only this many top hosts get exposed-file checks. |
| `rules.max_hosts_for_deep_checks` | `15` | Only this many top hosts get crawl/JS/CORS/GraphQL checks. |
| `rules.respect_robots_txt` | `true` | Keep this on unless the program explicitly allows otherwise. |
| `rules.allow_private_addresses` | `false` | Keep this off for real programs. Needed only for local demos/labs. |
| `rules.forbidden_paths` | destructive/logout patterns | Glob patterns denied even if in scope. |
| `rules.passive_sources` | crt.sh + Wayback | Passive source switches and result caps. |
| `rules.active_checks.enabled` | `false` | Master switch for active checks. |
| `rules.active_checks.*` | see template | Per-check switches: headers, cookies, CORS, exposed files, GraphQL introspection, takeover fingerprints, TLS. |

## Findings vs leads

- A **confirmed finding** has direct, low-impact evidence (for example a
  matching exposed-file signature, a reflected CORS origin with credentials,
  or a missing cookie flag observed in a response).
- A **lead** is a hypothesis that needs a human: interesting subdomain
  naming, archived parameters that look like IDOR/open-redirect candidates,
  a dangling CNAME, a JavaScript endpoint, a source map, or a cloud storage
  reference.
- Reports list what was **not tested** and include coverage/limitations, the
  policy SHA-256, request statistics, and the audit-trail paths.

Outputs:

- `reports/<run-id>.md` - human-readable report.
- `reports/<run-id>.json` - machine-readable report (`bughunter.report/1`).
- `.bughunter/bughunter.db` - SQLite run/asset/observation/hypothesis/request/artifact store.
- `.bughunter/audit/<run-id>.jsonl` - hash-chained audit log.
- `.bughunter/cache/` - passive source cache.

## Local end-to-end demo

`examples/local_demo/` contains a deliberately vulnerable local HTTP server
and a policy scoped to `localtest.me` with `allow_private_addresses: true`.
This is for learning and for verifying that the pipeline works on your
machine. It never touches the internet except DNS for `localtest.me`.

```powershell
# Terminal 1
.\.venv\Scripts\python.exe examples\local_demo\server.py

# Terminal 2
.\.venv\Scripts\bughunter.exe hunt examples\local_demo\policy.yaml `
    --data-dir .demo-state --reports-dir .demo-reports
```

The demo intentionally exposes Git metadata, an `.env` file, a backup
archive, reflective CORS, GraphQL introspection, missing security headers,
a weak session cookie, a fake AWS key in JavaScript, and a source map
reference.

## Architecture

```
bughunter/
  cli.py            argparse commands: init, validate, scope, hunt, runs, show, audit, report
  policy.py         YAML schema, defaults, validation, authorization gate
  scope.py          scope/exclusion/forbidden-path decisions
  net.py            GatedSession (every guardrail) and PassiveClient (allowlisted)
  dnsutil.py        resolver, CNAME chains, wildcard probes
  store.py          SQLite state
  audit.py          hash-chained JSONL audit log
  models.py         Observation / Signal / Hypothesis, severity and confidence
  recon/            crt.sh, Wayback, takeover provider fingerprints
  analyze/          HTML/tech fingerprints, secret + endpoint intel, scoring engine
  checks/           headers, cookies, exposed files, CORS, GraphQL, TLS, takeover
  orchestrator.py   phase engine, ranking, budgets, reporting
  report.py         Markdown + JSON report generation with redaction
```

## Development

```powershell
.\.venv\Scripts\python.exe -m pytest -q
.\.venv\Scripts\python.exe -m compileall -q bughunter
```

Tests cover scope semantics, policy validation, the request gate (scope,
method, DNS/private-IP, robots, budget, redirects), secret redaction,
hypothesis dedupe/upgrade, audit-chain verification, report generation, and
each active check with fake transports. No test contacts the internet.

### Extending

- Add a passive source in `bughunter/recon/` and call it from
  `Hunter._passive_phase`. Remember to allowlist its host in
  `net.PASSIVE_ALLOWLIST` and add a policy switch.
- Add a check in `bughunter/checks/` returning `Signal` objects, then wire
  it into `Hunter._probe_asset` behind a policy switch. Keep it
  detection-oriented and budget-aware.
- Add takeover providers in `bughunter/recon/takeover.py`; signatures are
  matched against the root page text.

## Limitations

- It is not a scanner. It does not test authentication, authorization,
  business logic, injections, or multi-step flows.
- It does not brute force, fuzz, or guess content.
- It does not verify secrets or access data.
- Passive sources can be stale, incomplete, or rate-limited.
- Wildcard DNS can make every subdomain look alive; the report says so.
- TLS checks record what the default verifier sees; they are not a deep
  protocol audit.
- Always validate leads manually and follow the program's rules for
  evidence, rate, and disclosure.

## Legal

Use this tool only against assets you own or are explicitly authorized to
test, within the program's published policy. You are responsible for every
request it makes. Keep the kill switch handy: create `.bughunter/STOP`.
