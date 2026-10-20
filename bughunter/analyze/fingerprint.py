from __future__ import annotations

import re
from dataclasses import dataclass, field
from html.parser import HTMLParser
from urllib.parse import urljoin

from ..util import decode_body, dedupe, normalize_host, truncate

_SESSION_RE = re.compile(r"(sess|session|auth|token|jwt|sid|remember|login)", re.I)
_NON_SESSION_RE = re.compile(r"(csrf|xsrf|nonce)", re.I)


@dataclass
class FormInfo:
    action: str
    method: str
    inputs: list[dict[str, str]] = field(default_factory=list)


@dataclass
class PageInfo:
    url: str
    title: str = ""
    generator: str = ""
    base_href: str = ""
    meta: dict[str, str] = field(default_factory=dict)
    scripts: list[str] = field(default_factory=list)
    links: list[str] = field(default_factory=list)
    forms: list[FormInfo] = field(default_factory=list)
    comments: list[str] = field(default_factory=list)
    inline_scripts: list[str] = field(default_factory=list)
    has_password_form: bool = False


@dataclass
class Fingerprint:
    server: str = ""
    powered_by: str = ""
    generator: str = ""
    technologies: list[str] = field(default_factory=list)
    cdn: str = ""
    waf: str = ""


class _Parser(HTMLParser):
    def __init__(self) -> None:
        super().__init__(convert_charrefs=True)
        self.title_parts: list[str] = []
        self.in_title = False
        self.in_script = False
        self.current_script: list[str] = []
        self.meta: dict[str, str] = {}
        self.scripts: list[str] = []
        self.links: list[str] = []
        self.forms: list[FormInfo] = []
        self.comments: list[str] = []
        self.inline_scripts: list[str] = []
        self.base_href = ""
        self._current_form: FormInfo | None = None
        self._script_count = 0

    def handle_starttag(self, tag: str, attrs: list[tuple[str, str | None]]) -> None:
        values = {key.lower(): (value or "") for key, value in attrs}
        tag = tag.lower()
        if tag == "title":
            self.in_title = True
        elif tag == "base" and values.get("href"):
            self.base_href = values["href"]
        elif tag == "meta":
            key = values.get("name") or values.get("property") or values.get("http-equiv")
            content = values.get("content", "")
            if key and content and len(self.meta) < 100:
                self.meta[key.lower()] = truncate(content, 500)
        elif tag == "script":
            src = values.get("src", "")
            if src and len(self.scripts) < 300:
                self.scripts.append(src)
            elif self._script_count < 30:
                self.in_script = True
                self.current_script = []
                self._script_count += 1
        elif tag in {"a", "link", "area"}:
            href = values.get("href", "")
            if href and len(self.links) < 500:
                self.links.append(href)
        elif tag == "form":
            method = (values.get("method") or "GET").upper()
            self._current_form = FormInfo(action=values.get("action", ""), method=method)
            if len(self.forms) < 50:
                self.forms.append(self._current_form)
        elif tag in {"input", "textarea", "select"} and self._current_form is not None:
            name = values.get("name", "")
            input_type = values.get("type", tag)
            if len(self._current_form.inputs) < 100:
                if name:
                    self._current_form.inputs.append({"name": name, "type": input_type})
                elif input_type == "password":
                    self._current_form.inputs.append({"name": "(password)", "type": "password"})

    def handle_startendtag(self, tag: str, attrs: list[tuple[str, str | None]]) -> None:
        self.handle_starttag(tag, attrs)

    def handle_endtag(self, tag: str) -> None:
        tag = tag.lower()
        if tag == "title":
            self.in_title = False
        elif tag == "script" and self.in_script:
            text = "".join(self.current_script).strip()
            if text and len(self.inline_scripts) < 30:
                self.inline_scripts.append(truncate(text, 100_000))
            self.in_script = False
            self.current_script = []
        elif tag == "form":
            self._current_form = None

    def handle_data(self, data: str) -> None:
        if self.in_title:
            if sum(len(part) for part in self.title_parts) < 500:
                self.title_parts.append(data)
        elif self.in_script:
            total = sum(len(part) for part in self.current_script)
            if total < 100_000:
                self.current_script.append(data)

    def handle_comment(self, data: str) -> None:
        if len(self.comments) < 30:
            text = " ".join(data.split())
            if text:
                self.comments.append(truncate(text, 500))


def analyze_html(url: str, body: bytes, content_type: str = "") -> PageInfo:
    text = decode_body(body, content_type)
    parser = _Parser()
    try:
        parser.feed(text)
        parser.close()
    except Exception:
        pass
    base = urljoin(url, parser.base_href) if parser.base_href else url
    scripts = dedupe(urljoin(base, src) for src in parser.scripts if src)
    links = dedupe(urljoin(base, href) for href in parser.links if href)
    forms: list[FormInfo] = []
    for form in parser.forms:
        form.action = urljoin(base, form.action) if form.action else url
        forms.append(form)
    generator = parser.meta.get("generator", "")
    return PageInfo(
        url=url,
        title=" ".join("".join(parser.title_parts).split()),
        generator=generator,
        base_href=parser.base_href,
        meta=parser.meta,
        scripts=scripts[:200],
        links=links[:400],
        forms=forms,
        comments=parser.comments,
        inline_scripts=parser.inline_scripts,
        has_password_form=any(
            any(item.get("type") == "password" for item in form.inputs) for form in forms
        ),
    )


def parse_cookies(raw_headers: list[tuple[str, str]]) -> list[dict[str, object]]:
    cookies: list[dict[str, object]] = []
    for key, value in raw_headers:
        if key != "set-cookie":
            continue
        parts = value.split(";")
        if not parts or "=" not in parts[0]:
            continue
        name = parts[0].split("=", 1)[0].strip()
        if not name:
            continue
        attrs: dict[str, str] = {}
        for part in parts[1:]:
            if "=" in part:
                attr_key, attr_value = part.split("=", 1)
                attrs[attr_key.strip().lower()] = attr_value.strip()
            else:
                attrs[part.strip().lower()] = ""
        cookies.append(
            {
                "name": name,
                "secure": "secure" in attrs,
                "httponly": "httponly" in attrs,
                "samesite": attrs.get("samesite", "").lower(),
                "domain": attrs.get("domain", ""),
                "path": attrs.get("path", ""),
                "prefix": "__host-" if name.lower().startswith("__host-") else (
                    "__secure-" if name.lower().startswith("__secure-") else ""
                ),
                "value_length": len(parts[0].split("=", 1)[1]) if "=" in parts[0] else 0,
            }
        )
    return cookies


def is_session_cookie(name: str) -> bool:
    if _NON_SESSION_RE.search(name):
        return False
    return bool(_SESSION_RE.search(name))


def fingerprint_response(headers: dict[str, str], page: PageInfo | None = None) -> Fingerprint:
    server = headers.get("server", "")
    powered_by = headers.get("x-powered-by", "")
    technologies: list[str] = []
    cdn = ""
    waf = ""
    lower = {key.lower(): value for key, value in headers.items()}

    if server:
        technologies.append(f"Server: {server}")
        server_lower = server.lower()
        for token, label in (
            ("nginx", "nginx"),
            ("apache", "Apache"),
            ("iis", "Microsoft IIS"),
            ("cloudflare", "Cloudflare"),
            ("envoy", "Envoy"),
            ("gunicorn", "Gunicorn"),
            ("kestrel", "ASP.NET Core"),
        ):
            if token in server_lower:
                technologies.append(label)
    if powered_by:
        technologies.append(f"X-Powered-By: {powered_by}")
    if headers.get("x-aspnet-version"):
        technologies.append("ASP.NET")
    if headers.get("x-aspnetmvc-version"):
        technologies.append("ASP.NET MVC")
    if headers.get("x-drupal-cache") or headers.get("x-drupal-dynamic-cache"):
        technologies.append("Drupal")
    if headers.get("x-shopware-shop-id"):
        technologies.append("Shopware")
    if headers.get("x-nextjs-cache") or headers.get("x-nextjs-prerender"):
        technologies.append("Next.js")
    if headers.get("x-runtime"):
        technologies.append("Ruby/Rack")

    if "cf-ray" in lower:
        cdn, technologies = "Cloudflare", [*technologies, "Cloudflare"]
    elif "x-amz-cf-id" in lower:
        cdn, technologies = "AWS CloudFront", [*technologies, "AWS CloudFront"]
    elif "x-vercel-id" in lower:
        cdn, technologies = "Vercel", [*technologies, "Vercel"]
    elif "x-azure-ref" in lower:
        cdn, technologies = "Azure Front Door", [*technologies, "Azure Front Door"]
    elif "x-github-request-id" in lower:
        cdn, technologies = "GitHub", [*technologies, "GitHub"]
    elif "x-served-by" in lower:
        cdn, technologies = "Fastly", [*technologies, "Fastly"]

    waf_tokens = (
        ("cf-ray", "Cloudflare"),
        ("x-sucuri-id", "Sucuri"),
        ("x-iinfo", "Imperva"),
        ("akamai-grn", "Akamai"),
        ("x-akamai-transformed", "Akamai"),
    )
    for header, label in waf_tokens:
        if header in lower:
            waf = label
            break

    if page:
        if page.generator:
            technologies.append(f"Generator: {page.generator}")
            generator_lower = page.generator.lower()
            for token, label in (
                ("wordpress", "WordPress"),
                ("drupal", "Drupal"),
                ("joomla", "Joomla"),
                ("hugo", "Hugo"),
                ("jekyll", "Jekyll"),
                ("next.js", "Next.js"),
                ("nuxt", "Nuxt"),
                ("shopify", "Shopify"),
            ):
                if token in generator_lower:
                    technologies.append(label)
        for script in page.scripts:
            script_lower = script.lower()
            for token, label in (
                ("/wp-content/", "WordPress"),
                ("/wp-includes/", "WordPress"),
                ("/_next/", "Next.js"),
                ("/_nuxt/", "Nuxt"),
                ("/static/js/main.", "Create React App"),
                ("jquery", "jQuery"),
                ("react", "React"),
                ("vue", "Vue"),
                ("angular", "Angular"),
            ):
                if token in script_lower:
                    technologies.append(label)

    return Fingerprint(
        server=server,
        powered_by=powered_by,
        generator=page.generator if page else "",
        technologies=dedupe(technologies),
        cdn=cdn,
        waf=waf,
    )


def cookie_technologies(cookies: list[dict[str, object]]) -> list[str]:
    hints = []
    for cookie in cookies:
        name = str(cookie.get("name", "")).lower()
        if name == "phpsessid":
            hints.append("PHP")
        elif name == "jsessionid":
            hints.append("Java")
        elif name == "asp.net_sessionid":
            hints.append("ASP.NET")
        elif name == "laravel_session":
            hints.append("Laravel")
        elif name == "csrftoken":
            hints.append("Django")
        elif name.startswith("wp-"):
            hints.append("WordPress")
        elif name == "connect.sid":
            hints.append("Express")
    return dedupe(hints)
