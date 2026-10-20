from __future__ import annotations

from dataclasses import dataclass
from typing import Iterable

from ..util import normalize_host


@dataclass(frozen=True)
class Provider:
    suffix: str
    name: str
    signatures: tuple[str, ...]


PROVIDERS: tuple[Provider, ...] = (
    Provider("github.io", "GitHub Pages", ("there isn't a github pages site here",)),
    Provider("herokuapp.com", "Heroku", ("no such app", "heroku | no such app")),
    Provider("s3.amazonaws.com", "AWS S3", ("nosuchbucket", "the specified bucket does not exist")),
    Provider("cloudfront.net", "AWS CloudFront", ("the request could not be satisfied",)),
    Provider("azurewebsites.net", "Azure App Service", ("404 web site not found",)),
    Provider("cloudapp.azure.com", "Azure Cloud App", ("404 web site not found",)),
    Provider("blob.core.windows.net", "Azure Blob Storage", ("blobnotfound",)),
    Provider("netlify.app", "Netlify", ("not found - request id",)),
    Provider("vercel.app", "Vercel", ("the deployment could not be found",)),
    Provider("now.sh", "Vercel (legacy now.sh)", ("the deployment could not be found", "deployment not found")),
    Provider("pages.dev", "Cloudflare Pages", ("project not found",)),
    Provider("web.app", "Firebase Hosting", ("site not found",)),
    Provider("firebaseapp.com", "Firebase Hosting", ("site not found",)),
    Provider("surge.sh", "Surge", ("project not found",)),
    Provider("readme.io", "ReadMe", ("project doesn't exist",)),
    Provider("wordpress.com", "WordPress.com", ("doesn’t exist", "doesn't exist")),
    Provider("tumblr.com", "Tumblr", ("whatever you were looking for isn't here",)),
    Provider("myshopify.com", "Shopify", ("sorry, this shop is currently unavailable",)),
    Provider("unbounce.com", "Unbounce", ("the requested url was not found",)),
    Provider("fastly.net", "Fastly", ("fastly error: unknown domain",)),
    Provider("pantheonsite.io", "Pantheon", ("the gods are wise, but do not know of the site which you seek",)),
    Provider("helpscoutdocs.com", "Help Scout Docs", ("no settings were found for this company",)),
    Provider("freshdesk.com", "Freshdesk", ("there is no helpdesk here",)),
    Provider("uservoice.com", "UserVoice", ("this uservoice subdomain is currently available",)),
    Provider("zendesk.com", "Zendesk", ("this help center is no longer active", "help center closed")),
    Provider("bigcartel.com", "Big Cartel", ("this store is unavailable",)),
    Provider("webflow.io", "Webflow", ("the page you are looking for doesn't exist or has been moved",)),
    Provider("glitch.me", "Glitch", ("there's no site here", "no site here")),
)


def provider_for(cname_chain: Iterable[str]) -> Provider | None:
    for cname in cname_chain:
        host = normalize_host(cname)
        for provider in PROVIDERS:
            if host == provider.suffix or host.endswith("." + provider.suffix):
                return provider
    return None


def matching_signature(provider: Provider, text: str) -> str | None:
    haystack = (text or "").lower()
    for signature in provider.signatures:
        if signature in haystack:
            return signature
    return None
