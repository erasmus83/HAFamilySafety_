"""Fork-only diagnostics for the 24 h Family sign-in failure (upstream #52).

At +8 h and +16 h after an interactive sign-in the Family bootstrap ends on
``account.microsoft.com/auth/complete-client-signin-oauth-silent`` and
recovers on the next poll; at +24 h it ends on
``login.microsoftonline.com/.../authorize?prompt=login``. A browser runs the
silent page's JavaScript; httpx does not. These helpers record what that page
asks for and how the redirect chain got there, so the next step can be decided
on evidence.

Everything logged here is redacted: query values outside a short allow-list,
any token-like run of 40+ characters, and e-mail addresses are replaced by
their length. Nothing is sent anywhere; it only goes to the Home Assistant log
at DEBUG level.
"""

from __future__ import annotations

import logging
import re
from typing import Any

from yarl import URL

# Query parameters whose values are protocol switches, not credentials.
_SAFE_QUERY_KEYS = frozenset(
    {
        "prompt",
        "response_mode",
        "response_type",
        "client_id",
        "scope",
        "lc",
        "fref",
        "refd",
        "msaoauth2",
        "cobrandid",
        "instance_aware",
        "x-client-sku",
        "x-client-ver",
        "error",
        "error_description",
        "error_subcode",
        "wa",
        "wp",
        "lw",
        "fl",
    }
)
# Parameters that hold a URL: keep only its host and path.
_URL_QUERY_KEYS = frozenset({"redirect_uri", "ru", "wreply", "returnurl", "return_url"})

_URL_RE = re.compile(r"https?://[^\s\"'<>\\]+")
_TOKEN_RE = re.compile(r"[A-Za-z0-9+/_\-=%.]{40,}")
_EMAIL_RE = re.compile(r"[\w.+-]+@[\w-]+\.[\w.-]+")
_PAGE_CHUNK = 3500
_PAGE_LIMIT = 60000


def describe_url(value: Any) -> str:
    """Return host/path plus redacted query of a URL."""
    try:
        url = URL(str(value))
    except ValueError:
        return f"<unparseable len={len(str(value))}>"
    parts: list[str] = []
    for key, val in url.query.items():
        lowered = key.lower()
        if lowered in _SAFE_QUERY_KEYS:
            parts.append(f"{key}={_EMAIL_RE.sub('<email>', val)[:200]}")
        elif lowered in _URL_QUERY_KEYS:
            try:
                inner = URL(val)
                parts.append(f"{key}={inner.host}{inner.path}")
            except ValueError:
                parts.append(f"{key}=<len={len(val)}>")
        else:
            parts.append(f"{key}=<len={len(val)}>")
    text = f"{url.host}{url.path}"
    if parts:
        text += "?" + "&".join(parts)
    if url.fragment:
        text += f"#<fragment len={len(url.fragment)}>"
    return text


def redact_page(page: str) -> str:
    """Redact a page so its structure survives but no credential does."""
    urls: list[str] = []

    def _stash(match: re.Match[str]) -> str:
        urls.append(describe_url(match.group(0)))
        return f"\x00{len(urls) - 1}\x00"

    text = _URL_RE.sub(_stash, page)
    text = _EMAIL_RE.sub("<email>", text)
    text = _TOKEN_RE.sub(lambda m: f"<redacted len={len(m.group(0))}>", text)
    return re.sub(r"\x00(\d+)\x00", lambda m: f"https://{urls[int(m.group(1))]}", text)


def redirect_chain(resp: Any) -> list[str]:
    """Describe each hop of a followed redirect chain, ending at the final URL."""
    hops: list[str] = []
    for hop in getattr(resp, "history", None) or []:
        location = hop.headers.get("location") if getattr(hop, "headers", None) else None
        hops.append(
            f"{hop.status_code} {describe_url(hop.url)}"
            + (f" -> {describe_url(location)}" if location else "")
        )
    hops.append(f"{getattr(resp, 'status', '?')} {describe_url(resp.url)}")
    return hops


def _silent_cookies(session: Any) -> list[str]:
    """Names, domains, expiry and (when short) values of the silent-sign-in markers."""
    found: list[str] = []
    for morsel in session.cookie_jar:
        if "silent" not in morsel.key.lower():
            continue
        value = morsel.value or ""
        shown = value if len(value) <= 40 and not _EMAIL_RE.search(value) else f"<len={len(value)}>"
        found.append(f"{morsel.key}@{morsel['domain']} value={shown} expires={morsel['expires']}")
    return found


def log_bootstrap(
    logger: logging.Logger, outcome: str, resp: Any, page: str | None, session: Any
) -> None:
    """Log the redirect chain, silent-sign-in cookies and (for /auth pages) the page."""
    if not logger.isEnabledFor(logging.DEBUG):
        return
    try:
        logger.debug(
            "Fork #52 diag: Family bootstrap %s; chain=%s; silent_cookies=%s",
            outcome,
            " | ".join(redirect_chain(resp)),
            _silent_cookies(session),
        )
        final = URL(str(resp.url))
        # Only the account.microsoft.com /auth/* pages (the silent sign-in
        # step); never a Family page, which carries the antiforgery token.
        if (
            page is None
            or (final.host or "").lower() != "account.microsoft.com"
            or not (final.path or "").lower().startswith("/auth/")
        ):
            return
        redacted = redact_page(page)[:_PAGE_LIMIT]
        chunks = [
            redacted[i : i + _PAGE_CHUNK] for i in range(0, len(redacted), _PAGE_CHUNK)
        ] or [""]
        for index, chunk in enumerate(chunks, 1):
            logger.debug(
                "Fork #52 diag: page %s (original length %d) part %d/%d:\n%s",
                final.path,
                len(page),
                index,
                len(chunks),
                chunk,
            )
    except Exception as err:  # noqa: BLE001 - diagnostics must never break a poll
        logger.debug("Fork #52 diag failed: %r", err)
