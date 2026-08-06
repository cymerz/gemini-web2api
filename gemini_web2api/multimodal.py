"""Multimodal: Scotty resumable upload for Gemini image input."""
import json
import base64
import http.cookiejar
import urllib.request
import urllib.parse
import time
import ssl
import re
import os

from .config import CONFIG
from .gemini import load_cookie, make_sapisidhash, _get_ssl_ctx, log


def _get_page_tokens() -> dict:
    """Fetch page tokens, self-healing via cookie rotation on degraded sessions."""
    return _get_page_tokens_inner()


def _get_page_tokens_inner() -> dict:
    """Fetch WIZ_global_data tokens from Gemini page (Push-ID, X-Client-Pctx)."""
    headers = {
        "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36",
        "Origin": "https://gemini.google.com",
        "Referer": "https://gemini.google.com/",
    }
    cookie_str, sapisid = load_cookie()
    if cookie_str:
        headers["Cookie"] = cookie_str
    try:
        req = urllib.request.Request("https://gemini.google.com/app", headers=headers)
        proxy = CONFIG.get("proxy")
        if proxy:
            opener = urllib.request.build_opener(
                urllib.request.ProxyHandler({"http": proxy, "https": proxy}),
                urllib.request.HTTPSHandler(context=_get_ssl_ctx()))
            resp = opener.open(req, timeout=30)
        else:
            resp = urllib.request.urlopen(req, context=_get_ssl_ctx(), timeout=30)
        html = resp.read().decode()
        tokens = {}
        for key, pattern in [
            ("push_id", r'"qKIAYe":"([^"]+)"'),
            ("pctx", r'"Ylro7b":"([^"]+)"'),
        ]:
            m = re.search(pattern, html)
            if m:
                tokens[key] = m.group(1)
        # XSRF "at" token: SNlM0e is the real token (ADR5... format) and must
        # take priority; thykhd is a different token type and only works as a
        # fallback when it also looks like an ADR xsrf token.
        m = re.search(r'SNlM0e":"([^"]+)"', html) or re.search(r'SNlM0e=([^"&\s]+)', html)
        if m:
            tokens["at"] = m.group(1)
        else:
            m = re.search(r'"thykhd":"([^"]+)"', html)
            if m and m.group(1).startswith("ADR"):
                tokens["at"] = m.group(1)
        if not tokens.get("at"):
            # Degraded session: __Secure-1PSIDTS is very likely expired.
            # Try rotating it once, then fetch the page again.
            if _maybe_rotate_cookies():
                return _get_page_tokens_inner()
        return tokens
    except Exception as e:
        log(f"Page token fetch failed: {e}")
        return {}


_page_tokens_cache = {"tokens": {}, "ts": 0}
_upload_debug = bool(os.environ.get("GEMINI_UPLOAD_DEBUG"))
_rotate_state = {"last_attempt": 0.0}


def _cookie_jar_from_str(cookie_str: str):
    """Build a CookieJar for .google.com from a 'k=v; k=v' cookie string."""
    cj = http.cookiejar.CookieJar()
    for part in cookie_str.split(";"):
        if "=" in part:
            k, v = part.strip().split("=", 1)
            cj.set_cookie(http.cookiejar.Cookie(
                0, k, v, None, False, ".google.com", True, False,
                "google.com", True, False, None, False, None, None, {}))
    return cj


def _jar_cookie_str(cj) -> str:
    return "; ".join(f"{c.name}={c.value}" for c in cj)


def _persist_rotated_cookies(cookie_str: str):
    """Update the in-memory cookie cache and rewrite the cookie file if possible."""
    from . import gemini as _g
    pairs = dict(p.split("=", 1) for p in cookie_str.split("; ") if "=" in p)
    sapisid = pairs.get("SAPISID") or None
    _g._cookie_cache.update({"str": cookie_str, "sapisid": sapisid, "mtime": 0})
    cookie_file = CONFIG.get("cookie_file")
    if cookie_file:
        try:
            with open(cookie_file, "w") as f:
                f.write(cookie_str)
            log(f"[COOKIE] Refreshed cookies persisted to {cookie_file}")
        except Exception as e:
            log(f"[COOKIE] WARNING: could not persist refreshed cookies: {e}")


def _maybe_rotate_cookies() -> bool:
    """Refresh __Secure-1PSIDTS via accounts.google.com/RotateCookies.

    Google rotates this cookie frequently; when it expires the session degrades
    (no SNlM0e token, uploads orphaned -> BardErrorInfo [1100]). Returns True
    when a fresh __Secure-1PSIDTS was obtained. Throttled to once per 5 min.
    """
    now = time.time()
    if now - _rotate_state["last_attempt"] < 300:
        return False
    _rotate_state["last_attempt"] = now

    cookie_str, _ = load_cookie()
    if not cookie_str:
        return False

    cj = _cookie_jar_from_str(cookie_str)
    old_ts = next((c.value for c in cj if c.name == "__Secure-1PSIDTS"), None)
    ua = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36"

    # Preferred path: curl_cffi with Chrome TLS impersonation. Google rejects
    # plain HTTP clients on this endpoint with 401.
    try:
        from curl_cffi import requests as _creq
        proxy = CONFIG.get("proxy")
        s = _creq.Session(impersonate="chrome", proxy=proxy)
        for c in cj:
            s.cookies.set(c.name, c.value, domain=".google.com")
        s.get("https://www.google.com", timeout=20)
        resp = s.post("https://accounts.google.com/RotateCookies",
                      headers={"Content-Type": "application/json",
                               "Origin": "https://accounts.google.com"},
                      data='[000,"-0000000000000000000"]', timeout=20)
        if resp.status_code == 200:
            new_ts = s.cookies.get("__Secure-1PSIDTS", domain=".google.com")
            if new_ts and new_ts != old_ts:
                merged = "; ".join(
                    f"{k}={v}" for k, v in
                    {**{c.name: c.value for c in cj}, **dict(s.cookies.items())}.items())
                _persist_rotated_cookies(merged)
                log("[COOKIE] __Secure-1PSIDTS rotated successfully (curl_cffi) - session refreshed")
                s.close()
                return True
            log("[COOKIE] Rotation completed but no fresh __Secure-1PSIDTS returned - "
                "cookies are likely fully expired; re-export them from the browser")
            s.close()
            return False
        log(f"[COOKIE] Rotation request failed: HTTP {resp.status_code} (curl_cffi)")
        s.close()
    except ImportError:
        log("[COOKIE] curl_cffi not installed - trying plain rotation (may fail with 401)")
    except Exception as e:
        log(f"[COOKIE] Rotation request failed (curl_cffi): {e}")

    # Fallback: plain urllib (usually 401 on this endpoint, but zero new deps)
    opener = urllib.request.build_opener(
        urllib.request.HTTPCookieProcessor(cj),
        urllib.request.HTTPSHandler(context=_get_ssl_ctx()))
    try:
        # Preflight like a real browser session (collects AEC/NID etc.)
        opener.open(urllib.request.Request("https://www.google.com",
                                           headers={"User-Agent": ua}), timeout=20).read()
        req = urllib.request.Request(
            "https://accounts.google.com/RotateCookies",
            data=b'[000,"-0000000000000000000"]', method="POST",
            headers={"Content-Type": "application/json",
                     "Origin": "https://accounts.google.com",
                     "User-Agent": ua})
        resp = opener.open(req, timeout=20)
        resp.read()
    except Exception as e:
        log(f"[COOKIE] Rotation request failed: {e} - re-export fresh cookies "
            f"(especially __Secure-1PSIDTS) if image requests keep failing")
        return False

    new_ts = next((c.value for c in cj if c.name == "__Secure-1PSIDTS"), None)
    if not new_ts or new_ts == old_ts:
        log("[COOKIE] Rotation did not yield a fresh __Secure-1PSIDTS - "
            "cookies are likely fully expired; re-export them from the browser")
        return False

    _persist_rotated_cookies(_jar_cookie_str(cj))
    log("[COOKIE] __Secure-1PSIDTS rotated successfully - session refreshed")
    return True


def _cached_page_tokens() -> dict:
    now = time.time()
    if now - _page_tokens_cache["ts"] > 600:
        tokens = _get_page_tokens()
        if tokens.get("at"):
            _page_tokens_cache["tokens"] = tokens
            _page_tokens_cache["ts"] = now
        else:
            # Degraded result (no XSRF token): return it but do not cache,
            # so the next call re-checks (and may rotate cookies again).
            return tokens
    return _page_tokens_cache["tokens"]


def _invalidate_page_tokens():
    """Drop cached tokens (e.g. after a 400 xsrf) so the next call re-fetches."""
    _page_tokens_cache["tokens"] = {}
    _page_tokens_cache["ts"] = 0


def upload_image(image_bytes: bytes, filename: str = "image.png", mime_type: str = "image/png",
                 extra_headers: dict = None) -> str:
    """Upload image via Scotty resumable upload. Returns file reference path."""
    tokens = _cached_page_tokens()
    push_id = tokens.get("push_id", "feeds/mcudyrk2a4khkz")
    pctx = tokens.get("pctx", "CgcSBWjK7pYx")

    cookie_str, sapisid = load_cookie()
    ctx = _get_ssl_ctx()
    proxy = CONFIG.get("proxy")

    # Step 1: Initiate resumable upload
    start_headers = {
        "Push-ID": push_id,
        "X-Tenant-Id": "bard-storage",
        "X-Client-Pctx": pctx,
        "X-Goog-Upload-Header-Content-Length": str(len(image_bytes)),
        "X-Goog-Upload-Header-Content-Type": mime_type,
        "X-Goog-Upload-Protocol": "resumable",
        "X-Goog-Upload-Command": "start",
        "Content-Type": "application/x-www-form-urlencoded;charset=utf-8",
        "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36",
    }
    if extra_headers:
        start_headers.update(extra_headers)
    if cookie_str:
        start_headers["Cookie"] = cookie_str
    if sapisid:
        start_headers["Authorization"] = make_sapisidhash(sapisid)

    start_url = "https://content-push.googleapis.com/upload/"
    req = urllib.request.Request(start_url, data=b"", headers=start_headers, method="POST")

    if _upload_debug:
        masked = {k: ("<masked>" if k in ("Cookie", "Authorization") else v)
                  for k, v in start_headers.items()}
        log(f"[UPLOAD-DEBUG] start request headers: {masked}")

    if proxy:
        opener = urllib.request.build_opener(
            urllib.request.ProxyHandler({"http": proxy, "https": proxy}),
            urllib.request.HTTPSHandler(context=ctx)
        )
        resp = opener.open(req, timeout=30)
    else:
        resp = urllib.request.urlopen(req, context=ctx, timeout=30)

    if _upload_debug:
        log(f"[UPLOAD-DEBUG] start response status={resp.status} "
            f"headers={dict(resp.headers.items())}")

    upload_url = resp.headers.get("X-Goog-Upload-URL") or resp.headers.get("x-goog-upload-url")
    if not upload_url:
        raise RuntimeError(f"No upload URL in response headers: {dict(resp.headers)}")

    log(f"Upload session started: {upload_url[:80]}...")

    # Step 2: Upload file data + finalize
    upload_headers = {
        "X-Goog-Upload-Command": "upload, finalize",
        "X-Goog-Upload-Offset": "0",
        "Content-Type": "application/octet-stream",
        "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36",
    }

    req2 = urllib.request.Request(upload_url, data=image_bytes, headers=upload_headers, method="POST")
    if proxy:
        resp2 = opener.open(req2, timeout=60)
    else:
        resp2 = urllib.request.urlopen(req2, context=ctx, timeout=60)

    raw_body = resp2.read().decode(errors="replace")
    if _upload_debug:
        log(f"[UPLOAD-DEBUG] finalize response status={resp2.status} "
            f"headers={dict(resp2.headers.items())}")
        log(f"[UPLOAD-DEBUG] finalize body (raw, first 400 chars): {raw_body[:400]!r}")

    file_ref = raw_body.strip()
    if not file_ref or not file_ref.startswith("/"):
        raise RuntimeError(f"Invalid file reference: {file_ref[:100]}")

    log(f"Image uploaded: {filename} ({mime_type}, {len(image_bytes)} bytes) -> {file_ref}")
    return file_ref


def _guess_mime_from_url(url: str) -> str:
    """Guess image mime type from URL file extension."""
    ext = os.path.splitext(urllib.parse.urlparse(url).path)[1].lower()
    return {
        ".jpg": "image/jpeg", ".jpeg": "image/jpeg", ".png": "image/png",
        ".gif": "image/gif", ".webp": "image/webp", ".bmp": "image/bmp",
        ".heic": "image/heic", ".heif": "image/heif",
    }.get(ext, "image/png")


def fetch_image_bytes(url: str) -> tuple:
    """Fetch image from URL. Returns (bytes, mime_type); (b"", mime) on failure."""
    try:
        req = urllib.request.Request(url, headers={"User-Agent": "Mozilla/5.0"})
        resp = urllib.request.urlopen(req, timeout=30)
        mime = resp.headers.get("Content-Type", "").split(";")[0].strip()
        if not mime.startswith("image/"):
            # Server returned generic content type; fall back to URL extension
            mime = _guess_mime_from_url(url)
        return resp.read(), mime
    except Exception as e:
        log(f"Image fetch failed: {e}")
        return b"", "image/png"
