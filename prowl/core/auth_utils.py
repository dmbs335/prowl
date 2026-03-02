"""Standalone auth login utilities (extracted from s7_auth_crawl module)."""

from __future__ import annotations

import logging
import re
from pathlib import Path
from typing import Any

logger = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# Raw HTTP request parsing & replay
# ---------------------------------------------------------------------------


def parse_raw_http_request(text: str, default_host: str = "") -> dict[str, Any]:
    """Parse a raw HTTP request (Burp Suite / devtools copy format).

    Accepts::

        POST /login HTTP/1.1
        Host: example.com
        Content-Type: application/x-www-form-urlencoded
        Cookie: csrftoken=abc

        username=admin&password=secret

    Returns dict with keys: method, url, headers, body, cookies.
    """
    lines = text.replace("\r\n", "\n").split("\n")

    # Skip leading blank lines
    while lines and not lines[0].strip():
        lines.pop(0)
    if not lines:
        raise ValueError("Empty HTTP request")

    # --- Request line ---
    request_line = lines[0].strip()
    parts = request_line.split(None, 2)
    if len(parts) < 2:
        raise ValueError(f"Invalid request line: {request_line}")
    method = parts[0].upper()
    path = parts[1]

    # --- Headers ---
    headers: dict[str, str] = {}
    idx = 1
    while idx < len(lines):
        line = lines[idx]
        if not line.strip():
            idx += 1
            break
        if ":" in line:
            key, _, value = line.partition(":")
            headers[key.strip()] = value.strip()
        idx += 1

    # --- Body ---
    body = "\n".join(lines[idx:]).strip() if idx < len(lines) else ""

    # --- Resolve full URL from Host header ---
    host = headers.get("Host", "") or default_host
    if path.startswith("http://") or path.startswith("https://"):
        url = path
    else:
        scheme = "https"
        if host:
            _, _, port_part = host.rpartition(":")
            if port_part == "80":
                scheme = "http"
        url = f"{scheme}://{host}{path}"

    # --- Extract cookies ---
    cookies: dict[str, str] = {}
    cookie_header = headers.get("Cookie", "")
    if cookie_header:
        for pair in cookie_header.split(";"):
            pair = pair.strip()
            if "=" in pair:
                k, _, v = pair.partition("=")
                cookies[k.strip()] = v.strip()

    return {
        "method": method,
        "url": url,
        "headers": headers,
        "body": body,
        "cookies": cookies,
    }


def load_raw_requests(file_path: str) -> list[dict[str, Any]]:
    """Load one or more raw HTTP requests from a file.

    Multiple requests are separated by a line of ``---`` or ``###``.
    """
    path = Path(file_path)
    if not path.is_file():
        raise FileNotFoundError(f"Auth request file not found: {file_path}")

    content = path.read_text(encoding="utf-8", errors="replace")
    blocks = re.split(r"\n-{3,}\s*\n|\n#{3,}\s*\n", content)
    blocks = [b.strip() for b in blocks if b.strip()]

    results = []
    for block in blocks:
        try:
            results.append(parse_raw_http_request(block))
        except ValueError as e:
            logger.warning("Skipping invalid request block: %s", e)
    return results


async def replay_raw_request(parsed: dict[str, Any]) -> dict[str, Any]:
    """Replay a parsed raw HTTP request and return obtained cookies.

    Returns ``{success, cookies, status, message}``.
    """
    import httpx

    method = parsed["method"]
    url = parsed["url"]
    # Drop Host (httpx sets it) and Content-Length (httpx recalculates)
    skip = {"host", "content-length"}
    headers = {k: v for k, v in parsed["headers"].items() if k.lower() not in skip}
    body = parsed.get("body", "")

    async with httpx.AsyncClient(follow_redirects=True, timeout=15.0, verify=False) as client:
        try:
            resp = await client.request(
                method=method,
                url=url,
                headers=headers,
                content=body.encode() if body else None,
            )

            cookies: dict[str, str] = {}
            # Cookies from redirect chain
            for hist_resp in resp.history:
                for cookie in hist_resp.cookies.jar:
                    cookies.setdefault(cookie.name, cookie.value)
            # Cookies from final response (override)
            for cookie in resp.cookies.jar:
                cookies[cookie.name] = cookie.value

            return {
                "success": resp.status_code < 400,
                "cookies": cookies,
                "status": resp.status_code,
                "message": f"Replay {resp.status_code} ({len(cookies)} cookies)",
            }
        except Exception as e:
            logger.error("Raw request replay error: %s", e)
            return {
                "success": False,
                "cookies": {},
                "status": 0,
                "message": f"Replay error: {e}",
            }


def detect_login_fields(doc: Any) -> dict | None:
    """Parse an lxml HTML document to find login form fields.

    Returns dict with user_field, pass_field, action, hidden if found, else None.
    """
    _USER_HINTS = {"user", "uname", "username", "login", "email", "account", "name", "usr"}
    _PASS_HINTS = {"pass", "password", "passwd", "pwd", "secret"}

    for form in doc.xpath("//form"):
        inputs = form.xpath(".//input[@name]")
        user_field = None
        pass_field = None
        hidden_fields: dict[str, str] = {}

        for inp in inputs:
            name = inp.get("name", "")
            inp_type = inp.get("type", "text").lower()

            if inp_type == "password":
                pass_field = name
            elif inp_type == "hidden":
                hidden_fields[name] = inp.get("value", "")
            elif inp_type in ("text", "email", "") and not user_field:
                if name.lower() in _USER_HINTS or not user_field:
                    user_field = name

        if pass_field:
            action = form.get("action", "")
            return {
                "user_field": user_field or "username",
                "pass_field": pass_field,
                "action": action or None,
                "hidden": hidden_fields,
            }
    return None


async def perform_login(
    login_url: str,
    username: str,
    password: str,
    extra_fields: dict[str, str] | None = None,
) -> dict[str, Any]:
    """Perform automated login by fetching the login page and POSTing credentials.

    Returns ``{success: bool, cookies: dict, message: str}``.
    """
    import httpx
    from lxml.html import fromstring as html_fromstring

    extra_fields = extra_fields or {}

    async with httpx.AsyncClient(follow_redirects=True, timeout=15.0) as client:
        try:
            # Step 1: Fetch login page to discover form field names
            user_field = "username"
            pass_field = "password"
            form_action = login_url
            extra_hidden: dict[str, str] = {}

            try:
                get_resp = await client.get(login_url)
                if get_resp.status_code == 200 and "html" in get_resp.headers.get("content-type", ""):
                    doc = html_fromstring(get_resp.content)
                    doc.make_links_absolute(login_url, resolve_base_href=True)
                    detected = detect_login_fields(doc)
                    if detected:
                        user_field = detected["user_field"]
                        pass_field = detected["pass_field"]
                        if detected.get("action"):
                            form_action = detected["action"]
                        extra_hidden = detected.get("hidden", {})
                        logger.info(
                            "Detected login fields: user=%s pass=%s action=%s",
                            user_field, pass_field, form_action,
                        )
            except Exception as e:
                logger.debug("Could not parse login page: %s", e)

            # Step 2: POST login form
            login_data = {
                user_field: username,
                pass_field: password,
                **extra_hidden,
                **extra_fields,
            }
            resp = await client.post(form_action, data=login_data)

            if resp.status_code < 400:
                cookies = {cookie.name: cookie.value for cookie in resp.cookies.jar}
                return {
                    "success": True,
                    "cookies": cookies,
                    "message": f"Login successful ({len(cookies)} cookies obtained)",
                }
            else:
                return {
                    "success": False,
                    "cookies": {},
                    "message": f"Login failed (status {resp.status_code})",
                }
        except Exception as e:
            logger.error("Login error: %s", e)
            return {
                "success": False,
                "cookies": {},
                "message": f"Login error: {e}",
            }
