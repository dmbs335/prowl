"""Browser bridge — import cookies/sessions from various sources."""

from __future__ import annotations

import json
import logging
import re
from typing import Any

logger = logging.getLogger(__name__)


class BrowserBridge:
    """Import authentication state from external sources."""

    @staticmethod
    def parse_cookie_string(cookie_string: str) -> dict[str, str]:
        """Parse a 'name=value; name2=value2' cookie string."""
        cookies: dict[str, str] = {}
        for part in cookie_string.split(";"):
            part = part.strip()
            if "=" in part:
                name, _, value = part.partition("=")
                cookies[name.strip()] = value.strip()
        return cookies

    @staticmethod
    def parse_curl_command(curl_command: str) -> dict[str, Any]:
        """Extract headers and cookies from a curl command."""
        headers: dict[str, str] = {}
        cookies: dict[str, str] = {}

        # Extract -H/--header flags
        header_pattern = re.compile(r"""-H\s+['"]([^'"]+)['"]""")
        for match in header_pattern.finditer(curl_command):
            header_str = match.group(1)
            if ":" in header_str:
                name, _, value = header_str.partition(":")
                name = name.strip()
                value = value.strip()
                if name.lower() == "cookie":
                    cookies.update(BrowserBridge.parse_cookie_string(value))
                else:
                    headers[name] = value

        # Extract -b/--cookie flags
        cookie_pattern = re.compile(r"""-b\s+['"]([^'"]+)['"]""")
        for match in cookie_pattern.finditer(curl_command):
            cookies.update(BrowserBridge.parse_cookie_string(match.group(1)))

        return {"headers": headers, "cookies": cookies}

    @staticmethod
    def parse_burp_cookies_xml(xml_content: str) -> dict[str, str]:
        """Parse cookies from Burp Suite XML export."""
        cookies: dict[str, str] = {}
        try:
            import xml.etree.ElementTree as ET
            root = ET.fromstring(xml_content)
            for cookie in root.findall(".//cookie"):
                name = cookie.findtext("name", "")
                value = cookie.findtext("value", "")
                if name:
                    cookies[name] = value
        except Exception as e:
            logger.warning("Failed to parse Burp XML: %s", e)
        return cookies

    @staticmethod
    def parse_json_cookies(json_content: str) -> dict[str, str]:
        """Parse cookies from JSON format (browser extension exports)."""
        cookies: dict[str, str] = {}
        try:
            data = json.loads(json_content)
            if isinstance(data, list):
                for item in data:
                    if isinstance(item, dict) and "name" in item:
                        cookies[item["name"]] = item.get("value", "")
            elif isinstance(data, dict):
                cookies = data
        except json.JSONDecodeError as e:
            logger.warning("Failed to parse JSON cookies: %s", e)
        return cookies

    @staticmethod
    async def extract_from_browser(page: Any) -> dict[str, str]:
        """Extract cookies from a Playwright page."""
        cookies: dict[str, str] = {}
        try:
            context = page.context
            browser_cookies = await context.cookies()
            for cookie in browser_cookies:
                cookies[cookie["name"]] = cookie["value"]
        except Exception as e:
            logger.warning("Failed to extract browser cookies: %s", e)
        return cookies
