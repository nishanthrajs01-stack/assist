"""Certificate Transparency Log Enumeration."""
import aiohttp
import asyncio
from typing import Set, List
import json


class CTLogScanner:
    def __init__(self, timeout: float = 10.0):
        self.timeout = aiohttp.ClientTimeout(total=timeout)

    async def fetch_crtsh_subdomains(self, domain: str) -> Set[str]:
        """Fetch subdomains from crt.sh API."""
        domain = domain.strip().lower()
        subdomains: Set[str] = set()
        url = f"https://crt.sh/?q=%.{domain}&output=json"

        try:
            headers = {
                "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) InfraGraph/1.0"
            }
            async with aiohttp.ClientSession(timeout=self.timeout) as session:
                async with session.get(url, headers=headers) as response:
                    if response.status == 200:
                        data = await response.json(content_type=None)
                        for entry in data:
                            name_value = entry.get("name_value", "")
                            for raw_sub in name_value.split("\n"):
                                raw_sub = raw_sub.strip().lower()
                                if raw_sub.startswith("*."):
                                    raw_sub = raw_sub[2:]
                                if raw_sub.endswith(domain) and raw_sub != "":
                                    subdomains.add(raw_sub)
        except Exception:
            # Fallback gracefully if crt.sh rate limits or is down
            pass

        return subdomains
