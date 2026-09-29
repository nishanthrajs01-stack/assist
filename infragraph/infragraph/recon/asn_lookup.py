"""IP to ASN and CIDR lookup via Team Cymru DNS / RDAP."""
import asyncio
import ipaddress
from typing import Optional, Dict, List
import dns.asyncresolver
from pydantic import BaseModel


class ASNInfo(BaseModel):
    ip: str
    asn: str = "UNKNOWN"
    cidr: str = "UNKNOWN"
    country: str = "UNKNOWN"
    owner: str = "UNKNOWN"


class AsyncASNResolver:
    def __init__(self, nameservers: Optional[List[str]] = None, timeout: float = 2.5):
        self.resolver = dns.asyncresolver.Resolver()
        self.resolver.nameservers = nameservers or ["1.1.1.1", "8.8.8.8"]
        self.resolver.timeout = timeout
        self.resolver.lifetime = timeout
        self.cache: Dict[str, ASNInfo] = {}

    async def lookup_ip(self, ip: str) -> ASNInfo:
        ip = ip.strip()
        if ip in self.cache:
            return self.cache[ip]

        # Check private IP ranges
        try:
            ip_obj = ipaddress.ip_address(ip)
            if ip_obj.is_private or ip_obj.is_loopback:
                info = ASNInfo(ip=ip, asn="PRIVATE", cidr="RFC1918", owner="Private Network")
                self.cache[ip] = info
                return info
        except ValueError:
            return ASNInfo(ip=ip)

        # Team Cymru DNS mapping: origin.asn.cymru.com
        # IP 1.2.3.4 -> query 4.3.2.1.origin.asn.cymru.com TXT
        octets = ip.split(".")
        if len(octets) != 4:
            return ASNInfo(ip=ip)

        reversed_ip = ".".join(reversed(octets))
        query_domain = f"{reversed_ip}.origin.asn.cymru.com"

        try:
            answers = await self.resolver.resolve(query_domain, "TXT")
            for rdata in answers:
                txt = rdata.to_text().strip('"')
                # Format: "13335 | 1.1.1.0/24 | US | ripencc | 2011-08-11"
                parts = [p.strip() for p in txt.split("|")]
                if len(parts) >= 3:
                    asn_num = parts[0]
                    cidr = parts[1]
                    country = parts[2]
                    owner = await self._lookup_asn_name(asn_num)

                    info = ASNInfo(
                        ip=ip,
                        asn=f"AS{asn_num}",
                        cidr=cidr,
                        country=country,
                        owner=owner
                    )
                    self.cache[ip] = info
                    return info
        except Exception:
            pass

        # Fallback ASN info
        fallback = ASNInfo(ip=ip, asn="AS-UNKNOWN", cidr=f"{ip}/32", owner="Unknown Carrier")
        self.cache[ip] = fallback
        return fallback

    async def _lookup_asn_name(self, asn_num: str) -> str:
        """Query AS<num>.asn.cymru.com for the organization name."""
        query_domain = f"AS{asn_num}.asn.cymru.com"
        try:
            answers = await self.resolver.resolve(query_domain, "TXT")
            for rdata in answers:
                txt = rdata.to_text().strip('"')
                # Format: "13335 | US | arin | 2010-07-14 | CLOUDFLARENET, US"
                parts = [p.strip() for p in txt.split("|")]
                if len(parts) >= 5:
                    return parts[4]
        except Exception:
            pass
        return f"Autonomous System {asn_num}"
