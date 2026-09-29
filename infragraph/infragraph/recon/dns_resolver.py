"""High-performance Async DNS Resolver."""
import asyncio
from typing import Dict, List, Optional, Set
import dns.asyncresolver
import dns.resolver
from pydantic import BaseModel, Field


class DNSQueryResult(BaseModel):
    hostname: str
    is_nxdomain: bool = False
    is_servfail: bool = False
    is_timeout: bool = False
    a_records: List[str] = Field(default_factory=list)
    aaaa_records: List[str] = Field(default_factory=list)
    cname_records: List[str] = Field(default_factory=list)
    ns_records: List[str] = Field(default_factory=list)
    mx_records: List[str] = Field(default_factory=list)
    txt_records: List[str] = Field(default_factory=list)
    error: Optional[str] = None


class AsyncDNSScanner:
    def __init__(
        self,
        nameservers: Optional[List[str]] = None,
        timeout: float = 3.0,
        concurrency: int = 50
    ):
        self.nameservers = nameservers or ["1.1.1.1", "8.8.8.8", "9.9.9.9"]
        self.timeout = timeout
        self.semaphore = asyncio.Semaphore(concurrency)
        self.resolver = dns.asyncresolver.Resolver()
        self.resolver.nameservers = self.nameservers
        self.resolver.timeout = timeout
        self.resolver.lifetime = timeout

    async def resolve_hostname(self, hostname: str) -> DNSQueryResult:
        hostname = hostname.strip().rstrip(".")
        result = DNSQueryResult(hostname=hostname)

        async with self.semaphore:
            # 1. Check CNAME
            try:
                cname_answers = await self.resolver.resolve(hostname, "CNAME")
                for rdata in cname_answers:
                    result.cname_records.append(str(rdata.target).rstrip("."))
            except (dns.resolver.NoAnswer, dns.resolver.NoNameservers):
                pass
            except dns.resolver.NXDOMAIN:
                result.is_nxdomain = True
                return result
            except dns.resolver.Timeout:
                result.is_timeout = True
                result.error = "DNS Timeout"
                return result
            except Exception as e:
                result.error = str(e)

            # 2. Check A records
            try:
                a_answers = await self.resolver.resolve(hostname, "A")
                for rdata in a_answers:
                    result.a_records.append(rdata.address)
            except (dns.resolver.NoAnswer, dns.resolver.NXDOMAIN, dns.resolver.NoNameservers):
                pass
            except dns.resolver.Timeout:
                result.is_timeout = True
            except Exception as e:
                if not result.error:
                    result.error = str(e)

            # 3. Check AAAA records
            try:
                aaaa_answers = await self.resolver.resolve(hostname, "AAAA")
                for rdata in aaaa_answers:
                    result.aaaa_records.append(rdata.address)
            except (dns.resolver.NoAnswer, dns.resolver.NXDOMAIN, dns.resolver.NoNameservers):
                pass
            except Exception:
                pass

            # 4. Check NS records (especially for apex or delegated subdomains)
            try:
                ns_answers = await self.resolver.resolve(hostname, "NS")
                for rdata in ns_answers:
                    result.ns_records.append(str(rdata.target).rstrip("."))
            except (dns.resolver.NoAnswer, dns.resolver.NXDOMAIN, dns.resolver.NoNameservers):
                pass
            except Exception:
                pass

            # 5. Check MX records
            try:
                mx_answers = await self.resolver.resolve(hostname, "MX")
                for rdata in mx_answers:
                    result.mx_records.append(str(rdata.exchange).rstrip("."))
            except (dns.resolver.NoAnswer, dns.resolver.NXDOMAIN, dns.resolver.NoNameservers):
                pass
            except Exception:
                pass

            # 6. Check TXT records (SPF, DMARC, DKIM, verification tokens)
            try:
                txt_answers = await self.resolver.resolve(hostname, "TXT")
                for rdata in txt_answers:
                    # Each TXT record may have multiple strings; join them
                    txt_value = "".join(
                        part.decode("utf-8", errors="replace") if isinstance(part, bytes) else part
                        for part in rdata.strings
                    )
                    result.txt_records.append(txt_value)
            except (dns.resolver.NoAnswer, dns.resolver.NXDOMAIN, dns.resolver.NoNameservers):
                pass
            except Exception:
                pass

        return result

    async def batch_resolve(self, hostnames: List[str]) -> List[DNSQueryResult]:
        tasks = [self.resolve_hostname(h) for h in hostnames]
        return await asyncio.gather(*tasks)
