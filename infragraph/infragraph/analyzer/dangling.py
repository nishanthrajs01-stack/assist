"""Dangling CNAME and Subdomain Takeover Analyzer."""
import aiohttp
import asyncio
from typing import List, Optional
from pydantic import BaseModel

from infragraph.models.nodes import BaseNode, NodeType, RiskLevel
from infragraph.models.edges import BaseEdge, EdgeType
from infragraph.models.graph import InfraGraph
from infragraph.recon.dns_resolver import AsyncDNSScanner
from infragraph.analyzer.signatures import match_cloud_signature, CloudSignature


class DanglingFinding(BaseModel):
    subdomain: str
    cname_target: str
    cloud_service: str
    provider: str
    risk_level: RiskLevel
    evidence: str
    remediation: str


class DanglingAnalyzer:
    def __init__(self, dns_scanner: AsyncDNSScanner, http_timeout: float = 4.0):
        self.dns_scanner = dns_scanner
        self.http_timeout = aiohttp.ClientTimeout(total=http_timeout)

    async def verify_takeover(
        self,
        subdomain: str,
        cname_target: str,
        sig: CloudSignature
    ) -> Optional[DanglingFinding]:
        """Verify if a CNAME target is actually claimable / dangling."""
        # 1. Resolve target hostname to see if it's NXDOMAIN or unresolvable
        target_res = await self.dns_scanner.resolve_hostname(cname_target)
        if target_res.is_nxdomain and sig.nxdomain_vulnerable:
            return DanglingFinding(
                subdomain=subdomain,
                cname_target=cname_target,
                cloud_service=sig.service_name,
                provider=sig.provider,
                risk_level=RiskLevel.CRITICAL,
                evidence=f"CNAME points to NXDOMAIN target '{cname_target}' ({sig.service_name}) which can be registered.",
                remediation=sig.remediation
            )

        # 2. If fingerprints are defined, make HTTP/HTTPS GET requests to check body signatures
        if sig.fingerprint_body:
            for proto in ["https://", "http://"]:
                url = f"{proto}{subdomain}"
                try:
                    headers = {"User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) InfraGraph/1.0"}
                    async with aiohttp.ClientSession(
                        timeout=self.http_timeout,
                        connector=aiohttp.TCPConnector(ssl=False)
                    ) as session:
                        async with session.get(url, headers=headers, allow_redirects=True) as resp:
                            body = await resp.text()
                            for fp in sig.fingerprint_body:
                                if fp.lower() in body.lower():
                                    return DanglingFinding(
                                        subdomain=subdomain,
                                        cname_target=cname_target,
                                        cloud_service=sig.service_name,
                                        provider=sig.provider,
                                        risk_level=RiskLevel[sig.risk_level],
                                        evidence=f"HTTP signature matched '{fp}' on {url} pointing to {sig.service_name}.",
                                        remediation=sig.remediation
                                    )
                except Exception:
                    continue

        return None

    async def scan_graph(self, graph: InfraGraph) -> List[DanglingFinding]:
        """Scan all CNAME relationships in the graph for takeover vulnerabilities."""
        findings: List[DanglingFinding] = []
        tasks = []

        for edge in list(graph.edges.values()):
            if edge.type == EdgeType.ALIAS_OF:
                subdomain = edge.source_id
                cname_target = edge.target_id
                sig = match_cloud_signature(cname_target)
                if sig:
                    tasks.append((subdomain, cname_target, sig))

        # Run all verifications concurrently instead of sequentially
        if tasks:
            results = await asyncio.gather(
                *[self.verify_takeover(sub, cname, sig) for sub, cname, sig in tasks],
                return_exceptions=True
            )
        else:
            results = []

        for (subdomain, cname_target, sig), finding in zip(tasks, results):
            if isinstance(finding, Exception) or finding is None:
                continue
            findings.append(finding)

            # Update node in graph with CRITICAL risk and add Dangling Edge
            sub_node = graph.get_node(subdomain)
            if sub_node:
                sub_node.risk_level = finding.risk_level
                sub_node.attributes["dangling_vulnerability"] = finding.model_dump()

            cloud_id = f"cloud:{cname_target}"
            graph.add_node(BaseNode(
                id=cloud_id,
                type=NodeType.CLOUD_RESOURCE,
                label=f"{sig.service_name} ({cname_target})",
                risk_level=finding.risk_level,
                attributes={"provider": sig.provider, "service": sig.service_name, "dangling": True}
            ))

            graph.add_edge(BaseEdge(
                source_id=subdomain,
                target_id=cloud_id,
                type=EdgeType.DANGLING_TARGET,
                label="🚨 DANGLING TAKEOVER",
                confidence=1.0,
                attributes={"evidence": finding.evidence, "remediation": finding.remediation}
            ))

        return findings
