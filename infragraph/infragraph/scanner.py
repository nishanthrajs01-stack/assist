"""Main InfraGraph Scanning Orchestrator."""
import asyncio
from typing import List, Set, Optional
from datetime import datetime, timezone

from infragraph.models.nodes import BaseNode, NodeType, RiskLevel
from infragraph.models.edges import BaseEdge, EdgeType
from infragraph.models.graph import InfraGraph
from infragraph.recon.dns_resolver import AsyncDNSScanner, DNSQueryResult
from infragraph.recon.ct_logs import CTLogScanner
from infragraph.recon.asn_lookup import AsyncASNResolver
from infragraph.recon.wordlist import generate_subdomain_candidates
from infragraph.analyzer.dangling import DanglingAnalyzer
from infragraph.analyzer.anomalies import AnomalyDetector


class InfraScanner:
    def __init__(
        self,
        nameservers: Optional[List[str]] = None,
        concurrency: int = 50,
        dns_timeout: float = 3.0,
        enable_active_bruteforce: bool = True
    ):
        self.dns_scanner = AsyncDNSScanner(nameservers=nameservers, timeout=dns_timeout, concurrency=concurrency)
        self.ct_scanner = CTLogScanner()
        self.asn_resolver = AsyncASNResolver(nameservers=nameservers)
        self.dangling_analyzer = DanglingAnalyzer(self.dns_scanner)
        self.anomaly_detector = AnomalyDetector()
        self.enable_active_bruteforce = enable_active_bruteforce

    async def scan_domain(self, target_domain: str, extra_subdomains: Optional[List[str]] = None) -> InfraGraph:
        target_domain = target_domain.strip().lower()
        graph = InfraGraph(name=f"Recon Target: {target_domain}")

        # 1. Add Root Domain Node
        root_node = BaseNode(
            id=target_domain,
            type=NodeType.DOMAIN,
            label=target_domain,
            risk_level=RiskLevel.INFO,
            attributes={"is_apex": True}
        )
        graph.add_node(root_node)

        # 2. Discover Subdomain Candidates
        candidates: Set[str] = {target_domain}
        if extra_subdomains:
            candidates.update([s.strip().lower() for s in extra_subdomains if s.strip()])

        # Query Certificate Transparency
        ct_subdomains = await self.ct_scanner.fetch_crtsh_subdomains(target_domain)
        candidates.update(ct_subdomains)

        # Generate candidates from common prefixes if enabled
        if self.enable_active_bruteforce:
            brute_candidates = generate_subdomain_candidates(target_domain)
            candidates.update(brute_candidates)

        # 3. Resolve all candidates via Async DNS
        candidate_list = list(candidates)
        dns_results = await self.dns_scanner.batch_resolve(candidate_list)

        unique_ips: Set[str] = set()

        for res in dns_results:
            # Skip unresolvable candidates that are not the apex domain
            has_records = (
                bool(res.a_records) or
                bool(res.aaaa_records) or
                bool(res.cname_records) or
                bool(res.ns_records) or
                bool(res.mx_records)
            )

            if not has_records and res.hostname != target_domain:
                continue

            # Add Subdomain Node
            node_type = NodeType.DOMAIN if res.hostname == target_domain else NodeType.SUBDOMAIN
            sub_node = BaseNode(
                id=res.hostname,
                type=node_type,
                label=res.hostname,
                risk_level=RiskLevel.INFO,
                attributes={
                    "a_records": res.a_records,
                    "aaaa_records": res.aaaa_records,
                    "cname_records": res.cname_records,
                    "ns_records": res.ns_records,
                    "mx_records": res.mx_records,
                    "txt_records": res.txt_records
                }
            )
            graph.add_node(sub_node)

            if res.hostname != target_domain:
                graph.add_edge(BaseEdge(
                    source_id=target_domain,
                    target_id=res.hostname,
                    type=EdgeType.HAS_SUBDOMAIN,
                    label="subdomain"
                ))

            # Add CNAME Edges
            for cname in res.cname_records:
                cname_node = BaseNode(
                    id=cname,
                    type=NodeType.DOMAIN if not cname.endswith(f".{target_domain}") else NodeType.SUBDOMAIN,
                    label=cname,
                    attributes={"is_cname_target": True}
                )
                graph.add_node(cname_node)
                graph.add_edge(BaseEdge(
                    source_id=res.hostname,
                    target_id=cname,
                    type=EdgeType.ALIAS_OF,
                    label="CNAME"
                ))

            # Add IP Nodes and RESOLVES_TO edges
            for ip in res.a_records + res.aaaa_records:
                unique_ips.add(ip)
                ip_node = BaseNode(
                    id=ip,
                    type=NodeType.IP,
                    label=ip,
                    attributes={"is_ipv6": ":" in ip}
                )
                graph.add_node(ip_node)
                graph.add_edge(BaseEdge(
                    source_id=res.hostname,
                    target_id=ip,
                    type=EdgeType.RESOLVES_TO,
                    label="A/AAAA"
                ))

        # 4. Enrich IP Nodes with ASN & CIDR lookups
        asn_tasks = [self.asn_resolver.lookup_ip(ip) for ip in unique_ips]
        asn_results = await asyncio.gather(*asn_tasks)

        for asn_info in asn_results:
            if asn_info.asn and asn_info.asn != "UNKNOWN":
                asn_node_id = asn_info.asn
                asn_node = BaseNode(
                    id=asn_node_id,
                    type=NodeType.ASN,
                    label=f"{asn_info.asn} ({asn_info.owner})",
                    attributes={
                        "asn": asn_info.asn,
                        "owner": asn_info.owner,
                        "country": asn_info.country
                    }
                )
                graph.add_node(asn_node)

                graph.add_edge(BaseEdge(
                    source_id=asn_info.ip,
                    target_id=asn_node_id,
                    type=EdgeType.BELONGS_TO_ASN,
                    label=f"ASN ({asn_info.cidr})"
                ))

                # Update IP attributes
                ip_node = graph.get_node(asn_info.ip)
                if ip_node:
                    ip_node.attributes["asn"] = asn_info.asn
                    ip_node.attributes["cidr"] = asn_info.cidr
                    ip_node.attributes["owner"] = asn_info.owner
                    ip_node.attributes["country"] = asn_info.country

        # 5. Run Dangling / Takeover Detection
        await self.dangling_analyzer.scan_graph(graph)

        # 6. Run Attack Surface Anomaly Detection
        self.anomaly_detector.detect_anomalies(graph)

        return graph
