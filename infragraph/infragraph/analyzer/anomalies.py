"""Attack surface anomaly and orphan asset detector."""
from typing import List, Dict, Any
from pydantic import BaseModel

from infragraph.models.nodes import BaseNode, NodeType, RiskLevel
from infragraph.models.edges import BaseEdge, EdgeType
from infragraph.models.graph import InfraGraph


class AnomalyReport(BaseModel):
    anomaly_type: str
    target_id: str
    severity: RiskLevel
    description: str
    recommendation: str


class AnomalyDetector:
    def detect_anomalies(self, graph: InfraGraph) -> List[AnomalyReport]:
        reports: List[AnomalyReport] = []

        # 1. Detect high-risk internal keywords exposed on public IPs
        sensitive_keywords = ["admin", "internal", "corp", "vpn", "stag", "test", "dev", "k8s", "grafana", "vault"]
        for node in graph.nodes.values():
            if node.type == NodeType.SUBDOMAIN:
                label_lower = node.label.lower()
                for kw in sensitive_keywords:
                    if kw in label_lower and not label_lower.startswith("mail."):
                        # Check if it resolves to a public IP
                        resolved_ips = [
                            e.target_id for e in graph.edges.values()
                            if e.source_id == node.id and e.type == EdgeType.RESOLVES_TO
                        ]
                        if resolved_ips:
                            reports.append(AnomalyReport(
                                anomaly_type="EXPOSED_INTERNAL_SERVICE",
                                target_id=node.id,
                                severity=RiskLevel.MEDIUM if "stag" in kw or "dev" in kw else RiskLevel.HIGH,
                                description=f"Potential internal or administrative asset '{node.label}' ({kw}) is publicly routable to IP(s): {', '.join(resolved_ips)}.",
                                recommendation="Verify access control (SSO, IP whitelist, VPN) on this endpoint."
                            ))
                            if node.risk_level == RiskLevel.INFO:
                                node.risk_level = RiskLevel.MEDIUM
                        break

        # 2. Check for missing SPF/DMARC on Root Domains
        for node in graph.nodes.values():
            if node.type == NodeType.DOMAIN:
                txt_records = node.attributes.get("txt_records", [])
                has_spf = any("v=spf1" in txt.lower() for txt in txt_records)
                has_dmarc = any("v=dmarc1" in txt.lower() for txt in txt_records)

                if not has_spf:
                    reports.append(AnomalyReport(
                        anomaly_type="MISSING_SPF_RECORD",
                        target_id=node.id,
                        severity=RiskLevel.LOW,
                        description=f"Domain '{node.label}' lacks an SPF record, allowing email spoofing.",
                        recommendation="Configure a valid TXT SPF record (e.g. 'v=spf1 include:... -all')."
                    ))
                if not has_dmarc:
                    reports.append(AnomalyReport(
                        anomaly_type="MISSING_DMARC_RECORD",
                        target_id=node.id,
                        severity=RiskLevel.LOW,
                        description=f"Domain '{node.label}' lacks a DMARC policy record.",
                        recommendation="Add a '_dmarc' TXT record with an enforcement policy ('p=reject' or 'p=quarantine')."
                    ))

        return reports
