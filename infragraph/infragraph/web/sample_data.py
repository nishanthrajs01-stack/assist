"""Sample attack surface graph generator for demonstration."""
from infragraph.models.nodes import BaseNode, NodeType, RiskLevel
from infragraph.models.edges import BaseEdge, EdgeType
from infragraph.models.graph import InfraGraph


def generate_sample_graph() -> InfraGraph:
    graph = InfraGraph(name="Demo Target: security-bounty-target.com")

    # Apex Domain
    graph.add_node(BaseNode(
        id="security-bounty-target.com",
        type=NodeType.DOMAIN,
        label="security-bounty-target.com",
        attributes={"is_apex": True, "txt_records": ["v=spf1 include:_spf.google.com ~all"]}
    ))

    # Subdomains
    subdomains = [
        ("api.security-bounty-target.com", RiskLevel.INFO, "API Gateway"),
        ("dev-auth.security-bounty-target.com", RiskLevel.MEDIUM, "Exposed Dev SSO"),
        ("assets.security-bounty-target.com", RiskLevel.INFO, "Static CDN Assets"),
        ("blog.security-bounty-target.com", RiskLevel.CRITICAL, "Dangling S3 Bucket"),
        ("docs.security-bounty-target.com", RiskLevel.HIGH, "Dangling GitHub Pages"),
        ("payments.security-bounty-target.com", RiskLevel.INFO, "Stripe Proxy"),
        ("staging-portal.security-bounty-target.com", RiskLevel.HIGH, "Exposed Staging"),
        ("vpn.security-bounty-target.com", RiskLevel.MEDIUM, "Corporate Gateway"),
        ("marketing.security-bounty-target.com", RiskLevel.INFO, "Campaign Landing"),
        ("legacy-metrics.security-bounty-target.com", RiskLevel.HIGH, "Dangling Azure WebApp")
    ]

    for sub_id, risk, desc in subdomains:
        graph.add_node(BaseNode(
            id=sub_id,
            type=NodeType.SUBDOMAIN,
            label=sub_id,
            risk_level=risk,
            attributes={"description": desc}
        ))
        graph.add_edge(BaseEdge(
            source_id="security-bounty-target.com",
            target_id=sub_id,
            type=EdgeType.HAS_SUBDOMAIN,
            label="subdomain"
        ))

    # CNAME relationships & Cloud Targets
    # 1. Dangling S3
    s3_target = "security-bounty-blog.s3.amazonaws.com"
    graph.add_node(BaseNode(
        id=s3_target,
        type=NodeType.CLOUD_RESOURCE,
        label=f"AWS S3 ({s3_target})",
        risk_level=RiskLevel.CRITICAL,
        attributes={"provider": "AWS", "service": "S3 Bucket", "bucket_status": "NoSuchBucket"}
    ))
    graph.add_edge(BaseEdge(
        source_id="blog.security-bounty-target.com",
        target_id=s3_target,
        type=EdgeType.DANGLING_TARGET,
        label="🚨 DANGLING S3 TAKEOVER",
        attributes={
            "evidence": "CNAME points to non-existent AWS S3 bucket 'security-bounty-blog'. HTTP 404 NoSuchBucket returned.",
            "remediation": "Claim bucket in AWS S3 or remove DNS CNAME record."
        }
    ))

    # 2. Dangling GitHub Pages
    gh_target = "target-security.github.io"
    graph.add_node(BaseNode(
        id=gh_target,
        type=NodeType.CLOUD_RESOURCE,
        label=f"GitHub Pages ({gh_target})",
        risk_level=RiskLevel.HIGH,
        attributes={"provider": "GitHub", "service": "GitHub Pages", "status": "404 Not Found"}
    ))
    graph.add_edge(BaseEdge(
        source_id="docs.security-bounty-target.com",
        target_id=gh_target,
        type=EdgeType.DANGLING_TARGET,
        label="🚨 DANGLING GITHUB PAGES",
        attributes={
            "evidence": "CNAME points to unclaimed GitHub Pages repo. Returns '404 There isn't a GitHub Pages site here.'",
            "remediation": "Claim repository or delete the CNAME record."
        }
    ))

    # 3. Dangling Azure App
    azure_target = "target-metrics-app.azurewebsites.net"
    graph.add_node(BaseNode(
        id=azure_target,
        type=NodeType.CLOUD_RESOURCE,
        label=f"Azure App Service ({azure_target})",
        risk_level=RiskLevel.CRITICAL,
        attributes={"provider": "Azure", "service": "App Service", "status": "404 Web Site not found"}
    ))
    graph.add_edge(BaseEdge(
        source_id="legacy-metrics.security-bounty-target.com",
        target_id=azure_target,
        type=EdgeType.DANGLING_TARGET,
        label="🚨 DANGLING AZURE TAKEOVER",
        attributes={
            "evidence": "CNAME points to deleted Azure App Service. Web App Not Found.",
            "remediation": "Claim Azure App Service name in Azure Portal or delete DNS record."
        }
    ))

    # IPs & ASNs
    ips = [
        ("104.21.45.12", "AS13335", "Cloudflare, Inc.", "104.21.0.0/16"),
        ("172.67.180.5", "AS13335", "Cloudflare, Inc.", "172.67.0.0/16"),
        ("52.216.14.88", "AS16509", "Amazon.com, Inc.", "52.216.0.0/15"),
        ("34.120.90.11", "AS15169", "Google LLC", "34.120.0.0/16"),
        ("198.51.100.42", "AS20940", "Akamai Technologies", "198.51.100.0/24")
    ]

    for ip, asn, owner, cidr in ips:
        graph.add_node(BaseNode(
            id=ip,
            type=NodeType.IP,
            label=ip,
            attributes={"asn": asn, "owner": owner, "cidr": cidr}
        ))
        graph.add_node(BaseNode(
            id=asn,
            type=NodeType.ASN,
            label=f"{asn} ({owner})",
            attributes={"owner": owner}
        ))
        graph.add_edge(BaseEdge(
            source_id=ip,
            target_id=asn,
            type=EdgeType.BELONGS_TO_ASN,
            label=f"ASN ({cidr})"
        ))

    # Connect subdomains to IPs
    graph.add_edge(BaseEdge(source_id="api.security-bounty-target.com", target_id="104.21.45.12", type=EdgeType.RESOLVES_TO, label="A"))
    graph.add_edge(BaseEdge(source_id="security-bounty-target.com", target_id="104.21.45.12", type=EdgeType.RESOLVES_TO, label="A"))
    graph.add_edge(BaseEdge(source_id="security-bounty-target.com", target_id="172.67.180.5", type=EdgeType.RESOLVES_TO, label="A"))
    graph.add_edge(BaseEdge(source_id="dev-auth.security-bounty-target.com", target_id="34.120.90.11", type=EdgeType.RESOLVES_TO, label="A"))
    graph.add_edge(BaseEdge(source_id="staging-portal.security-bounty-target.com", target_id="34.120.90.11", type=EdgeType.RESOLVES_TO, label="A"))
    graph.add_edge(BaseEdge(source_id="vpn.security-bounty-target.com", target_id="198.51.100.42", type=EdgeType.RESOLVES_TO, label="A"))

    return graph
