"""Unit tests for InfraGraph components."""
import pytest
from infragraph.models.nodes import BaseNode, NodeType, RiskLevel
from infragraph.models.edges import BaseEdge, EdgeType
from infragraph.models.graph import InfraGraph
from infragraph.analyzer.signatures import match_cloud_signature
from infragraph.analyzer.diff import GraphDiffEngine
from infragraph.web.sample_data import generate_sample_graph


def test_graph_node_and_edge_addition():
    graph = InfraGraph(name="Test Graph")
    domain = BaseNode(id="example.com", type=NodeType.DOMAIN, label="example.com")
    subdomain = BaseNode(id="api.example.com", type=NodeType.SUBDOMAIN, label="api.example.com")
    ip = BaseNode(id="93.184.216.34", type=NodeType.IP, label="93.184.216.34")

    graph.add_node(domain)
    graph.add_node(subdomain)
    graph.add_node(ip)

    edge1 = BaseEdge(source_id="example.com", target_id="api.example.com", type=EdgeType.HAS_SUBDOMAIN)
    edge2 = BaseEdge(source_id="api.example.com", target_id="93.184.216.34", type=EdgeType.RESOLVES_TO)

    graph.add_edge(edge1)
    graph.add_edge(edge2)

    stats = graph.get_stats()
    assert stats.total_nodes == 3
    assert stats.total_edges == 2
    assert stats.domains_count == 1
    assert stats.subdomains_count == 1
    assert stats.ips_count == 1


def test_cytoscape_serialization():
    graph = generate_sample_graph()
    cyto = graph.to_cytoscape()
    assert "elements" in cyto
    assert "stats" in cyto
    assert len(cyto["elements"]) > 0


def test_cloud_signature_matching():
    # S3 Bucket
    s3_sig = match_cloud_signature("my-dangling-bucket.s3.amazonaws.com")
    assert s3_sig is not None
    assert s3_sig.service_name == "AWS S3 Bucket"

    # Azure WebApp
    azure_sig = match_cloud_signature("app-prod.azurewebsites.net")
    assert azure_sig is not None
    assert azure_sig.provider == "Azure"

    # GitHub Pages
    gh_sig = match_cloud_signature("username.github.io")
    assert gh_sig is not None
    assert gh_sig.service_name == "GitHub Pages"


def test_graph_diff_engine():
    g1 = InfraGraph(name="Snapshot 1")
    n1 = BaseNode(id="target.com", type=NodeType.DOMAIN, label="target.com")
    g1.add_node(n1)

    g2 = InfraGraph(name="Snapshot 2")
    n1_dup = BaseNode(id="target.com", type=NodeType.DOMAIN, label="target.com")
    n2 = BaseNode(id="dev.target.com", type=NodeType.SUBDOMAIN, label="dev.target.com")
    g2.add_node(n1_dup)
    g2.add_node(n2)
    g2.add_edge(BaseEdge(
        source_id="dev.target.com",
        target_id="s3-bucket.s3.amazonaws.com",
        type=EdgeType.DANGLING_TARGET
    ))

    delta = GraphDiffEngine.compare(g1, g2)
    assert len(delta.added_nodes) == 1
    assert delta.added_nodes[0].id == "dev.target.com"
    assert len(delta.new_vulnerabilities) == 1
    assert delta.new_vulnerabilities[0]["type"] == "DANGLING_TAKEOVER"
