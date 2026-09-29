"""Core Graph Container for InfraGraph."""
import json
from typing import Dict, List, Optional, Any
import networkx as nx
from datetime import datetime, timezone
from pydantic import BaseModel, Field

from infragraph.models.nodes import BaseNode, NodeType, RiskLevel
from infragraph.models.edges import BaseEdge, EdgeType


class GraphStats(BaseModel):
    total_nodes: int = 0
    total_edges: int = 0
    domains_count: int = 0
    subdomains_count: int = 0
    ips_count: int = 0
    asns_count: int = 0
    cloud_resources_count: int = 0
    dangling_records_count: int = 0
    critical_findings_count: int = 0


class InfraGraph:
    def __init__(self, name: str = "InfraGraph Snapshot"):
        self.name = name
        self.created_at = datetime.now(timezone.utc).isoformat()
        self.nodes: Dict[str, BaseNode] = {}
        self.edges: Dict[str, BaseEdge] = {}
        self._nx_graph: nx.DiGraph = nx.DiGraph()

    def add_node(self, node: BaseNode) -> BaseNode:
        if node.id in self.nodes:
            existing = self.nodes[node.id]
            existing.update_seen()
            existing.attributes.update(node.attributes)
            if node.risk_level.value != RiskLevel.INFO.value:
                existing.risk_level = node.risk_level
            return existing
        self.nodes[node.id] = node
        self._nx_graph.add_node(node.id, **node.model_dump())
        return node

    def add_edge(self, edge: BaseEdge) -> BaseEdge:
        key = edge.key
        if key in self.edges:
            return self.edges[key]
        
        # Ensure source and target exist in nx
        if edge.source_id not in self._nx_graph:
            self._nx_graph.add_node(edge.source_id)
        if edge.target_id not in self._nx_graph:
            self._nx_graph.add_node(edge.target_id)

        self.edges[key] = edge
        dump = edge.model_dump()
        dump["type"] = edge.type.value
        dump["label"] = edge.label or edge.type.value
        dump["key"] = key
        self._nx_graph.add_edge(
            edge.source_id,
            edge.target_id,
            **dump
        )
        return edge

    def get_node(self, node_id: str) -> Optional[BaseNode]:
        return self.nodes.get(node_id)

    def get_stats(self) -> GraphStats:
        stats = GraphStats(
            total_nodes=len(self.nodes),
            total_edges=len(self.edges)
        )
        for node in self.nodes.values():
            if node.type == NodeType.DOMAIN:
                stats.domains_count += 1
            elif node.type == NodeType.SUBDOMAIN:
                stats.subdomains_count += 1
            elif node.type == NodeType.IP:
                stats.ips_count += 1
            elif node.type == NodeType.ASN:
                stats.asns_count += 1
            elif node.type == NodeType.CLOUD_RESOURCE:
                stats.cloud_resources_count += 1
            if node.risk_level in [RiskLevel.CRITICAL, RiskLevel.HIGH]:
                stats.critical_findings_count += 1

        for edge in self.edges.values():
            if edge.type == EdgeType.DANGLING_TARGET:
                stats.dangling_records_count += 1

        return stats

    def to_cytoscape(self) -> Dict[str, Any]:
        """Convert graph into Cytoscape.js format for frontend visualization."""
        elements = []
        for node in self.nodes.values():
            elements.append({
                "data": {
                    "id": node.id,
                    "label": node.label,
                    "type": node.type.value,
                    "risk": node.risk_level.value,
                    "attributes": node.attributes,
                    "first_seen": node.first_seen,
                    "last_seen": node.last_seen
                }
            })

        for edge in self.edges.values():
            elements.append({
                "data": {
                    "id": edge.key,
                    "source": edge.source_id,
                    "target": edge.target_id,
                    "type": edge.type.value,
                    "label": edge.label or edge.type.value,
                    "confidence": edge.confidence,
                    "attributes": edge.attributes
                }
            })

        return {
            "name": self.name,
            "created_at": self.created_at,
            "stats": self.get_stats().model_dump(),
            "elements": elements
        }

    def to_dict(self) -> Dict[str, Any]:
        return {
            "name": self.name,
            "created_at": self.created_at,
            "stats": self.get_stats().model_dump(),
            "nodes": [n.model_dump() for n in self.nodes.values()],
            "edges": [e.model_dump() for e in self.edges.values()]
        }

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "InfraGraph":
        graph = cls(name=data.get("name", "Imported Graph"))
        graph.created_at = data.get("created_at", datetime.now(timezone.utc).isoformat())
        for n_data in data.get("nodes", []):
            graph.add_node(BaseNode(**n_data))
        for e_data in data.get("edges", []):
            graph.add_edge(BaseEdge(**e_data))
        return graph

    def to_json(self, indent: int = 2) -> str:
        return json.dumps(self.to_dict(), indent=indent)

    @classmethod
    def from_json(cls, json_str: str) -> "InfraGraph":
        return cls.from_dict(json.loads(json_str))

    def to_dot(self) -> str:
        """Export as Graphviz DOT format."""
        lines = ["digraph InfraGraph {", '  rankdir="LR";', '  node [shape=box, style=filled, fontname="Arial"];']
        
        color_map = {
            NodeType.ORGANIZATION: "#f6e05e",
            NodeType.DOMAIN: "#63b3ed",
            NodeType.SUBDOMAIN: "#90cdf4",
            NodeType.IP: "#68d391",
            NodeType.ASN: "#b794f4",
            NodeType.CLOUD_RESOURCE: "#f6ad55",
            NodeType.DNS_RECORD: "#cbd5e0"
        }

        for node in self.nodes.values():
            fill = color_map.get(node.type, "#edf2f7")
            if node.risk_level == RiskLevel.CRITICAL:
                fill = "#feb2b2"
            lines.append(f'  "{node.id}" [label="{node.label}\\n({node.type.value})", fillcolor="{fill}"];')

        for edge in self.edges.values():
            style = 'color="#e53e3e", penwidth=2' if edge.type == EdgeType.DANGLING_TARGET else 'color="#718096"'
            lines.append(f'  "{edge.source_id}" -> "{edge.target_id}" [label="{edge.label}", {style}];')

        lines.append("}")
        return "\n".join(lines)
