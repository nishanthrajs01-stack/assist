"""Differential Graph Comparator for InfraGraph Snapshots."""
from typing import Dict, List, Any, Set
from pydantic import BaseModel, Field

from infragraph.models.graph import InfraGraph
from infragraph.models.nodes import BaseNode, NodeType, RiskLevel
from infragraph.models.edges import BaseEdge, EdgeType


class GraphDelta(BaseModel):
    old_snapshot_name: str
    new_snapshot_name: str
    added_nodes: List[BaseNode] = Field(default_factory=list)
    removed_nodes: List[BaseNode] = Field(default_factory=list)
    added_edges: List[BaseEdge] = Field(default_factory=list)
    removed_edges: List[BaseEdge] = Field(default_factory=list)
    new_vulnerabilities: List[Dict[str, Any]] = Field(default_factory=list)
    resolved_vulnerabilities: List[Dict[str, Any]] = Field(default_factory=list)


class GraphDiffEngine:
    @staticmethod
    def compare(old_graph: InfraGraph, new_graph: InfraGraph) -> GraphDelta:
        delta = GraphDelta(
            old_snapshot_name=old_graph.name,
            new_snapshot_name=new_graph.name
        )

        old_node_ids = set(old_graph.nodes.keys())
        new_node_ids = set(new_graph.nodes.keys())

        # Added & Removed Nodes
        for nid in new_node_ids - old_node_ids:
            delta.added_nodes.append(new_graph.nodes[nid])

        for nid in old_node_ids - new_node_ids:
            delta.removed_nodes.append(old_graph.nodes[nid])

        # Added & Removed Edges
        old_edge_keys = set(old_graph.edges.keys())
        new_edge_keys = set(new_graph.edges.keys())

        for ekey in new_edge_keys - old_edge_keys:
            edge = new_graph.edges[ekey]
            delta.added_edges.append(edge)
            if edge.type == EdgeType.DANGLING_TARGET:
                delta.new_vulnerabilities.append({
                    "subdomain": edge.source_id,
                    "target": edge.target_id,
                    "type": "DANGLING_TAKEOVER",
                    "details": edge.attributes
                })

        for ekey in old_edge_keys - new_edge_keys:
            edge = old_graph.edges[ekey]
            delta.removed_edges.append(edge)
            if edge.type == EdgeType.DANGLING_TARGET:
                delta.resolved_vulnerabilities.append({
                    "subdomain": edge.source_id,
                    "target": edge.target_id,
                    "type": "DANGLING_TAKEOVER_RESOLVED",
                    "details": edge.attributes
                })

        return delta
