from __future__ import annotations

import hashlib
import json
from collections import defaultdict
from collections.abc import Iterable
from typing import Any

from aultline.models import GraphEdge, GraphNode


def stable_id(prefix: str, value: Any) -> str:
    rendered = json.dumps(value, sort_keys=True, separators=(",", ":"), default=str)
    digest = hashlib.sha256(rendered.encode("utf-8")).hexdigest()[:24]
    return f"{prefix}-{digest}"


class ApplicationGraph:
    """Normalized application-security graph shared by every Aultline pillar."""

    def __init__(self) -> None:
        self.nodes: dict[str, GraphNode] = {}
        self.edges: dict[str, GraphEdge] = {}
        self._kind_index: dict[str, set[str]] = defaultdict(set)
        self._out_index: dict[str, set[str]] = defaultdict(set)
        self._in_index: dict[str, set[str]] = defaultdict(set)

    def upsert_node(
        self,
        kind: str,
        key: str,
        *,
        attributes: dict[str, Any] | None = None,
        sources: Iterable[str] = (),
        node_id: str | None = None,
    ) -> GraphNode:
        normalized_kind = kind.strip().lower()
        normalized_key = str(key).strip()
        identifier = node_id or stable_id("node", {"kind": normalized_kind, "key": normalized_key})
        previous = self.nodes.get(identifier)
        merged_attributes = dict(previous.attributes) if previous else {}
        merged_attributes.update(attributes or {})
        merged_sources = set(previous.sources if previous else ())
        merged_sources.update(str(source) for source in sources if source)
        node = GraphNode(
            id=identifier,
            kind=normalized_kind,
            key=normalized_key,
            attributes=merged_attributes,
            sources=tuple(sorted(merged_sources)),
        )
        self.nodes[identifier] = node
        self._kind_index[normalized_kind].add(identifier)
        return node

    def link(
        self,
        source_id: str,
        target_id: str,
        relation: str,
        *,
        attributes: dict[str, Any] | None = None,
        edge_id: str | None = None,
    ) -> GraphEdge:
        if source_id not in self.nodes or target_id not in self.nodes:
            raise KeyError("both graph nodes must exist before an edge is created")
        normalized_relation = relation.strip().lower()
        identifier = edge_id or stable_id(
            "edge",
            {"source": source_id, "target": target_id, "relation": normalized_relation},
        )
        previous = self.edges.get(identifier)
        merged = dict(previous.attributes) if previous else {}
        merged.update(attributes or {})
        edge = GraphEdge(identifier, source_id, target_id, normalized_relation, merged)
        self.edges[identifier] = edge
        self._out_index[source_id].add(identifier)
        self._in_index[target_id].add(identifier)
        return edge

    def by_kind(self, kind: str) -> list[GraphNode]:
        return [self.nodes[node_id] for node_id in sorted(self._kind_index.get(kind.lower(), set()))]

    def outgoing(self, node_id: str, relation: str | None = None) -> list[GraphEdge]:
        edges = [self.edges[edge_id] for edge_id in self._out_index.get(node_id, set())]
        if relation is not None:
            edges = [edge for edge in edges if edge.relation == relation.lower()]
        return sorted(edges, key=lambda edge: edge.id)

    def incoming(self, node_id: str, relation: str | None = None) -> list[GraphEdge]:
        edges = [self.edges[edge_id] for edge_id in self._in_index.get(node_id, set())]
        if relation is not None:
            edges = [edge for edge in edges if edge.relation == relation.lower()]
        return sorted(edges, key=lambda edge: edge.id)

    def snapshot(self) -> dict[str, Any]:
        return {
            "nodes": [self.nodes[node_id].public_dict() for node_id in sorted(self.nodes)],
            "edges": [self.edges[edge_id].public_dict() for edge_id in sorted(self.edges)],
            "counts": {
                "nodes": len(self.nodes),
                "edges": len(self.edges),
                "kinds": {kind: len(ids) for kind, ids in sorted(self._kind_index.items())},
            },
        }
