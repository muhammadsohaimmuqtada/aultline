from __future__ import annotations

from collections import defaultdict
from collections.abc import Iterable

from aultline.graph import ApplicationGraph, stable_id
from aultline.models import EvidenceRef, Hypothesis, Pillar


def _evidence(source: str, summary: str, locator: str | None = None) -> EvidenceRef:
    return EvidenceRef(
        id=stable_id("evidence", {"source": source, "summary": summary, "locator": locator}),
        kind="surface-observation",
        source=source,
        locator=locator,
        summary=summary,
    )


class AnalysisEngine:
    """Generate conservative, evidence-backed hypotheses across the four v1 pillars."""

    def analyze(self, graph: ApplicationGraph) -> list[Hypothesis]:
        hypotheses: list[Hypothesis] = []
        hypotheses.extend(self._authorization(graph))
        hypotheses.extend(self._authentication(graph))
        hypotheses.extend(self._api_object(graph))
        hypotheses.extend(self._workflow(graph))
        return self._deduplicate(hypotheses)

    def _authorization(self, graph: ApplicationGraph) -> Iterable[Hypothesis]:
        identities = graph.by_kind("identity")
        identity_count = len(identities)
        for endpoint in graph.by_kind("endpoint"):
            object_tokens = endpoint.attributes.get("object_tokens") or []
            if not object_tokens:
                continue
            confidence = 0.45 if identity_count < 2 else 0.6
            yield Hypothesis(
                id=stable_id("hyp", {"pillar": "authorization", "endpoint": endpoint.id}),
                pillar=Pillar.AUTHORIZATION,
                category="object-authorization",
                title="Object authorization boundary requires differential validation",
                target_node_id=endpoint.id,
                rationale=(
                    "The endpoint contains object-like identifiers. Aultline does not infer an IDOR/BOLA "
                    "from naming alone; it requires an ownership or role differential before promotion."
                ),
                confidence=confidence,
                evidence=[
                    _evidence(
                        "surface-graph",
                        f"object-like reference(s) observed: {', '.join(map(str, object_tokens[:5]))}",
                        endpoint.key,
                    )
                ],
            )

    def _authentication(self, graph: ApplicationGraph) -> Iterable[Hypothesis]:
        endpoint_identities: dict[str, set[str]] = defaultdict(set)
        identity_nodes = {node.id: node for node in graph.by_kind("identity")}
        for identity_id in identity_nodes:
            for edge in graph.outgoing(identity_id, "observed_endpoint"):
                endpoint_identities[edge.target_id].add(identity_id)

        for endpoint_id, identity_ids in endpoint_identities.items():
            if len(identity_ids) < 2:
                continue
            endpoint = graph.nodes[endpoint_id]
            auth_states = {
                bool(identity_nodes[identity_id].attributes.get("authenticated"))
                for identity_id in identity_ids
            }
            if len(auth_states) < 2:
                continue
            yield Hypothesis(
                id=stable_id("hyp", {"pillar": "authentication", "endpoint": endpoint.id}),
                pillar=Pillar.AUTHENTICATION,
                category="auth-state-differential",
                title="Endpoint observed across anonymous and authenticated contexts",
                target_node_id=endpoint.id,
                rationale=(
                    "The same endpoint is represented in more than one authentication state. "
                    "Behavior must be compared before any authentication-control conclusion is made."
                ),
                confidence=0.55,
                evidence=[
                    _evidence(
                        "identity-graph",
                        f"endpoint mapped to {len(identity_ids)} identity contexts",
                        endpoint.key,
                    )
                ],
            )

    def _api_object(self, graph: ApplicationGraph) -> Iterable[Hypothesis]:
        for endpoint in graph.by_kind("endpoint"):
            inputs = graph.outgoing(endpoint.id, "accepts_input")
            object_tokens = endpoint.attributes.get("object_tokens") or []
            if not inputs and not object_tokens:
                continue
            yield Hypothesis(
                id=stable_id("hyp", {"pillar": "api-object", "endpoint": endpoint.id}),
                pillar=Pillar.API_OBJECT,
                category="resource-modeling",
                title="Endpoint participates in an object or parameterized API surface",
                target_node_id=endpoint.id,
                rationale=(
                    "Parameterized or object-referencing endpoints are candidates for resource ownership, "
                    "parent-child relationship, and CRUD capability modeling."
                ),
                confidence=0.5,
                evidence=[
                    _evidence(
                        "surface-graph",
                        f"{len(inputs)} input node(s), {len(object_tokens)} object-like token(s)",
                        endpoint.key,
                    )
                ],
            )

    def _workflow(self, graph: ApplicationGraph) -> Iterable[Hypothesis]:
        state_changing = {"POST", "PUT", "PATCH", "DELETE"}
        for endpoint in graph.by_kind("endpoint"):
            method = str(endpoint.attributes.get("method") or "GET").upper()
            if method not in state_changing:
                continue
            yield Hypothesis(
                id=stable_id("hyp", {"pillar": "workflow", "endpoint": endpoint.id}),
                pillar=Pillar.WORKFLOW,
                category="state-transition-modeling",
                title="State-changing operation requires workflow prerequisite modeling",
                target_node_id=endpoint.id,
                rationale=(
                    "A state-changing operation is known to the surface graph. Aultline should model its "
                    "preconditions and valid transitions before considering any active execution."
                ),
                confidence=0.5,
                evidence=[
                    _evidence("surface-graph", f"state-changing method observed: {method}", endpoint.key)
                ],
            )

    @staticmethod
    def _deduplicate(hypotheses: Iterable[Hypothesis]) -> list[Hypothesis]:
        unique = {hypothesis.id: hypothesis for hypothesis in hypotheses}
        return [unique[key] for key in sorted(unique)]
