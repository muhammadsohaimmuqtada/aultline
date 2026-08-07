from __future__ import annotations

from aultline.graph import ApplicationGraph, stable_id
from aultline.models import GraphNode, Hypothesis, Impact, Pillar, TestPlan, TestStep


class TestPlanner:
    """Build the minimum sufficient validation plan for an Aultline hypothesis.

    Plans describe what evidence is required. They do not execute network traffic.
    Execution is a separate policy-controlled subsystem.
    """

    def build(self, hypothesis: Hypothesis, graph: ApplicationGraph) -> TestPlan:
        target = graph.nodes[hypothesis.target_node_id]
        if hypothesis.pillar is Pillar.AUTHORIZATION:
            return self._authorization(hypothesis, target.key, graph)
        if hypothesis.pillar is Pillar.AUTHENTICATION:
            return self._authentication(hypothesis, target, graph)
        if hypothesis.pillar is Pillar.API_OBJECT:
            return self._api_object(hypothesis, target.key)
        if hypothesis.pillar is Pillar.WORKFLOW:
            return self._workflow(hypothesis, target.key)
        raise ValueError(f"unsupported pillar: {hypothesis.pillar}")

    @staticmethod
    def _authorization(
        hypothesis: Hypothesis,
        target: str,
        graph: ApplicationGraph,
    ) -> TestPlan:
        authenticated = sorted(
            (
                node
                for node in graph.by_kind("identity")
                if bool(node.attributes.get("authenticated"))
            ),
            key=lambda node: node.key,
        )
        missing: list[str] = []
        if len(authenticated) < 2:
            missing.append("two authenticated authorized test identities")

        owner_id = authenticated[0].key if authenticated else None
        peer_id = authenticated[1].key if len(authenticated) > 1 else None
        steps = (
            TestStep(
                id="control-owner",
                action="replay-owned-object-control",
                target=target,
                identity_id=owner_id,
                impact=Impact.ACTIVE_SAFE,
                expected_signal="identity A can access an object owned by identity A",
            ),
            TestStep(
                id="differential-peer",
                action="compare-peer-access-to-researcher-owned-object",
                target=target,
                identity_id=peer_id,
                impact=Impact.ACTIVE_SAFE,
                expected_signal="authorization result differs for the non-owner identity",
                notes="Use only researcher-controlled test objects and authorized identities.",
            ),
        )
        return TestPlan(
            id=stable_id("plan", {"hypothesis": hypothesis.id, "kind": "authorization"}),
            hypothesis_id=hypothesis.id,
            rationale="Use an owner/non-owner differential with a positive control before promotion.",
            steps=steps,
            maximum_impact=Impact.ACTIVE_SAFE,
            request_budget=4,
            requires_multiple_identities=True,
            prerequisites=(
                "two authenticated authorized test identities",
                "a researcher-controlled object with known ownership",
            ),
            missing_prerequisites=tuple(missing),
        )

    @staticmethod
    def _authentication(
        hypothesis: Hypothesis,
        target: GraphNode,
        graph: ApplicationGraph,
    ) -> TestPlan:
        mapped_identity_nodes: list[GraphNode] = []
        for edge in graph.incoming(target.id, "observed_endpoint"):
            node = graph.nodes.get(edge.source_id)
            if node and node.kind == "identity":
                mapped_identity_nodes.append(node)

        anonymous = sorted(
            (node for node in mapped_identity_nodes if not bool(node.attributes.get("authenticated"))),
            key=lambda node: node.key,
        )
        authenticated = sorted(
            (node for node in mapped_identity_nodes if bool(node.attributes.get("authenticated"))),
            key=lambda node: node.key,
        )
        missing: list[str] = []
        if not anonymous:
            missing.append("an anonymous identity observation for the target endpoint")
        if not authenticated:
            missing.append("an authenticated identity observation for the target endpoint")

        return TestPlan(
            id=stable_id("plan", {"hypothesis": hypothesis.id, "kind": "authentication"}),
            hypothesis_id=hypothesis.id,
            rationale="Compare anonymous and authenticated behavior without modifying application state.",
            steps=(
                TestStep(
                    id="anonymous-control",
                    action="observe-anonymous-response",
                    target=target.key,
                    identity_id=anonymous[0].key if anonymous else None,
                    impact=Impact.ACTIVE_SAFE,
                    expected_signal="baseline status/body metadata for anonymous identity",
                ),
                TestStep(
                    id="authenticated-control",
                    action="observe-authenticated-response",
                    target=target.key,
                    identity_id=authenticated[0].key if authenticated else None,
                    impact=Impact.ACTIVE_SAFE,
                    expected_signal="comparable status/body metadata for authenticated identity",
                ),
            ),
            maximum_impact=Impact.ACTIVE_SAFE,
            request_budget=4,
            requires_multiple_identities=True,
            prerequisites=(
                "anonymous and authenticated observations for the same endpoint",
            ),
            missing_prerequisites=tuple(missing),
        )

    @staticmethod
    def _api_object(hypothesis: Hypothesis, target: str) -> TestPlan:
        return TestPlan(
            id=stable_id("plan", {"hypothesis": hypothesis.id, "kind": "api-object"}),
            hypothesis_id=hypothesis.id,
            rationale="Model resource identifiers, ownership, and parent-child constraints before validation.",
            steps=(
                TestStep(
                    id="model-resource",
                    action="derive-resource-relationship",
                    target=target,
                    impact=Impact.PASSIVE,
                    expected_signal="resource/object relationship documented from existing evidence",
                ),
            ),
            maximum_impact=Impact.PASSIVE,
            request_budget=1,
        )

    @staticmethod
    def _workflow(hypothesis: Hypothesis, target: str) -> TestPlan:
        return TestPlan(
            id=stable_id("plan", {"hypothesis": hypothesis.id, "kind": "workflow"}),
            hypothesis_id=hypothesis.id,
            rationale=(
                "Reconstruct prerequisites and state transitions passively first; do not execute a "
                "state-changing operation under the default policy."
            ),
            steps=(
                TestStep(
                    id="model-preconditions",
                    action="infer-workflow-preconditions",
                    target=target,
                    impact=Impact.PASSIVE,
                    expected_signal="candidate predecessor and successor states documented",
                ),
            ),
            maximum_impact=Impact.PASSIVE,
            request_budget=1,
        )
