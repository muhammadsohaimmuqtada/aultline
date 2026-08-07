from __future__ import annotations

from aultline.graph import ApplicationGraph, stable_id
from aultline.models import Hypothesis, Impact, Pillar, TestPlan, TestStep


class TestPlanner:
    """Build the minimum sufficient validation plan for an Aultline hypothesis.

    Plans describe what evidence is required. They do not execute network traffic.
    Execution is a separate policy-controlled subsystem.
    """

    def build(self, hypothesis: Hypothesis, graph: ApplicationGraph) -> TestPlan:
        target = graph.nodes[hypothesis.target_node_id]
        if hypothesis.pillar is Pillar.AUTHORIZATION:
            return self._authorization(hypothesis, target.key)
        if hypothesis.pillar is Pillar.AUTHENTICATION:
            return self._authentication(hypothesis, target.key)
        if hypothesis.pillar is Pillar.API_OBJECT:
            return self._api_object(hypothesis, target.key)
        if hypothesis.pillar is Pillar.WORKFLOW:
            return self._workflow(hypothesis, target.key)
        raise ValueError(f"unsupported pillar: {hypothesis.pillar}")

    @staticmethod
    def _authorization(hypothesis: Hypothesis, target: str) -> TestPlan:
        steps = (
            TestStep(
                id="control-owner",
                action="replay-owned-object-control",
                target=target,
                identity_id="identity-a",
                impact=Impact.ACTIVE_SAFE,
                expected_signal="identity A can access an object owned by identity A",
            ),
            TestStep(
                id="differential-peer",
                action="compare-peer-access-to-researcher-owned-object",
                target=target,
                identity_id="identity-b",
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
        )

    @staticmethod
    def _authentication(hypothesis: Hypothesis, target: str) -> TestPlan:
        return TestPlan(
            id=stable_id("plan", {"hypothesis": hypothesis.id, "kind": "authentication"}),
            hypothesis_id=hypothesis.id,
            rationale="Compare anonymous and authenticated behavior without modifying application state.",
            steps=(
                TestStep(
                    id="anonymous-control",
                    action="observe-anonymous-response",
                    target=target,
                    identity_id="identity-anonymous",
                    impact=Impact.ACTIVE_SAFE,
                    expected_signal="baseline status/body metadata for anonymous identity",
                ),
                TestStep(
                    id="authenticated-control",
                    action="observe-authenticated-response",
                    target=target,
                    identity_id="identity-authenticated",
                    impact=Impact.ACTIVE_SAFE,
                    expected_signal="comparable status/body metadata for authenticated identity",
                ),
            ),
            maximum_impact=Impact.ACTIVE_SAFE,
            request_budget=4,
            requires_multiple_identities=True,
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
