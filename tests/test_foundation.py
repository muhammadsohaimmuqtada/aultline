import unittest

from aultline.analysis import AnalysisEngine
from aultline.importers import DedsecImporter
from aultline.models import HypothesisState, Impact, Pillar
from aultline.planner import TestPlanner
from aultline.policy import ExecutionPolicy
from aultline.priority import PriorityEngine


DEDSEC_FIXTURE = {
    "schema_version": "3.0",
    "scan_id": "scan-test",
    "target": {"url": "https://example.test/", "domain": "example.test"},
    "workspace": {
        "assets": [],
        "edges": [],
        "observations": [],
        "identities": [
            {
                "id": "identity-anonymous",
                "label": "anonymous",
                "kind": "anonymous",
                "role": None,
                "tenant": None,
                "authenticated": False,
            },
            {
                "id": "identity-user-a",
                "label": "user-a",
                "kind": "cookie",
                "role": "user",
                "tenant": "tenant-a",
                "authenticated": True,
            },
            {
                "id": "identity-user-b",
                "label": "user-b",
                "kind": "cookie",
                "role": "user",
                "tenant": "tenant-b",
                "authenticated": True,
            },
        ],
        "requests": [
            {
                "id": "req-anon",
                "method": "GET",
                "url": "https://example.test/api/orders/12345?user_id=7",
                "identity_id": "identity-anonymous",
                "source": "crawler",
                "tags": ["crawl"],
                "metadata": {},
                "insertion_points": [
                    {
                        "id": "point-1",
                        "location": "query",
                        "name": "user_id",
                        "value": "7",
                        "source": "crawler",
                    }
                ],
            },
            {
                "id": "req-auth",
                "method": "GET",
                "url": "https://example.test/api/orders/12345?user_id=7",
                "identity_id": "identity-user-a",
                "source": "browser",
                "tags": ["browser-observed"],
                "metadata": {},
                "insertion_points": [
                    {
                        "id": "point-1",
                        "location": "query",
                        "name": "user_id",
                        "value": "7",
                        "source": "browser",
                    }
                ],
            },
            {
                "id": "req-post",
                "method": "POST",
                "url": "https://example.test/api/orders/12345/cancel",
                "identity_id": "identity-user-a",
                "source": "openapi",
                "tags": ["recorded-not-executed"],
                "metadata": {},
                "insertion_points": [],
            },
        ],
    },
    "project_diff": {
        "baseline_scan_id": "scan-before",
        "current_scan_id": "scan-test",
        "assets": {"new": [], "changed": [], "removed": []},
    },
}


class FoundationTests(unittest.TestCase):
    def setUp(self):
        self.imported = DedsecImporter().ingest(DEDSEC_FIXTURE)
        self.graph = self.imported.graph

    def test_dedsec_import_builds_shared_graph(self):
        self.assertEqual(self.imported.schema_version, "3.0")
        self.assertGreaterEqual(len(self.graph.by_kind("endpoint")), 2)
        self.assertEqual(len(self.graph.by_kind("identity")), 3)
        self.assertEqual(len(self.graph.by_kind("historical-diff")), 1)

    def test_four_pillars_generate_conservative_hypotheses(self):
        hypotheses = AnalysisEngine().analyze(self.graph)
        pillars = {hypothesis.pillar for hypothesis in hypotheses}
        self.assertEqual(
            pillars,
            {
                Pillar.AUTHORIZATION,
                Pillar.AUTHENTICATION,
                Pillar.API_OBJECT,
                Pillar.WORKFLOW,
            },
        )
        self.assertTrue(all(h.state is HypothesisState.UNVERIFIED for h in hypotheses))

    def test_priority_does_not_promote_state(self):
        hypotheses = AnalysisEngine().analyze(self.graph)
        ranked = PriorityEngine().rank(hypotheses, self.graph)
        self.assertTrue(ranked)
        self.assertTrue(all(item.hypothesis.state is HypothesisState.UNVERIFIED for item in ranked))
        self.assertGreaterEqual(ranked[0].score, ranked[-1].score)

    def test_authorization_plan_requires_multiple_identities(self):
        hypothesis = next(
            h for h in AnalysisEngine().analyze(self.graph) if h.pillar is Pillar.AUTHORIZATION
        )
        plan = TestPlanner().build(hypothesis, self.graph)
        self.assertTrue(plan.requires_multiple_identities)
        self.assertFalse(plan.missing_prerequisites)
        self.assertEqual(plan.maximum_impact, Impact.ACTIVE_SAFE)
        self.assertLessEqual(plan.request_budget, 4)
        identities = {step.identity_id for step in plan.steps}
        self.assertEqual(identities, {"identity-user-a", "identity-user-b"})

    def test_policy_requires_declared_scope(self):
        hypothesis = next(
            h for h in AnalysisEngine().analyze(self.graph) if h.pillar is Pillar.AUTHORIZATION
        )
        plan = TestPlanner().build(hypothesis, self.graph)
        policy = ExecutionPolicy()
        self.assertFalse(policy.evaluate(plan, scope_declared=False).allowed)
        self.assertTrue(policy.evaluate(plan, scope_declared=True).allowed)

    def test_hypothesis_lifecycle_blocks_false_promotion(self):
        hypothesis = AnalysisEngine().analyze(self.graph)[0]
        with self.assertRaises(ValueError):
            hypothesis.transition(HypothesisState.VERIFIED, "no supporting state")
        hypothesis.transition(HypothesisState.SUPPORTED, "control evidence collected")
        hypothesis.transition(HypothesisState.VERIFIED, "reproducible differential evidence")
        self.assertEqual(hypothesis.state, HypothesisState.VERIFIED)


if __name__ == "__main__":
    unittest.main()
