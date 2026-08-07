import unittest

from aultline.analysis import AnalysisEngine
from aultline.importers import DedsecImporter
from aultline.models import Pillar
from aultline.planner import TestPlanner
from aultline.policy import ExecutionPolicy


class RealWorldHardeningTests(unittest.TestCase):
    def test_endpoint_asset_and_request_canonicalize_to_one_node(self):
        report = {
            "schema_version": "3.0",
            "target": {"url": "https://example.test/", "domain": "example.test"},
            "workspace": {
                "assets": [
                    {
                        "id": "asset-endpoint",
                        "kind": "endpoint",
                        "key": "GET https://example.test/api/orders/12345",
                        "attributes": {"method": "GET", "path_template": None},
                        "sources": ["browser"],
                    }
                ],
                "identities": [],
                "requests": [
                    {
                        "id": "req-1",
                        "method": "GET",
                        "url": "https://example.test/api/orders/12345",
                        "identity_id": "identity-anonymous",
                        "source": "browser",
                        "insertion_points": [],
                    }
                ],
                "observations": [],
                "edges": [],
            },
        }
        graph = DedsecImporter().ingest(report).graph
        endpoints = graph.by_kind("endpoint")
        self.assertEqual(len(endpoints), 1)
        self.assertEqual(endpoints[0].key, "GET https://example.test/api/orders/12345")
        self.assertIn("browser", endpoints[0].sources)
        self.assertIn("dedsec:request", endpoints[0].sources)

    def test_static_filename_does_not_become_object_reference(self):
        report = {
            "schema_version": "3.0",
            "target": {"url": "https://example.test/", "domain": "example.test"},
            "workspace": {
                "assets": [],
                "identities": [],
                "requests": [
                    {
                        "id": "req-image",
                        "method": "GET",
                        "url": "https://example.test/images/product-600x600.jpg",
                        "identity_id": "identity-anonymous",
                        "source": "browser",
                        "insertion_points": [],
                    },
                    {
                        "id": "req-slug",
                        "method": "GET",
                        "url": "https://example.test/case-study-2",
                        "identity_id": "identity-anonymous",
                        "source": "browser",
                        "insertion_points": [],
                    },
                ],
                "observations": [],
                "edges": [],
            },
        }
        graph = DedsecImporter().ingest(report).graph
        hypotheses = AnalysisEngine().analyze(graph)
        self.assertFalse(
            [
                hypothesis
                for hypothesis in hypotheses
                if hypothesis.pillar in {Pillar.AUTHORIZATION, Pillar.API_OBJECT}
            ]
        )

    def test_strong_numeric_object_reference_remains_detectable(self):
        report = {
            "schema_version": "3.0",
            "target": {"url": "https://example.test/", "domain": "example.test"},
            "workspace": {
                "assets": [],
                "identities": [],
                "requests": [
                    {
                        "id": "req-object",
                        "method": "GET",
                        "url": "https://example.test/api/orders/12345",
                        "identity_id": "identity-anonymous",
                        "source": "browser",
                        "insertion_points": [],
                    }
                ],
                "observations": [],
                "edges": [],
            },
        }
        graph = DedsecImporter().ingest(report).graph
        hypotheses = AnalysisEngine().analyze(graph)
        pillars = {hypothesis.pillar for hypothesis in hypotheses}
        self.assertIn(Pillar.AUTHORIZATION, pillars)
        self.assertIn(Pillar.API_OBJECT, pillars)

    def test_scope_does_not_override_missing_identity_prerequisites(self):
        report = {
            "schema_version": "3.0",
            "target": {"url": "https://example.test/", "domain": "example.test"},
            "workspace": {
                "assets": [],
                "identities": [
                    {
                        "id": "identity-user-a",
                        "authenticated": True,
                        "kind": "cookie",
                        "label": "user-a",
                    }
                ],
                "requests": [
                    {
                        "id": "req-object",
                        "method": "GET",
                        "url": "https://example.test/api/orders/12345",
                        "identity_id": "identity-user-a",
                        "source": "browser",
                        "insertion_points": [],
                    }
                ],
                "observations": [],
                "edges": [],
            },
        }
        graph = DedsecImporter().ingest(report).graph
        hypothesis = next(
            hypothesis
            for hypothesis in AnalysisEngine().analyze(graph)
            if hypothesis.pillar is Pillar.AUTHORIZATION
        )
        plan = TestPlanner().build(hypothesis, graph)
        decision = ExecutionPolicy().evaluate(plan, scope_declared=True)
        self.assertFalse(decision.allowed)
        self.assertIn("two authenticated authorized test identities", decision.reason)
        self.assertIsNone(plan.steps[1].identity_id)


if __name__ == "__main__":
    unittest.main()
