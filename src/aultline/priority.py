from __future__ import annotations

from dataclasses import dataclass

from aultline.graph import ApplicationGraph
from aultline.models import Hypothesis, Pillar


PILLAR_WEIGHT = {
    Pillar.AUTHORIZATION: 30,
    Pillar.AUTHENTICATION: 25,
    Pillar.API_OBJECT: 20,
    Pillar.WORKFLOW: 25,
}


@dataclass(frozen=True)
class RankedHypothesis:
    hypothesis: Hypothesis
    score: int
    reasons: tuple[str, ...]


class PriorityEngine:
    """Rank hypotheses by security value without promoting their verification state."""

    def rank(self, hypotheses: list[Hypothesis], graph: ApplicationGraph) -> list[RankedHypothesis]:
        ranked: list[RankedHypothesis] = []
        for hypothesis in hypotheses:
            target = graph.nodes[hypothesis.target_node_id]
            score = PILLAR_WEIGHT[hypothesis.pillar]
            reasons = [f"{hypothesis.pillar.value} pillar"]

            method = str(target.attributes.get("method") or "GET").upper()
            if method in {"POST", "PUT", "PATCH", "DELETE"}:
                score += 15
                reasons.append("state-changing operation")

            if target.attributes.get("object_tokens"):
                score += 15
                reasons.append("object reference present")

            path = str(target.attributes.get("path") or target.key).lower()
            sensitive_terms = (
                "admin",
                "account",
                "billing",
                "payment",
                "user",
                "role",
                "tenant",
                "upload",
                "export",
                "password",
            )
            matched = sorted(term for term in sensitive_terms if term in path)
            if matched:
                score += min(20, len(matched) * 5)
                reasons.append("sensitive surface term: " + ", ".join(matched))

            score += min(20, int(hypothesis.confidence * 20))
            ranked.append(RankedHypothesis(hypothesis, min(score, 100), tuple(reasons)))

        return sorted(ranked, key=lambda item: (-item.score, item.hypothesis.id))
