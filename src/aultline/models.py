from __future__ import annotations

from dataclasses import asdict, dataclass, field
from enum import Enum
from typing import Any


class Pillar(str, Enum):
    AUTHORIZATION = "authorization"
    AUTHENTICATION = "authentication"
    API_OBJECT = "api-object"
    WORKFLOW = "workflow"


class HypothesisState(str, Enum):
    UNVERIFIED = "unverified"
    SUPPORTED = "supported"
    VERIFIED = "verified"
    REJECTED = "rejected"


class Impact(str, Enum):
    PASSIVE = "passive"
    NORMAL = "normal"
    ACTIVE_SAFE = "active-safe"
    STATE_CHANGING = "state-changing"
    HIGH_IMPACT = "high-impact"


IMPACT_ORDER = {
    Impact.PASSIVE: 0,
    Impact.NORMAL: 1,
    Impact.ACTIVE_SAFE: 2,
    Impact.STATE_CHANGING: 3,
    Impact.HIGH_IMPACT: 4,
}


@dataclass(frozen=True)
class GraphNode:
    id: str
    kind: str
    key: str
    attributes: dict[str, Any] = field(default_factory=dict)
    sources: tuple[str, ...] = ()

    def public_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass(frozen=True)
class GraphEdge:
    id: str
    source_id: str
    target_id: str
    relation: str
    attributes: dict[str, Any] = field(default_factory=dict)

    def public_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass(frozen=True)
class EvidenceRef:
    id: str
    kind: str
    source: str
    locator: str | None = None
    summary: str | None = None


@dataclass(frozen=True)
class TestStep:
    id: str
    action: str
    target: str
    identity_id: str | None = None
    impact: Impact = Impact.PASSIVE
    expected_signal: str | None = None
    notes: str | None = None


@dataclass(frozen=True)
class TestPlan:
    id: str
    hypothesis_id: str
    rationale: str
    steps: tuple[TestStep, ...]
    maximum_impact: Impact = Impact.ACTIVE_SAFE
    request_budget: int = 10
    requires_multiple_identities: bool = False
    prerequisites: tuple[str, ...] = ()
    missing_prerequisites: tuple[str, ...] = ()


@dataclass
class Hypothesis:
    id: str
    pillar: Pillar
    category: str
    title: str
    target_node_id: str
    rationale: str
    confidence: float
    state: HypothesisState = HypothesisState.UNVERIFIED
    evidence: list[EvidenceRef] = field(default_factory=list)
    contradictory_evidence: list[EvidenceRef] = field(default_factory=list)
    plan: TestPlan | None = None
    verification_summary: str | None = None
    rejection_reason: str | None = None

    def transition(self, state: HypothesisState, reason: str | None = None) -> None:
        allowed = {
            HypothesisState.UNVERIFIED: {
                HypothesisState.SUPPORTED,
                HypothesisState.REJECTED,
            },
            HypothesisState.SUPPORTED: {
                HypothesisState.VERIFIED,
                HypothesisState.REJECTED,
            },
            HypothesisState.VERIFIED: set(),
            HypothesisState.REJECTED: set(),
        }
        if state == self.state:
            return
        if state not in allowed[self.state]:
            raise ValueError(f"invalid hypothesis transition: {self.state.value} -> {state.value}")
        self.state = state
        if state is HypothesisState.REJECTED:
            self.rejection_reason = reason or "rejected by evidence"
        elif state is HypothesisState.VERIFIED:
            self.verification_summary = reason or "verified by reproducible evidence"

    def public_dict(self) -> dict[str, Any]:
        payload = asdict(self)
        payload["pillar"] = self.pillar.value
        payload["state"] = self.state.value
        if self.plan:
            payload["plan"]["maximum_impact"] = self.plan.maximum_impact.value
            for step in payload["plan"]["steps"]:
                step["impact"] = step["impact"].value if isinstance(step["impact"], Impact) else step["impact"]
        return payload
