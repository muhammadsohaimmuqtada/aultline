from __future__ import annotations

from dataclasses import dataclass

from aultline.models import IMPACT_ORDER, Impact, TestPlan


@dataclass(frozen=True)
class PolicyDecision:
    allowed: bool
    reason: str


@dataclass(frozen=True)
class ExecutionPolicy:
    maximum_impact: Impact = Impact.ACTIVE_SAFE
    maximum_requests_per_plan: int = 20
    require_explicit_scope: bool = True
    allow_state_changing: bool = False
    allow_high_impact: bool = False

    def evaluate(self, plan: TestPlan, *, scope_declared: bool) -> PolicyDecision:
        if self.require_explicit_scope and not scope_declared:
            return PolicyDecision(False, "explicit authorized scope is required")
        if plan.missing_prerequisites:
            return PolicyDecision(
                False,
                "missing plan prerequisite(s): " + "; ".join(plan.missing_prerequisites),
            )
        if plan.requires_multiple_identities:
            identities = {step.identity_id for step in plan.steps if step.identity_id}
            if len(identities) < 2:
                return PolicyDecision(False, "test plan requires at least two resolved identities")
        if plan.request_budget < 1:
            return PolicyDecision(False, "test plan request budget must be positive")
        if plan.request_budget > self.maximum_requests_per_plan:
            return PolicyDecision(False, "test plan exceeds configured request budget")
        if IMPACT_ORDER[plan.maximum_impact] > IMPACT_ORDER[self.maximum_impact]:
            return PolicyDecision(False, "test plan exceeds configured impact ceiling")
        for step in plan.steps:
            if step.impact is Impact.STATE_CHANGING and not self.allow_state_changing:
                return PolicyDecision(False, "state-changing execution is disabled")
            if step.impact is Impact.HIGH_IMPACT and not self.allow_high_impact:
                return PolicyDecision(False, "high-impact execution is disabled")
            if IMPACT_ORDER[step.impact] > IMPACT_ORDER[self.maximum_impact]:
                return PolicyDecision(False, f"step {step.id} exceeds configured impact ceiling")
        return PolicyDecision(True, "plan satisfies configured policy")
