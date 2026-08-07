# Aultline

**Aultline** is an evidence-driven application security analysis and vulnerability validation framework.

Aultline is not a second reconnaissance scanner. It consumes reconnaissance and application-surface evidence, builds a normalized application-security graph, prioritizes meaningful security questions, generates bounded test plans, and promotes findings only when reproducible evidence supports them.

## v1 pillars

Aultline v1 is built around four shared analysis pillars:

1. **Authorization** — horizontal/vertical authorization, object ownership, role boundaries, tenant isolation, IDOR/BOLA hypotheses.
2. **Authentication** — anonymous/authenticated differentials, session-state boundaries, identity and privilege transitions.
3. **API/Object Intelligence** — endpoint/resource graphs, object references, parent-child relationships, CRUD semantics, OpenAPI/observed-traffic fusion.
4. **Workflow/Business Logic** — state-machine reconstruction, prerequisites, invalid transitions, sequence dependencies, replay/duplicate behavior.

The pillars share one graph, one evidence model, one hypothesis lifecycle, one planner, and one policy layer. They are intentionally not four disconnected scanners.

## Hypothesis lifecycle

Aultline uses a conservative finding lifecycle:

```text
UNVERIFIED -> SUPPORTED -> VERIFIED
     |             |
     +----------> REJECTED
```

Imported signals, endpoint names, object identifiers, response differences, and scanner observations do **not** become verified vulnerabilities automatically.

## Current v1 foundation

The first foundation includes:

- unified application graph;
- DEDSEC schema-3 report importer;
- identity, request, endpoint, input, observation, asset, and historical-diff normalization;
- four-pillar hypothesis generation;
- security-value prioritization without finding promotion;
- minimum-sufficient test-plan generation;
- explicit scope, request-budget, and impact policy gates;
- strict hypothesis state transitions;
- JSON CLI output;
- Python 3.10–3.13 CI and regression tests.

Network execution is deliberately separated from analysis/planning. The initial v1 foundation describes required evidence and enforces policy before an executor is introduced.

## Install

```bash
python -m pip install -e .
aultline --version
```

## Import a DEDSEC report

```bash
aultline graph /path/to/dedsec-report.json --output graph.json
aultline analyze /path/to/dedsec-report.json --output analysis.json
```

If the operator has explicitly declared authorized scope for subsequent validation planning:

```bash
aultline analyze /path/to/dedsec-report.json --scope-declared
```

`--scope-declared` does not execute traffic. It only allows eligible generated plans to pass the current policy evaluation.

## Design principles

- Evidence before claims.
- Lowest-impact validation first.
- Explicit identity and ownership boundaries.
- Authorized scope is mandatory for active validation.
- Request budgets and impact ceilings are first-class constraints.
- Historical changes are evidence, not proof of remediation or regression by themselves.
- Weak signals remain hypotheses.
- Verification requires reproducible evidence and appropriate controls.

## Intended use

Aultline is intended for authorized application security testing, internal security engineering, defensive validation, and researcher-controlled environments.

## Status

`1.0.0.dev0` — v1 architecture and core foundation under active development.
