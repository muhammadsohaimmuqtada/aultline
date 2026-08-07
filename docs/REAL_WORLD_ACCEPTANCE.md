# Real-world acceptance notes

Aultline is developed against deterministic fixtures and real DEDSEC schema-3 reports from authorized test environments.

## Acceptance invariants

- Reconnaissance signals never become verified findings automatically.
- Static resources must not be promoted into object-authorization hypotheses merely because filenames contain digits or long strings.
- One logical endpoint must have one canonical graph node even when DEDSEC represents it both as an asset and as an observed request.
- A plan that requires multiple identities must remain policy-blocked until the required identity contexts actually exist.
- Scope declaration is necessary for active validation, but scope declaration alone is never sufficient to satisfy missing test prerequisites.

These invariants were added after the first full DEDSEC-to-Aultline real-world import acceptance run.
