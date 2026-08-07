# Security policy

Aultline is intended for authorized security testing and defensive validation.

## Operating boundary

Active validation must be limited to systems and identities the operator is explicitly authorized to test. Use researcher-controlled objects and test identities when evaluating authorization, tenant, session, or workflow behavior.

The default Aultline policy is conservative: explicit scope is required, request budgets are bounded, and state-changing/high-impact execution is disabled unless a future executor is deliberately configured to allow it.

## Reporting Aultline vulnerabilities

Please avoid publishing an unpatched vulnerability in Aultline before maintainers have had a reasonable opportunity to reproduce and address it. Open a private security advisory when available, or contact the repository owner directly through GitHub.
