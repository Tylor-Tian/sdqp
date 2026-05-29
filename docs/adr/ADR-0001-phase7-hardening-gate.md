# ADR-0001: Keep Final Hardening as a Separate Delivery Gate

## Status

Accepted

## Context

Phases 0-6 delivered functional slices of SDQP, but section 15 of the execution plan still required a final pass for chain hardening, performance smoke validation, and document cleanup before the implementation could be treated as complete.

## Decision

Treat the final hardening pass as an explicit stage with its own exit criteria instead of folding it into an earlier feature phase.

The stage owns:

- API hardening headers
- `/v1/audit/events/search`
- cross-phase UAT coverage
- lightweight performance smoke budgets
- gate scripts and local verification documentation

## Consequences

- The plan can record a final release-quality milestone without reopening earlier feature phases.
- Codex has a deterministic final stage gate to satisfy before the implementation is reported as complete.
- Future changes to hardening or verification can extend this stage without changing the phase ordering in sections 10 and 15.
