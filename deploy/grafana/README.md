# Grafana Templates

This directory stores importable Grafana templates for SDQP operational verification.

## Current Template

- `stage13-prod-sim-dashboard.json`

## Import Notes

- Bind the dashboard to a Prometheus datasource.
- The template expects the `sdqp-api` and `sdqp-worker` metrics exposed by the repo's `/metrics` endpoints.
- The panels are intended to corroborate Stage 13 smoke runs, not replace the scripted gates.
