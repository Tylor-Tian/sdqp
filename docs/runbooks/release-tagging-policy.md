# Release Tagging Policy

## Goal

Define a single release-tag convention for Stage 13 and later production handoff.

## Tag Formats

- Production release: `sdqp-prod-v<major>.<minor>.<patch>`
- Release candidate: `sdqp-prod-v<major>.<minor>.<patch>-rc.<n>`

Examples:

- `sdqp-prod-v1.0.0`
- `sdqp-prod-v1.0.1-rc.1`

## Preconditions

Create or move a production tag only after all of the following are true:

- `powershell -NoProfile -ExecutionPolicy Bypass -File scripts/test-all.ps1` is green
- `powershell -NoProfile -ExecutionPolicy Bypass -File scripts/check-stage13-release-smoke.ps1` is green
- `powershell -NoProfile -ExecutionPolicy Bypass -File scripts/check-stage13-backup-restore.ps1` is green
- `powershell -NoProfile -ExecutionPolicy Bypass -File scripts/check-stage13-perf-smoke.ps1` is green
- the final acceptance checklist in `docs/runbooks/stage13-final-acceptance-checklist.md` is complete

## Tagging Rules

- Use annotated tags, not lightweight tags.
- Tag only the exact commit that passed the required gates.
- Keep release-candidate tags on the same commit lineage as the final production tag.
- If a hotfix is required, publish a new patch version; do not retarget an existing production tag.

## Recommended Command Sequence

```powershell
git tag -a sdqp-prod-v1.0.0 -m "SDQP production release v1.0.0"
git push origin sdqp-prod-v1.0.0
```

For an RC:

```powershell
git tag -a sdqp-prod-v1.0.1-rc.1 -m "SDQP production release candidate v1.0.1-rc.1"
git push origin sdqp-prod-v1.0.1-rc.1
```

## Release Note Minimums

Every production tag should reference:

- the commit SHA
- the three Stage 13 smoke-gate results
- the matching dashboard template revision
- any required recovery or rollback notes

## Notes

- The tag name is the user-facing release identity. Container image tags, compose bundles, and acceptance records should all point back to the same Git tag.
- Do not create a production tag from an unreviewed local workspace state.
