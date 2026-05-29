# KMS Key Recovery Runbook

## Scope

This runbook covers Stage 13 key recovery for encrypted snapshots and evidence objects.

Use it when any of the following happens:

- the configured KMS key ring is unavailable
- the active master key version changes and stored envelopes must be rewrapped
- objects were restored from backup and their KEK binding must be validated before reuse

For local `prod-sim`, the authoritative configuration inputs are:

- `configs/prod-sim/app.toml`
- `docs/runbooks/docker-prod-sim-backup-restore.md`
- `docs/api/snapshot-lifecycle-stage8.md`

## Required Inputs

- latest known-good backup set under `artifacts/stage13-backup-restore`
- target snapshot IDs that must be recovered or rewrapped
- current KMS settings:
  - `kms.provider`
  - `kms.endpoint`
  - `kms.master_key_id`
  - `kms.key_ring`
- object-store targets:
  - `object_store.bucket_snapshots`
  - `object_store.bucket_evidence`

## Recovery Flow

1. Contain writes.
   Stop the prod-sim stack or block new snapshot/export traffic before changing key material.

2. Rehydrate the data plane if required.
   If PostgreSQL, ClickHouse, or MinIO were restored, run:

```powershell
powershell -NoProfile -ExecutionPolicy Bypass -File scripts/docker-prod-sim-restore.ps1 -BackupDir artifacts/stage13-backup-restore
```

3. Verify the intended key identity before restart.
   Confirm the runtime should come back with the expected `master_key_id` and `key_ring` from [app.toml](/D:/Project/SDQP/configs/prod-sim/app.toml).

4. Bring the stack up without smoke.

```powershell
powershell -NoProfile -ExecutionPolicy Bypass -File scripts/docker-prod-sim-up.ps1 -SkipSmoke
```

5. Authenticate and inspect the target snapshot.
   Use an operator account to read snapshot metadata first, then confirm the object is still present in the restored bucket.

6. Rewrap the snapshot envelope under the active key version.
   Call `POST /v1/snapshots/{snapshot_id}/refresh`.
   This keeps the encrypted payload in object storage but rewrites the wrapped DEK and updates `last_rewrapped_at`.

7. Validate read-path recovery.
   Confirm all of the following for the rewrapped snapshot:

- `GET /v1/snapshots/{snapshot_id}/metadata` returns `delete_state = active`
- `GET /v1/snapshots/{snapshot_id}/page?page_size=1` returns rows
- any evidence export depending on that snapshot can be reissued

8. Record the recovery boundary.
   Capture the refreshed snapshot ID, the active key version, the operator, and the timestamp in the incident log.

## Local Prod-Sim Verification

After recovery, rerun the Stage 13 gates that cover object access and durability:

```powershell
powershell -NoProfile -ExecutionPolicy Bypass -File scripts/check-stage13-release-smoke.ps1
powershell -NoProfile -ExecutionPolicy Bypass -File scripts/check-stage13-backup-restore.ps1
```

If the incident involved a key version change, also rerun:

```powershell
powershell -NoProfile -ExecutionPolicy Bypass -File scripts/check-stage13-perf-smoke.ps1
```

## Notes

- `prod-sim` configuration points at a Vault-style KMS endpoint, while the local runtime still uses the repo's mockable envelope path. The operator concern is the same: restore access to the intended KEK identity before reusing restored ciphertext.
- Do not mark the incident resolved until the snapshot page and at least one downstream export/read path have been revalidated.
