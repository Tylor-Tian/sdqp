import { expect, test, type Page } from "@playwright/test";

async function mockApi(page: Page, options?: { stepUp?: boolean }) {
  let taskPolls = 0;

  await page.route("**/*", async (route) => {
    const url = new URL(route.request().url());
    const { pathname } = url;

    const json = (body: unknown) =>
      route.fulfill({
        status: 200,
        contentType: "application/json",
        body: JSON.stringify(body)
      });

    if (pathname === "/auth/login") {
      return json({
        pending_session_id: "pending-a",
        mfa_required: true,
        method: "totp",
        challenge_id: "challenge-a",
        auth_source: "local"
      });
    }

    if (pathname === "/auth/mfa/verify") {
      return json({
        access_token:
          "eyJhbGciOiJIUzI1NiJ9.eyJ0ZW5hbnRfaWQiOiJ0ZW5hbnQtYWxwaGEifQ.signature",
        refresh_token: "refresh-a",
        session_id: "session-a"
      });
    }

    if (pathname === "/auth/refresh") {
      return json({
        access_token:
          "eyJhbGciOiJIUzI1NiJ9.eyJ0ZW5hbnRfaWQiOiJ0ZW5hbnQtYWxwaGEifQ.signature",
        refresh_token: "refresh-b",
        session_id: "session-b"
      });
    }

    if (pathname === "/auth/device-posture") {
      return json({
        risk_score: options?.stepUp ? 88 : 12,
        action: options?.stepUp ? "step_up" : "allow",
        compliant: !options?.stepUp,
        reasons: options?.stepUp ? ["ip drift", "query burst"] : ["baseline"],
        step_up_required: Boolean(options?.stepUp),
        session_revoked: false
      });
    }

    if (pathname === "/auth/step-up/verify") {
      return json({
        access_token:
          "eyJhbGciOiJIUzI1NiJ9.eyJ0ZW5hbnRfaWQiOiJ0ZW5hbnQtYWxwaGEifQ.signature",
        refresh_token: "refresh-c",
        session_id: "session-c"
      });
    }

    if (pathname === "/auth/logout") {
      return json({ revoked: true });
    }

    if (pathname === "/v1/projects") {
      return json({
        projects: [
          {
            project_id: "project-alpha",
            tenant_id: "tenant-alpha",
            state: "active",
            can_accept_new_permissions: true,
            can_export: true,
            read_only: false
          }
        ]
      });
    }

    if (pathname === "/v1/projects/project-alpha/state") {
      return json({
        project_id: "project-alpha",
        previous_state: "active",
        current_state: "frozen",
        revoked_permissions: 0,
        deleted_snapshots: 0,
        checkpoint_id: "checkpoint-a"
      });
    }

    if (pathname === "/v1/permissions/applications") {
      return json({
        application_id: "application-a",
        applicant_user_id: "user-analyst",
        project_id: "project-alpha",
        data_source_id: "datasource-rest",
        requested_fields: ["employee_id", "department"],
        status: "pending"
      });
    }

    if (pathname === "/v1/permissions/grants") {
      return json({
        grants: [
          {
            grant_id: "grant-a",
            data_source_id: "datasource-rest",
            status: "active",
            fields: ["employee_id", "department"],
            valid_until: "2026-03-30T10:00:00Z"
          }
        ]
      });
    }

    if (pathname === "/v1/approvals/tasks") {
      return json({
        tasks: [
          {
            instance_id: "approval-a",
            application_id: "application-a",
            applicant_user_id: "user-analyst",
            data_source_id: "datasource-rest",
            step_id: "step-1",
            status: "pending",
            pending_approvers: ["user-security-a"],
            requested_fields: ["employee_id"],
            due_at: "2026-03-30T11:00:00Z",
            escalation_target: null,
            delegated_to: null
          }
        ]
      });
    }

    if (pathname === "/v1/approvals/callback") {
      return json({
        instance_id: "approval-a",
        status: "delegated",
        application_status: "pending"
      });
    }

    if (pathname === "/v1/queries") {
      return json({
        task_id: "task-a",
        status: "running",
        websocket_path: "/v1/tasks/task-a/ws"
      });
    }

    if (pathname === "/v1/tasks/task-a/status") {
      taskPolls += 1;
      return json(
        taskPolls < 2
          ? {
              task_id: "task-a",
              state: "running",
              snapshot_id: null,
              cache_hit: false,
              error: null
            }
          : {
              task_id: "task-a",
              state: "completed",
              snapshot_id: "snapshot-a",
              cache_hit: false,
              error: null
            }
      );
    }

    if (pathname === "/v1/snapshots/snapshot-a/page") {
      return json({
        snapshot_id: "snapshot-a",
        columns: ["employee_id", "department"],
        rows: [{ employee_id: "E-100", department: "fraud" }],
        next_cursor: null,
        field_policies: [
          {
            field_name: "employee_id",
            masked: false,
            render_mode: "canvas",
            watermark_strength: "low"
          },
          {
            field_name: "department",
            masked: false,
            render_mode: "canvas",
            watermark_strength: "low"
          }
        ],
        watermark_text: "tenant-alpha / project-alpha / user-analyst"
      });
    }

    if (pathname === "/v1/analysis/pivot") {
      return json({
        snapshot_id: "snapshot-a",
        dimension: "department",
        metric: "record_count",
        buckets: [{ key: "fraud", value: 1 }],
        watermark_text: "tenant-alpha / project-alpha / user-analyst"
      });
    }

    if (pathname === "/v1/analysis/pivot/drilldown") {
      return json({
        snapshot_id: "snapshot-a",
        columns: ["employee_id", "department"],
        rows: [{ employee_id: "E-100", department: "fraud" }],
        next_cursor: null,
        field_policies: [
          {
            field_name: "employee_id",
            masked: false,
            render_mode: "canvas",
            watermark_strength: "low"
          },
          {
            field_name: "department",
            masked: false,
            render_mode: "canvas",
            watermark_strength: "low"
          }
        ],
        watermark_text: "tenant-alpha / project-alpha / user-analyst"
      });
    }

    if (pathname === "/v1/audit/events/search") {
      return json({
        chain_valid: true,
        total_matches: 1,
        events: [
          {
            event_id: "event-a",
            timestamp: "2026-03-30T08:00:00Z",
            actor_user_id: "user-analyst",
            action: "query",
            result: "success",
            tenant_id: "tenant-alpha",
            project_id: "project-alpha",
            resource_id: "queries/task-a",
            context: "query completed",
            data_fingerprint: "fp-a"
          }
        ]
      });
    }

    if (pathname === "/v1/exports/evidence") {
      return json({
        task_id: "export-a",
        status: "completed",
        package_id: "package-a",
        snapshot_id: "snapshot-a",
        template: "china",
        watermark_token: "wm-a",
        watermark_text: "tenant-alpha / project-alpha / user-analyst",
        exported_document: "document body",
        audit_event_count: 3,
        audit_chain_valid: true,
        timestamp_authority: "mock-tsa",
        timestamp_token: "tsa-a",
        anchor_network: "mock-chain",
        anchor_transaction_id: "tx-a",
        manifest_digest: "digest-a",
        verification_ready: true,
        file_name: "evidence.txt",
        media_type: "text/plain",
        download_ready: true,
        created_at: "2026-03-30T09:00:00Z",
        completed_at: "2026-03-30T09:01:00Z"
      });
    }

    if (pathname === "/v1/exports/tasks/export-a") {
      return json({
        task_id: "export-a",
        status: "completed",
        package_id: "package-a",
        snapshot_id: "snapshot-a",
        template: "china",
        watermark_token: "wm-a",
        watermark_text: "tenant-alpha / project-alpha / user-analyst",
        exported_document: "document body",
        audit_event_count: 3,
        audit_chain_valid: true,
        timestamp_authority: "mock-tsa",
        timestamp_token: "tsa-a",
        anchor_network: "mock-chain",
        anchor_transaction_id: "tx-a",
        manifest_digest: "digest-a",
        verification_ready: true,
        file_name: "evidence.txt",
        media_type: "text/plain",
        download_ready: true,
        created_at: "2026-03-30T09:00:00Z",
        completed_at: "2026-03-30T09:01:00Z"
      });
    }

    if (pathname === "/v1/exports/tasks/export-a/authorize-download") {
      return json({
        task_id: "export-a",
        download_token: "download-a",
        file_name: "evidence.txt",
        media_type: "text/plain",
        expires_at: "2026-03-30T09:10:00Z"
      });
    }

    if (pathname === "/v1/exports/download/download-a") {
      return route.fulfill({
        status: 200,
        contentType: "text/plain",
        body: "download preview"
      });
    }

    if (pathname === "/v1/ueba/alerts") {
      return json({
        alerts: [],
        step_up_sessions: 0,
        permissions_revoked: 0,
        terminated_sessions: 0
      });
    }

    if (pathname === "/v1/ueba/baselines") {
      return json({
        user_baselines: [],
        entity_baselines: []
      });
    }

    return route.continue();
  });
}

test("analyst flow reaches export preview", async ({ page }) => {
  await mockApi(page);
  await page.goto("/");

  await page.getByRole("button", { name: "Start Login" }).click();
  await expect(page.getByRole("heading", { name: "MFA Challenge" })).toBeVisible();
  await page.getByRole("button", { name: "Complete MFA" }).click();
  await page.getByRole("button", { name: "Submit Permission Request" }).click();
  await expect(page.getByText("application-a")).toBeVisible();
  await page.getByRole("button", { name: "Submit Async Query" }).click();
  await expect(page.getByText("Detail Page")).toBeVisible();
  await page.getByRole("button", { name: "Generate Evidence Package" }).click();
  await expect(page.getByText("package-a")).toBeVisible();
  await page.getByRole("button", { name: "Authorize Download" }).click();
  await expect(page.getByText(/token download-a/)).toBeVisible();
  await page.getByRole("button", { name: "Preview Download" }).click();
  await expect(page.locator("pre.codeBlock")).toContainText("download preview");
});

test("security flow triggers step-up and delegation", async ({ page }) => {
  await mockApi(page, { stepUp: true });
  await page.goto("/");

  await page.getByRole("combobox", { name: "Persona" }).selectOption("security");
  await page.getByRole("button", { name: "Start Login" }).click();
  await page.getByRole("button", { name: "Complete MFA" }).click();
  await page.getByRole("button", { name: "Evaluate Device Posture" }).click();
  await expect(page.getByText("Step-Up Required")).toBeVisible();
  await page.getByRole("button", { name: "Complete Step-Up" }).click();
  await page.getByRole("button", { name: "Load Approval Queue" }).click();
  await expect(page.getByText("approval-a")).toBeVisible();
  await page.getByRole("button", { name: "Delegate" }).click();
  await expect(page.getByText(/Executed delegate -> delegated/)).toBeVisible();
});
