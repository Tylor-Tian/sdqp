import { fireEvent, render, screen, waitFor } from "@testing-library/react";
import { describe, expect, it, vi } from "vitest";
import { App } from "./App";
import { ApiError, type FrontendClient } from "./api";

function createClient(overrides?: Partial<FrontendClient>): FrontendClient {
  return {
    setSession: vi.fn(),
    beginLogin: vi.fn().mockResolvedValue({
      pendingSessionId: "pending-a",
      mfaRequired: true,
      method: "totp",
      challengeId: "challenge-a",
      authSource: "local"
    }),
    verifyMfa: vi.fn().mockResolvedValue({
      accessToken: "access-a",
      refreshToken: "refresh-a",
      sessionId: "session-a"
    }),
    refreshSession: vi.fn().mockResolvedValue({
      accessToken: "access-b",
      refreshToken: "refresh-b",
      sessionId: "session-b"
    }),
    logout: vi.fn().mockResolvedValue({ revoked: true }),
    reportDevicePosture: vi.fn().mockResolvedValue({
      risk_score: 88,
      action: "step_up",
      compliant: false,
      reasons: ["ip drift", "query burst"],
      step_up_required: true,
      session_revoked: false
    }),
    verifyStepUp: vi.fn().mockResolvedValue({
      accessToken: "access-c",
      refreshToken: "refresh-c",
      sessionId: "session-c"
    }),
    getProjects: vi.fn().mockResolvedValue({
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
    }),
    changeProjectState: vi.fn().mockResolvedValue({
      project_id: "project-alpha",
      previous_state: "active",
      current_state: "frozen",
      revoked_permissions: 0,
      deleted_snapshots: 0,
      checkpoint_id: "checkpoint-a"
    }),
    submitPermissionApplication: vi.fn().mockResolvedValue({
      application_id: "application-a",
      applicant_user_id: "user-analyst",
      project_id: "project-alpha",
      data_source_id: "datasource-rest",
      requested_fields: ["employee_id", "department"],
      status: "pending"
    }),
    getPermissionGrants: vi.fn().mockResolvedValue({
      grants: []
    }),
    getApprovalTasks: vi.fn().mockResolvedValue({
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
    }),
    submitApprovalAction: vi.fn().mockResolvedValue({
      instance_id: "approval-a",
      status: "delegated",
      application_status: "pending"
    }),
    submitQuery: vi.fn().mockResolvedValue({
      task_id: "task-a",
      status: "running",
      websocket_path: "/v1/tasks/task-a/ws"
    }),
    streamTaskStatus: vi.fn().mockImplementation((_taskId, options) => {
      Promise.resolve().then(() =>
        options.onStatus({
          task_id: "task-a",
          state: "running",
          snapshot_id: null,
          cache_hit: false,
          error: null
        })
      );
      Promise.resolve().then(() =>
        options.onStatus({
          task_id: "task-a",
          state: "completed",
          snapshot_id: "snapshot-a",
          cache_hit: false,
          error: null
        })
      );
      return {
        close: vi.fn()
      };
    }),
    getTaskStatus: vi
      .fn()
      .mockResolvedValueOnce({
        task_id: "task-a",
        state: "running",
        snapshot_id: null,
        cache_hit: false,
        error: null
      })
      .mockResolvedValue({
        task_id: "task-a",
        state: "completed",
        snapshot_id: "snapshot-a",
        cache_hit: false,
        error: null
      }),
    getSnapshotPage: vi.fn().mockResolvedValue({
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
    }),
    getPivot: vi.fn().mockResolvedValue({
      snapshot_id: "snapshot-a",
      dimension: "department",
      metric: "record_count",
      buckets: [{ key: "fraud", value: 1 }],
      watermark_text: "tenant-alpha / project-alpha / user-analyst"
    }),
    getDrilldown: vi.fn().mockResolvedValue({
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
    }),
    searchAudit: vi.fn().mockResolvedValue({
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
    }),
    exportEvidence: vi.fn().mockResolvedValue({
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
    }),
    getExportTask: vi.fn().mockResolvedValue({
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
    }),
    authorizeDownload: vi.fn().mockResolvedValue({
      task_id: "export-a",
      download_token: "download-a",
      file_name: "evidence.txt",
      media_type: "text/plain",
      expires_at: "2026-03-30T09:10:00Z"
    }),
    downloadExport: vi.fn().mockResolvedValue({
      content: "download preview",
      contentType: "text/plain",
      fileName: "evidence.txt"
    }),
    getUebaAlerts: vi.fn().mockResolvedValue({
      alerts: [],
      step_up_sessions: 0,
      permissions_revoked: 0,
      terminated_sessions: 0
    }),
    getUebaBaselines: vi.fn().mockResolvedValue({
      user_baselines: [],
      entity_baselines: []
    }),
    ...overrides
  };
}

describe("Stage12 UAT", () => {
  it("walks the analyst flow from MFA to export preview", async () => {
    const client = createClient();
    render(<App client={client} pollIntervalMs={1} />);

    fireEvent.click(screen.getByRole("button", { name: "Start Login" }));
    await screen.findByText("MFA Challenge");
    fireEvent.click(screen.getByRole("button", { name: "Complete MFA" }));

    await waitFor(() => {
      expect(client.getProjects).toHaveBeenCalled();
      expect(client.getPermissionGrants).toHaveBeenCalled();
    });
    await waitFor(() => {
      expect(screen.getByRole("button", { name: "Submit Permission Request" })).not.toBeDisabled();
    });

    fireEvent.click(screen.getByRole("button", { name: "Submit Permission Request" }));
    expect(await screen.findByText("application-a")).toBeInTheDocument();

    fireEvent.click(screen.getByRole("button", { name: "Submit Async Query" }));
    expect(await screen.findByText("Detail Page")).toBeInTheDocument();

    fireEvent.click(screen.getByRole("button", { name: "Generate Evidence Package" }));
    expect(await screen.findByText("package-a")).toBeInTheDocument();

    fireEvent.click(screen.getByRole("button", { name: "Authorize Download" }));
    expect(await screen.findByText(/token download-a/)).toBeInTheDocument();

    fireEvent.click(screen.getByRole("button", { name: "Preview Download" }));
    expect(await screen.findByText("Preview Metadata")).toBeInTheDocument();
    expect(await screen.findByText("L1: download preview")).toBeInTheDocument();
  });

  it("walks the security flow through step-up and approval delegation", async () => {
    const client = createClient();
    render(<App client={client} />);

    fireEvent.change(screen.getByRole("combobox", { name: "Persona" }), {
      target: { value: "security" }
    });
    fireEvent.click(screen.getByRole("button", { name: "Start Login" }));
    await screen.findByText("MFA Challenge");
    fireEvent.click(screen.getByRole("button", { name: "Complete MFA" }));
    await waitFor(() => {
      expect(screen.getByRole("button", { name: "Evaluate Device Posture" })).not.toBeDisabled();
    });

    fireEvent.click(screen.getByRole("button", { name: "Evaluate Device Posture" }));
    expect(await screen.findByText("Step-Up Required")).toBeInTheDocument();

    fireEvent.click(screen.getByRole("button", { name: "Complete Step-Up" }));
    await waitFor(() => {
      expect(client.verifyStepUp).toHaveBeenCalled();
    });

    fireEvent.click(screen.getByRole("button", { name: "Load Approval Queue" }));
    expect(await screen.findByText("approval-a")).toBeInTheDocument();

    fireEvent.click(screen.getByRole("button", { name: "Delegate" }));
    expect(await screen.findByText(/Executed delegate -> delegated/)).toBeInTheDocument();
  });

  it("surfaces step-up guidance when a privileged queue call returns 403", async () => {
    const client = createClient({
      getApprovalTasks: vi.fn().mockRejectedValue(new ApiError("Forbidden approval queue", 403))
    });
    render(<App client={client} />);

    fireEvent.change(screen.getByRole("combobox", { name: "Persona" }), {
      target: { value: "security" }
    });
    fireEvent.click(screen.getByRole("button", { name: "Start Login" }));
    await screen.findByText("MFA Challenge");
    fireEvent.click(screen.getByRole("button", { name: "Complete MFA" }));
    await waitFor(() => {
      expect(screen.getByRole("button", { name: "Load Approval Queue" })).not.toBeDisabled();
    });

    fireEvent.click(screen.getByRole("button", { name: "Load Approval Queue" }));

    expect(await screen.findByText("Step-up or access upgrade required")).toBeInTheDocument();
    expect(
      await screen.findByText(
        "The server blocked this action. Complete step-up or switch to a permitted persona or project."
      )
    ).toBeInTheDocument();
  });

  it("keeps the console active when the server returns a step-up-required 401", async () => {
    const client = createClient({
      getApprovalTasks: vi.fn().mockRejectedValue(
        new ApiError("step-up authentication required", 401, {
          stepUpRequired: true,
          stepUpChallenge: {
            challengeId: "challenge-a",
            method: "totp",
            reason: "continuous risk assessment requires step-up",
            expiresAt: "2026-04-11T12:00:00Z"
          }
        })
      )
    });
    render(<App client={client} />);

    fireEvent.change(screen.getByRole("combobox", { name: "Persona" }), {
      target: { value: "security" }
    });
    fireEvent.click(screen.getByRole("button", { name: "Start Login" }));
    await screen.findByText("MFA Challenge");
    fireEvent.click(screen.getByRole("button", { name: "Complete MFA" }));
    await waitFor(() => {
      expect(screen.getByRole("button", { name: "Load Approval Queue" })).not.toBeDisabled();
    });

    fireEvent.click(screen.getByRole("button", { name: "Load Approval Queue" }));

    expect(await screen.findByText("Step-up required")).toBeInTheDocument();
    expect(
      await screen.findByText("continuous risk assessment requires step-up")
    ).toBeInTheDocument();
    expect(screen.getByTestId("authenticated-workspace-shell")).toBeInTheDocument();
  });
});
