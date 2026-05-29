import { fireEvent, render, screen, waitFor } from "@testing-library/react";
import { describe, expect, it, vi } from "vitest";
import { App, buildFieldCatalog, buildPersonaCatalog } from "./App";
import { ApiError, type FrontendClient, type QueryPriorityLevel, type QueryTaskStatus } from "./api";

function priorityValue(priority: QueryPriorityLevel) {
  switch (priority) {
    case "low":
      return 25;
    case "high":
      return 75;
    case "critical":
      return 100;
    default:
      return 50;
  }
}

function makeTaskStatus(
  state: "pending" | "running" | "completed" | "failed" | "cancelled",
  options: {
    taskId?: string;
    snapshotId?: string | null;
    priority?: QueryPriorityLevel;
    error?: string | null;
  } = {}
): QueryTaskStatus {
  const taskId = options.taskId ?? "task-a";
  const priority = options.priority ?? "normal";
  const snapshotId = options.snapshotId ?? (state === "completed" ? "snapshot-a" : null);
  const canAccessSnapshot = state === "completed" && Boolean(snapshotId);
  const secureSnapshotAccess = canAccessSnapshot
    ? "authorized_encrypted_snapshot"
    : state === "failed"
      ? "blocked_failed_task"
      : state === "cancelled"
        ? "blocked_cancelled_task"
        : "pending_encrypted_snapshot";

  return {
    task_id: taskId,
    state,
    snapshot_id: snapshotId,
    cache_hit: false,
    error: options.error ?? null,
    priority: { label: priority, value: priorityValue(priority) },
    runtime: {
      task_id: taskId,
      priority: { label: priority, value: priorityValue(priority) },
      runtime_state: state,
      adapter_runtime_state: "Started",
      adapter_availability: "Available",
      secure_snapshot_access: secureSnapshotAccess,
      controls: {
        can_cancel: state === "pending" || state === "running",
        can_retry: state === "failed" || state === "cancelled",
        can_access_snapshot: canAccessSnapshot
      }
    }
  };
}

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
      risk_score: 12,
      action: "allow",
      compliant: true,
      reasons: ["baseline"],
      step_up_required: false,
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
      revoked_permissions: 1,
      deleted_snapshots: 2,
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
      grants: [
        {
          grant_id: "grant-a",
          data_source_id: "datasource-rest",
          status: "active",
          fields: ["employee_id", "department"],
          valid_until: "2026-03-30T10:00:00Z"
        }
      ]
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
      status: "approved",
      application_status: "approved"
    }),
    submitQuery: vi.fn().mockImplementation(async (payload) => {
      const priority = payload.priority ?? "normal";
      const status = makeTaskStatus("running", { priority });
      return {
        task_id: status.task_id,
        status: status.state,
        websocket_path: "/v1/tasks/task-a/ws",
        priority: status.priority,
        runtime: status.runtime
      };
    }),
    streamTaskStatus: vi.fn().mockImplementation((_taskId, options) => {
      Promise.resolve().then(() =>
        options.onStatus(makeTaskStatus("running"))
      );
      Promise.resolve().then(() =>
        options.onStatus(makeTaskStatus("completed"))
      );
      return {
        close: vi.fn()
      };
    }),
    getTaskStatus: vi
      .fn()
      .mockResolvedValueOnce(makeTaskStatus("running"))
      .mockResolvedValue(makeTaskStatus("completed")),
    cancelTask: vi.fn().mockResolvedValue({
      task_id: "task-a",
      cancelled: true
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
    getSnapshotPageArrowIpc: vi.fn().mockResolvedValue({
      content: new ArrayBuffer(0),
      contentType: "application/vnd.apache.arrow.stream",
      metadata: {
        snapshot_id: "snapshot-a",
        columns: ["employee_id", "department"],
        next_cursor: null,
        field_policies: [],
        watermark_text: "tenant-alpha / project-alpha / user-analyst"
      }
    }),
    getPivot: vi.fn().mockResolvedValue({
      snapshot_id: "snapshot-a",
      dimension: "department",
      metric: "record_count",
      buckets: [{ key: "fraud", value: 1 }],
      watermark_text: "tenant-alpha / project-alpha / user-analyst"
    }),
    getPivotArrowIpc: vi.fn().mockResolvedValue({
      content: new ArrayBuffer(0),
      contentType: "application/vnd.apache.arrow.stream",
      metadata: {
        snapshot_id: "snapshot-a",
        dimension: "department",
        metric: "record_count",
        watermark_text: "tenant-alpha / project-alpha / user-analyst"
      }
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
    listAnalysisTemplates: vi.fn().mockResolvedValue({
      templates: [
        {
          template_id: "template-a",
          name: "Fraud triage",
          description: "Default fraud workspace",
          data_source_id: "datasource-rest",
          visibility: "private",
          owner_user_id: "user-analyst",
          editable: true,
          published_at: null,
          created_at: "2026-04-05T09:00:00Z",
          updated_at: "2026-04-05T09:00:00Z",
          config: {
            page_size: 2,
            detail_fields: ["employee_id", "department"],
            pivot_dimension: "department",
            pivot_metric: "record_count",
            pivot_metric_field: null,
            pivot_percentile: null
          }
        }
      ]
    }),
    createAnalysisTemplate: vi.fn().mockResolvedValue({
      template_id: "template-b",
      name: "Fraud triage saved",
      description: "Saved from UI",
      data_source_id: "datasource-rest",
      visibility: "private",
      owner_user_id: "user-analyst",
      editable: true,
      published_at: null,
      created_at: "2026-04-05T10:00:00Z",
      updated_at: "2026-04-05T10:00:00Z",
      config: {
        page_size: 2,
        detail_fields: ["employee_id", "department"],
        pivot_dimension: "department",
        pivot_metric: "record_count",
        pivot_metric_field: null,
        pivot_percentile: null
      }
    }),
    getAnalysisTemplate: vi.fn().mockResolvedValue({
      template_id: "template-a",
      name: "Fraud triage",
      description: "Default fraud workspace",
      data_source_id: "datasource-rest",
      visibility: "published",
      owner_user_id: "user-analyst",
      editable: true,
      published_at: "2026-04-05T10:00:00Z",
      created_at: "2026-04-05T09:00:00Z",
      updated_at: "2026-04-05T10:00:00Z",
      config: {
        page_size: 2,
        detail_fields: ["employee_id", "department"],
        pivot_dimension: "department",
        pivot_metric: "record_count",
        pivot_metric_field: null,
        pivot_percentile: null
      }
    }),
    updateAnalysisTemplate: vi.fn().mockResolvedValue({
      template_id: "template-a",
      name: "Fraud triage updated",
      description: "Updated",
      data_source_id: "datasource-rest",
      visibility: "private",
      owner_user_id: "user-analyst",
      editable: true,
      published_at: null,
      created_at: "2026-04-05T09:00:00Z",
      updated_at: "2026-04-05T11:00:00Z",
      config: {
        page_size: 2,
        detail_fields: ["employee_id", "department"],
        pivot_dimension: "department",
        pivot_metric: "record_count",
        pivot_metric_field: null,
        pivot_percentile: null
      }
    }),
    publishAnalysisTemplate: vi.fn().mockResolvedValue({
      template_id: "template-a",
      name: "Fraud triage",
      description: "Default fraud workspace",
      data_source_id: "datasource-rest",
      visibility: "published",
      owner_user_id: "user-analyst",
      editable: true,
      published_at: "2026-04-05T10:00:00Z",
      created_at: "2026-04-05T09:00:00Z",
      updated_at: "2026-04-05T10:00:00Z",
      config: {
        page_size: 2,
        detail_fields: ["employee_id", "department"],
        pivot_dimension: "department",
        pivot_metric: "record_count",
        pivot_metric_field: null,
        pivot_percentile: null
      }
    }),
    unpublishAnalysisTemplate: vi.fn().mockResolvedValue({
      template_id: "template-a",
      name: "Fraud triage",
      description: "Default fraud workspace",
      data_source_id: "datasource-rest",
      visibility: "private",
      owner_user_id: "user-analyst",
      editable: true,
      published_at: null,
      created_at: "2026-04-05T09:00:00Z",
      updated_at: "2026-04-05T10:30:00Z",
      config: {
        page_size: 2,
        detail_fields: ["employee_id", "department"],
        pivot_dimension: "department",
        pivot_metric: "record_count",
        pivot_metric_field: null,
        pivot_percentile: null
      }
    }),
    deleteAnalysisTemplate: vi.fn().mockResolvedValue({
      template_id: "template-a",
      deleted: true
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

describe("Stage12 App", () => {
  it("builds the field and persona catalogs", () => {
    expect(buildFieldCatalog()).toHaveLength(3);
    expect(buildFieldCatalog().map((field) => field.name)).toContain("employee_email");
    expect(buildPersonaCatalog().map((persona) => persona.key)).toContain("security");
  });

  it("renders the stage12 console shell and starts login", async () => {
    const client = createClient();
    render(<App client={client} />);

    expect(screen.getByText("SDQP Operations Console")).toBeInTheDocument();
    expect(screen.getByTestId("workspace-root-shell")).toBeInTheDocument();
    expect(screen.getByTestId("console-content-shell")).toBeInTheDocument();
    fireEvent.click(screen.getByRole("button", { name: "Start Login" }));

    expect(await screen.findByText("MFA Challenge")).toBeInTheDocument();
    expect(client.beginLogin).toHaveBeenCalledWith({
      username: "analyst",
      password: "password123",
      deviceFingerprint: "sdqp-ops-console"
    });
  });

  it("completes login and loads query artifacts", async () => {
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
      expect(screen.getByRole("button", { name: "Submit Async Query" })).not.toBeDisabled();
    });

    fireEvent.change(screen.getByLabelText("Query Priority"), {
      target: { value: "critical" }
    });
    fireEvent.click(screen.getByRole("button", { name: "Submit Async Query" }));
    expect(client.submitQuery).toHaveBeenCalledWith(
      expect.objectContaining({ priority: "critical" })
    );

    expect(await screen.findByText("Detail Page")).toBeInTheDocument();
    expect(await screen.findByText("Evidence Export")).toBeInTheDocument();
    expect(await screen.findByText("Secure Snapshot Access")).toBeInTheDocument();
    expect(await screen.findByText("authorized_encrypted_snapshot")).toBeInTheDocument();
    expect(await screen.findByTestId("workspace-root-shell")).toBeInTheDocument();
    expect(await screen.findByTestId("console-content-shell")).toBeInTheDocument();
    expect(await screen.findByTestId("authenticated-workspace-shell")).toBeInTheDocument();
    expect(await screen.findByTestId("analysis-workspace-shell")).toBeInTheDocument();
    await waitFor(() => {
      expect(client.streamTaskStatus).toHaveBeenCalledWith(
        "task-a",
        expect.objectContaining({ path: "/v1/tasks/task-a/ws", replayLast: true })
      );
    });
  });

  it("saves and loads analysis templates from the workbench", async () => {
    const client = createClient();
    render(<App client={client} pollIntervalMs={1} />);

    fireEvent.click(screen.getByRole("button", { name: "Start Login" }));
    await screen.findByText("MFA Challenge");
    fireEvent.click(screen.getByRole("button", { name: "Complete MFA" }));

    await waitFor(() => {
      expect(client.listAnalysisTemplates).toHaveBeenCalled();
    });

    await waitFor(() => {
      expect(screen.getByRole("button", { name: "Submit Async Query" })).not.toBeDisabled();
    });

    fireEvent.click(screen.getByRole("button", { name: "Submit Async Query" }));
    await screen.findByText("Detail Page");

    fireEvent.change(screen.getByLabelText("Template Name"), {
      target: { value: "Fraud triage saved" }
    });
    fireEvent.click(screen.getByRole("button", { name: "Save Current Template" }));

    await waitFor(() => {
      expect(client.createAnalysisTemplate).toHaveBeenCalled();
    });

    fireEvent.change(screen.getByLabelText("Saved Template"), {
      target: { value: "template-a" }
    });
    fireEvent.click(screen.getByRole("button", { name: "Load Selected Template" }));

    await waitFor(() => {
      expect(client.getAnalysisTemplate).toHaveBeenCalledWith("template-a");
      expect(screen.getByText("Loaded template Fraud triage.")).toBeInTheDocument();
    });
  });

  it("falls back to polling when task websocket streaming fails", async () => {
    const client = createClient({
      streamTaskStatus: vi.fn().mockImplementation((_taskId, options) => {
        Promise.resolve().then(() => options.onError?.(new Error("socket unavailable")));
        return {
          close: vi.fn()
        };
      })
    });
    render(<App client={client} pollIntervalMs={1} />);

    fireEvent.click(screen.getByRole("button", { name: "Start Login" }));
    await screen.findByText("MFA Challenge");
    fireEvent.click(screen.getByRole("button", { name: "Complete MFA" }));

    await waitFor(() => {
      expect(screen.getByRole("button", { name: "Submit Async Query" })).not.toBeDisabled();
    });

    fireEvent.click(screen.getByRole("button", { name: "Submit Async Query" }));

    expect(await screen.findByText("Detail Page")).toBeInTheDocument();
    await waitFor(() => {
      expect(client.streamTaskStatus).toHaveBeenCalled();
      expect(client.getTaskStatus).toHaveBeenCalled();
    });
  });

  it("surfaces session timeout guidance when hydration gets a 401", async () => {
    const client = createClient({
      getProjects: vi.fn().mockRejectedValue(new ApiError("Expired refresh session", 401))
    });
    render(<App client={client} />);

    fireEvent.click(screen.getByRole("button", { name: "Start Login" }));
    await screen.findByText("MFA Challenge");
    fireEvent.click(screen.getByRole("button", { name: "Complete MFA" }));

    expect(await screen.findByText("Session expired")).toBeInTheDocument();
    expect(await screen.findByText("Reauthenticate to continue operating in this console.")).toBeInTheDocument();
  });
});
