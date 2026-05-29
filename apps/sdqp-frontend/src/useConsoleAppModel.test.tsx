import { act, renderHook, waitFor } from "@testing-library/react";
import { describe, expect, it, vi } from "vitest";
import { ApiError, type FrontendClient } from "./api";
import { useConsoleAppModel } from "./useConsoleAppModel";

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
    createAnalysisTemplate: vi.fn(),
    getAnalysisTemplate: vi.fn(),
    updateAnalysisTemplate: vi.fn(),
    publishAnalysisTemplate: vi.fn(),
    unpublishAnalysisTemplate: vi.fn(),
    deleteAnalysisTemplate: vi.fn(),
    searchAudit: vi.fn().mockResolvedValue({
      chain_valid: true,
      total_matches: 1,
      events: []
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
    getExportTask: vi.fn(),
    authorizeDownload: vi.fn(),
    downloadExport: vi.fn(),
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

describe("useConsoleAppModel", () => {
  it("hydrates the workspace and assembles the shell props after MFA", async () => {
    const client = createClient();
    const { result } = renderHook(() =>
      useConsoleAppModel({
        client,
        pollIntervalMs: 1
      })
    );

    expect(result.current.showWorkspace).toBe(false);

    act(() => {
      result.current.heroPanelProps.onStartLogin();
    });

    await waitFor(() => {
      expect(result.current.mfaChallengePanelProps.challenge?.pendingSessionId).toBe("pending-a");
    });

    act(() => {
      result.current.heroPanelProps.onCompleteMfa();
    });

    await waitFor(() => {
      expect(result.current.showWorkspace).toBe(true);
      expect(result.current.projectControlPanelProps.projectId).toBe("project-alpha");
      expect(result.current.permissionsPanelProps.permissionGrants).toHaveLength(1);
      expect(result.current.heroPanelProps.statusMessage).toBe("MFA verified and workspace hydrated.");
    });
  });

  it("wires query completion into detail and analysis panel props", async () => {
    const client = createClient();
    const { result } = renderHook(() =>
      useConsoleAppModel({
        client,
        pollIntervalMs: 1
      })
    );

    act(() => {
      result.current.heroPanelProps.onStartLogin();
    });
    await waitFor(() => {
      expect(result.current.mfaChallengePanelProps.challenge).not.toBeNull();
    });
    act(() => {
      result.current.heroPanelProps.onCompleteMfa();
    });
    await waitFor(() => {
      expect(result.current.showWorkspace).toBe(true);
    });

    act(() => {
      result.current.queryWorkbenchPanelProps.onDataSourceIdChange("datasource-rpc");
      result.current.queryWorkbenchPanelProps.onSelectedFieldToggle("employee_email", true);
      result.current.analysisTemplatesPanelProps.onPageSizeChange(10);
      result.current.analysisTemplatesPanelProps.onPivotDimensionChange("employee_id");
      result.current.analysisTemplatesPanelProps.onPivotMetricChange("sum");
    });

    await waitFor(() => {
      expect(result.current.analysisTemplatesPanelProps.pivotMetricField).toBe("employee_id");
    });

    act(() => {
      result.current.queryWorkbenchPanelProps.onSubmitAsyncQuery();
    });

    await waitFor(() => {
      expect(client.submitQuery).toHaveBeenCalledWith({
        dataSourceId: "datasource-rpc",
        sourceType: "rpc",
        fields: ["employee_id", "department", "employee_email"]
      });
      expect(client.streamTaskStatus).toHaveBeenCalledWith(
        "task-a",
        expect.objectContaining({ path: "/v1/tasks/task-a/ws", replayLast: true })
      );
      expect(result.current.queryWorkbenchPanelProps.task?.state).toBe("completed");
      expect(client.getSnapshotPage).toHaveBeenCalledWith("snapshot-a", 10);
      expect(client.getPivot).toHaveBeenCalledWith("snapshot-a", "employee_id", {
        metric: "sum",
        metricField: "employee_id",
        percentile: undefined
      });
    });
  });

  it("threads configurable evidence export and audit search state through the shell props", async () => {
    const client = createClient();
    const { result } = renderHook(() =>
      useConsoleAppModel({
        client,
        pollIntervalMs: 1
      })
    );

    act(() => {
      result.current.heroPanelProps.onStartLogin();
    });
    await waitFor(() => {
      expect(result.current.mfaChallengePanelProps.challenge).not.toBeNull();
    });
    act(() => {
      result.current.heroPanelProps.onCompleteMfa();
    });
    await waitFor(() => {
      expect(result.current.showWorkspace).toBe(true);
    });

    act(() => {
      result.current.queryWorkbenchPanelProps.onSubmitAsyncQuery();
    });

    await waitFor(() => {
      expect(result.current.queryWorkbenchPanelProps.task?.state).toBe("completed");
      expect(client.getSnapshotPage).toHaveBeenCalledWith("snapshot-a", 2);
    });

    act(() => {
      result.current.evidenceExportPanelProps.onExportTemplateChange("eu");
      result.current.evidenceExportPanelProps.onExportBodyChange("cross-border export");
      result.current.uebaAuditPanelProps.onAuditActionChange("export");
      result.current.uebaAuditPanelProps.onAuditLimitChange(25);
    });

    act(() => {
      result.current.evidenceExportPanelProps.onGenerateEvidencePackage();
      result.current.uebaAuditPanelProps.onLoadAuditView();
    });

    await waitFor(() => {
      expect(client.exportEvidence).toHaveBeenCalledWith({
        snapshotId: "snapshot-a",
        template: "eu",
        exportBody: "cross-border export"
      });
      expect(result.current.evidenceExportPanelProps.exportSummary?.packageId).toBe("package-a");
      expect(client.searchAudit).toHaveBeenCalledWith({
        action: "export",
        limit: 25
      });
      expect(result.current.uebaAuditPanelProps.auditView).toEqual({
        chainValid: true,
        totalMatches: 1,
        actionLabel: "export",
        limit: 25,
        events: []
      });
    });

  });

  it("surfaces 403 approval failures through the shell-level notice wiring", async () => {
    const client = createClient({
      getApprovalTasks: vi.fn().mockRejectedValue(new ApiError("Forbidden approval queue", 403))
    });
    const { result } = renderHook(() =>
      useConsoleAppModel({
        client,
        pollIntervalMs: 1
      })
    );

    act(() => {
      result.current.heroPanelProps.onStartLogin();
    });
    await waitFor(() => {
      expect(result.current.mfaChallengePanelProps.challenge).not.toBeNull();
    });
    act(() => {
      result.current.heroPanelProps.onCompleteMfa();
    });
    await waitFor(() => {
      expect(result.current.showWorkspace).toBe(true);
    });

    act(() => {
      result.current.approvalQueuePanelProps.onLoadApprovalQueue();
    });

    await waitFor(() => {
      expect(result.current.securityNoticeBannerProps.notice?.title).toBe(
        "Step-up or access upgrade required"
      );
      expect(result.current.heroPanelProps.statusMessage).toBe("Forbidden approval queue");
    });
  });

  it("keeps the workspace active when a protected route returns step-up-required 401", async () => {
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
    const { result } = renderHook(() =>
      useConsoleAppModel({
        client,
        pollIntervalMs: 1
      })
    );

    act(() => {
      result.current.heroPanelProps.onStartLogin();
    });
    await waitFor(() => {
      expect(result.current.mfaChallengePanelProps.challenge).not.toBeNull();
    });
    act(() => {
      result.current.heroPanelProps.onCompleteMfa();
    });
    await waitFor(() => {
      expect(result.current.showWorkspace).toBe(true);
    });

    act(() => {
      result.current.approvalQueuePanelProps.onLoadApprovalQueue();
    });

    await waitFor(() => {
      expect(result.current.showWorkspace).toBe(true);
      expect(result.current.securityNoticeBannerProps.notice?.title).toBe("Step-up required");
      expect(result.current.securityPanelProps.riskResult).toEqual({
        required: true,
        action: "step_up",
        challenge: {
          challengeId: "challenge-a",
          method: "totp",
          reason: "continuous risk assessment requires step-up",
          expiresAt: "2026-04-11T12:00:00Z"
        }
      });
    });
  });
});
