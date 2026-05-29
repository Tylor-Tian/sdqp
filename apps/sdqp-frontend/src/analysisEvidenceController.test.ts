import { describe, expect, it, vi } from "vitest";
import type {
  AnalysisTemplate,
  FrontendClient,
  PivotAnalysis,
  QueryTaskStatus,
  SnapshotPage
} from "./api";
import {
  type AuditSearchConfig,
  type AnalysisWorkbenchConfig,
  type EvidenceExportConfig,
  applyTaskUpdateCommand,
  authorizeEvidenceDownloadCommand,
  deleteTemplateCommand,
  generateEvidencePackageCommand,
  loadAuditViewCommand,
  loadDrilldownCommand,
  loadSelectedTemplateCommand,
  loadSnapshotArtifactsCommand,
  previewEvidenceDownloadCommand,
  refreshAnalysisTemplatesCommand,
  saveCurrentTemplateCommand,
  selectTemplateCommand,
  submitAsyncQueryCommand,
  toggleTemplateVisibilityCommand
} from "./analysisEvidenceController";

const template: AnalysisTemplate = {
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
};

const pivot: PivotAnalysis = {
  snapshot_id: "snapshot-a",
  dimension: "department",
  metric: "record_count",
  buckets: [{ key: "fraud", value: 1 }],
  watermark_text: "tenant-alpha / project-alpha / user-analyst"
};

const snapshotPage: SnapshotPage = {
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
    }
  ],
  watermark_text: "tenant-alpha / project-alpha / user-analyst"
};

const workbenchConfig: AnalysisWorkbenchConfig = {
  dataSourceId: "datasource-rpc",
  sourceType: "rpc",
  detailFields: ["employee_id", "department"],
  pageSize: 5,
  pivotDimension: "employee_id",
  pivotMetric: "sum",
  pivotMetricField: "employee_id",
  pivotPercentile: null
};

const evidenceExportConfig: EvidenceExportConfig = {
  template: "eu",
  exportBody: "cross-border export"
};

const auditSearchConfig: AuditSearchConfig = {
  action: "export",
  limit: 25
};

function createClient(overrides?: Partial<FrontendClient>): FrontendClient {
  return {
    setSession: vi.fn(),
    beginLogin: vi.fn(),
    verifyMfa: vi.fn(),
    refreshSession: vi.fn(),
    logout: vi.fn(),
    reportDevicePosture: vi.fn(),
    verifyStepUp: vi.fn(),
    getProjects: vi.fn(),
    changeProjectState: vi.fn(),
    submitPermissionApplication: vi.fn(),
    getPermissionGrants: vi.fn(),
    getApprovalTasks: vi.fn(),
    submitApprovalAction: vi.fn(),
    submitQuery: vi.fn().mockResolvedValue({
      task_id: "task-a",
      status: "running",
      websocket_path: "/v1/tasks/task-a/ws"
    }),
    streamTaskStatus: vi.fn(),
    getTaskStatus: vi.fn(),
    getSnapshotPage: vi.fn().mockResolvedValue(snapshotPage),
    getSnapshotPageArrowIpc: vi.fn(),
    getPivot: vi.fn().mockResolvedValue(pivot),
    getPivotArrowIpc: vi.fn(),
    getDrilldown: vi.fn().mockResolvedValue(snapshotPage),
    listAnalysisTemplates: vi.fn().mockResolvedValue({
      templates: [template]
    }),
    createAnalysisTemplate: vi.fn().mockResolvedValue(template),
    getAnalysisTemplate: vi.fn().mockResolvedValue(template),
    updateAnalysisTemplate: vi.fn(),
    publishAnalysisTemplate: vi.fn().mockResolvedValue({
      ...template,
      visibility: "published",
      published_at: "2026-04-05T10:00:00Z"
    }),
    unpublishAnalysisTemplate: vi.fn().mockResolvedValue(template),
    deleteAnalysisTemplate: vi.fn().mockResolvedValue({ template_id: "template-a", deleted: true }),
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
    getUebaAlerts: vi.fn(),
    getUebaBaselines: vi.fn(),
    ...overrides
  };
}

describe("analysisEvidenceController", () => {
  it("refreshes template options and falls back to the first available selection", async () => {
    const client = createClient();

    const result = await refreshAnalysisTemplatesCommand({
      client,
      selectedTemplateId: "missing-template"
    });

    expect(result.templates).toHaveLength(1);
    expect(result.selectedTemplateId).toBe("template-a");
  });

  it("submits async queries and returns the initial task state", async () => {
    const client = createClient();

    const result = await submitAsyncQueryCommand({
      client,
      workbenchConfig
    });

    expect(client.submitQuery).toHaveBeenCalledWith({
      dataSourceId: "datasource-rpc",
      sourceType: "rpc",
      fields: ["employee_id", "department"]
    });
    expect(result.activeDataSourceId).toBe("datasource-rpc");
    expect(result.taskStreamPath).toBe("/v1/tasks/task-a/ws");
    expect(result.task).toEqual({
      task_id: "task-a",
      state: "running",
      snapshot_id: null,
      cache_hit: false,
      error: null
    });
  });

  it("loads snapshot artifacts and applies completed or failed task outcomes", async () => {
    const client = createClient();
    const artifacts = await loadSnapshotArtifactsCommand({
      client,
      snapshotId: "snapshot-a",
      template: null,
      fallbackConfig: workbenchConfig
    });

    expect(artifacts.snapshotPage.snapshot_id).toBe("snapshot-a");
    expect(artifacts.pivot.dimension).toBe("department");
    expect(client.getSnapshotPage).toHaveBeenCalledWith("snapshot-a", 5);
    expect(client.getPivot).toHaveBeenCalledWith("snapshot-a", "employee_id", {
      metric: "sum",
      metricField: "employee_id",
      percentile: undefined
    });

    const loadSnapshotArtifacts = vi.fn().mockResolvedValue(artifacts);
    const completed = await applyTaskUpdateCommand({
      nextTask: {
        task_id: "task-a",
        state: "completed",
        snapshot_id: "snapshot-a",
        cache_hit: false,
        error: null
      } satisfies QueryTaskStatus,
      activeTemplate: template,
      loadSnapshotArtifacts
    });
    const failed = await applyTaskUpdateCommand({
      nextTask: {
        task_id: "task-a",
        state: "failed",
        snapshot_id: null,
        cache_hit: false,
        error: "boom"
      } satisfies QueryTaskStatus,
      activeTemplate: template,
      loadSnapshotArtifacts
    });

    expect(loadSnapshotArtifacts).toHaveBeenCalledWith("snapshot-a", template);
    expect(completed.statusMessage).toBe("Query task-a completed and artifacts loaded.");
    expect(failed.securityNotice?.title).toBe("Query execution halted");
    expect(failed.statusMessage).toBe("boom");
  });

  it("handles template save, load, select, toggle, and delete commands", async () => {
    const client = createClient();
    const saveResult = await saveCurrentTemplateCommand({
      client,
      templateName: "Fraud triage",
      templateDescription: "",
      workbenchConfig
    });
    const loadSnapshotArtifacts = vi.fn().mockResolvedValue({
      snapshotPage,
      pivot
    });
    const loadResult = await loadSelectedTemplateCommand({
      client,
      selectedTemplateId: "template-a",
      activeDataSourceId: "datasource-rest",
      currentSnapshotId: "snapshot-a",
      loadSnapshotArtifacts
    });
    const selectResult = selectTemplateCommand(template);
    const toggleResult = await toggleTemplateVisibilityCommand({
      client,
      template
    });
    const deleteResult = await deleteTemplateCommand({
      client,
      template,
      activeTemplateId: "template-a",
      selectedTemplateId: "template-a"
    });

    expect(saveResult.analysisMessage).toBe("Saved template Fraud triage.");
    expect(loadSnapshotArtifacts).toHaveBeenCalledWith("snapshot-a", template);
    expect(loadResult.analysisMessage).toBe("Loaded template Fraud triage.");
    expect(loadResult.workbenchConfig).toEqual({
      dataSourceId: "datasource-rest",
      sourceType: "rest",
      detailFields: ["employee_id", "department"],
      pageSize: 2,
      pivotDimension: "department",
      pivotMetric: "record_count",
      pivotMetricField: null,
      pivotPercentile: null
    });
    expect(selectResult.selectedTemplateId).toBe("template-a");
    expect(selectResult.workbenchConfig.dataSourceId).toBe("datasource-rest");
    expect(toggleResult.analysisMessage).toBe("Fraud triage is now published.");
    expect(deleteResult).toEqual({
      clearActiveTemplate: true,
      clearSelectedTemplate: true,
      analysisMessage: "Deleted template Fraud triage."
    });
  });

  it("handles evidence export, download authorization, preview, drilldown, and audit lookup commands", async () => {
    const client = createClient();

    const exportTask = await generateEvidencePackageCommand({
      client,
      snapshotId: "snapshot-a",
      exportConfig: evidenceExportConfig
    });
    const authorization = await authorizeEvidenceDownloadCommand({
      client,
      exportTask
    });
    const preview = await authorizeEvidenceDownloadCommand({
      client,
      exportTask: null
    });
    const filePreview = await previewEvidenceDownloadCommand({
      client,
      downloadAuthorization: authorization
    });
    const drilldown = await loadDrilldownCommand({
      client,
      pivot,
      detailFields: ["employee_id", "department"],
      pivotDimension: "employee_id",
      bucketKey: "fraud"
    });
    const auditMessage = await loadAuditViewCommand({
      client,
      auditFilters: auditSearchConfig
    });

    expect(exportTask.exportTask.package_id).toBe("package-a");
    expect(exportTask.summary).toEqual({
      packageId: "package-a",
      snapshotId: "snapshot-a",
      template: "china",
      fileName: "evidence.txt",
      mediaType: "text/plain",
      auditEventCount: 3,
      auditChainValid: true,
      verificationReady: true,
      manifestDigest: "digest-a",
      timestampAuthority: "mock-tsa",
      anchorNetwork: "mock-chain",
      anchorTransactionId: "tx-a",
      watermarkText: "tenant-alpha / project-alpha / user-analyst",
      completedAt: "2026-03-30T09:01:00Z"
    });
    expect(client.exportEvidence).toHaveBeenCalledWith({
      snapshotId: "snapshot-a",
      template: "eu",
      exportBody: "cross-border export"
    });
    expect(authorization?.authorization.download_token).toBe("download-a");
    expect(authorization?.summary).toEqual({
      downloadToken: "download-a",
      fileName: "evidence.txt",
      mediaType: "text/plain",
      expiresAt: "2026-03-30T09:10:00Z"
    });
    expect(preview).toBeNull();
    expect(filePreview?.preview.fileName).toBe("evidence.txt");
    expect(filePreview?.summary).toEqual({
      fileName: "evidence.txt",
      contentType: "text/plain",
      lineCount: 1,
      characterCount: 16,
      previewLines: ["download preview"],
      truncated: false
    });
    expect(drilldown?.page.snapshot_id).toBe("snapshot-a");
    expect(drilldown?.summary).toEqual({
      snapshotId: "snapshot-a",
      dimension: "employee_id",
      bucketKey: "fraud",
      bucketValue: 1,
      metric: "record_count",
      rowCount: 1,
      columnCount: 2,
      maskedFieldCount: 0,
      plainFieldCount: 1,
      hasMoreRows: false,
      watermarkText: "tenant-alpha / project-alpha / user-analyst",
      fieldPolicies: ["employee_id / plain / low"]
    });
    expect(client.getDrilldown).toHaveBeenCalledWith({
      snapshotId: "snapshot-a",
      dimension: "employee_id",
      value: "fraud",
      fields: ["employee_id", "department"]
    });
    expect(client.searchAudit).toHaveBeenCalledWith({
      action: "export",
      limit: 25
    });
    expect(auditMessage).toEqual({
      chainValid: true,
      totalMatches: 1,
      actionLabel: "export",
      limit: 25,
      events: []
    });
  });
});
