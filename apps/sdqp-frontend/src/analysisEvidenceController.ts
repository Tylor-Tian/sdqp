import type {
  AnalysisTemplate,
  AuditSearchResponse,
  DownloadPreview,
  EvidenceExportResponse,
  ExportDownloadAuthorizationResponse,
  FrontendClient,
  PivotAnalysis,
  QueryPriorityLevel,
  QueryTaskStatus,
  SnapshotPage
} from "./api";
import type { SecurityNotice } from "./authWorkspaceController";

type TemplateClient = Pick<
  FrontendClient,
  | "listAnalysisTemplates"
  | "createAnalysisTemplate"
  | "getAnalysisTemplate"
  | "publishAnalysisTemplate"
  | "unpublishAnalysisTemplate"
  | "deleteAnalysisTemplate"
>;

type AnalysisClient = Pick<FrontendClient, "submitQuery" | "getSnapshotPage" | "getPivot" | "getDrilldown">;
type EvidenceClient = Pick<FrontendClient, "exportEvidence" | "authorizeDownload" | "downloadExport">;
type AuditClient = Pick<FrontendClient, "searchAudit">;

export type SnapshotArtifacts = {
  snapshotPage: SnapshotPage;
  pivot: PivotAnalysis;
};

export type AnalysisWorkbenchConfig = {
  dataSourceId: string;
  sourceType: string;
  detailFields: string[];
  queryPriority: QueryPriorityLevel;
  pageSize: number;
  pivotDimension: string;
  pivotMetric: string;
  pivotMetricField: string | null;
  pivotPercentile: number | null;
};

type TemplateWorkbenchConfig = Omit<AnalysisWorkbenchConfig, "queryPriority">;

export type WorkbenchRuntimeState = {
  queryPriority: QueryPriorityLevel;
  taskState: string;
  backendRuntimeState: string;
  adapterRuntimeState: string;
  snapshotAccessState: string;
  securityState: "clear" | "step_up_required" | "failure";
  downloadAuthorizationState: "not_requested" | "authorized" | "preview_ready";
  controls: {
    canSubmitQuery: boolean;
    canCancelTask: boolean;
    canRetryQuery: boolean;
    canCompleteStepUp: boolean;
    canAuthorizeDownload: boolean;
    canPreviewDownload: boolean;
  };
  summaryRows: Array<{ label: string; value: string }>;
};

export type EvidenceExportConfig = {
  template: string;
  exportBody: string;
};

export type AuditSearchConfig = {
  action: string;
  limit: number;
};

export type EvidenceExportSummary = {
  packageId: string;
  snapshotId: string;
  template: string;
  fileName: string;
  mediaType: string;
  auditEventCount: number;
  auditChainValid: boolean;
  verificationReady: boolean;
  manifestDigest: string;
  timestampAuthority: string;
  anchorNetwork: string;
  anchorTransactionId: string;
  watermarkText: string;
  completedAt: string | null;
};

export type DownloadAuthorizationSummary = {
  downloadToken: string;
  fileName: string;
  mediaType: string;
  expiresAt: string;
};

export type DownloadPreviewSummary = {
  fileName: string;
  contentType: string;
  lineCount: number;
  characterCount: number;
  previewLines: string[];
  truncated: boolean;
};

export type DrilldownSummary = {
  snapshotId: string;
  dimension: string;
  bucketKey: string;
  bucketValue: number | null;
  metric: string;
  rowCount: number;
  columnCount: number;
  maskedFieldCount: number;
  plainFieldCount: number;
  hasMoreRows: boolean;
  watermarkText: string;
  fieldPolicies: string[];
};

export type AuditEventSummary = {
  eventId: string;
  timestamp: string;
  actorUserId: string;
  action: string;
  result: string;
  projectId: string | null;
  resourceId: string;
  context: string;
};

export type AuditViewSummary = {
  chainValid: boolean;
  totalMatches: number;
  actionLabel: string;
  limit: number;
  events: AuditEventSummary[];
};

const PREVIEW_LINE_LIMIT = 4;

function summarizeFieldPolicies(snapshotPage: SnapshotPage) {
  return snapshotPage.field_policies.map((policy) => {
    const status = policy.masked ? "masked" : "plain";
    return `${policy.field_name} / ${status} / ${policy.watermark_strength}`;
  });
}

function summarizeEvidenceExport(exportTask: EvidenceExportResponse): EvidenceExportSummary {
  return {
    packageId: exportTask.package_id,
    snapshotId: exportTask.snapshot_id,
    template: exportTask.template,
    fileName: exportTask.file_name,
    mediaType: exportTask.media_type,
    auditEventCount: exportTask.audit_event_count,
    auditChainValid: exportTask.audit_chain_valid,
    verificationReady: exportTask.verification_ready,
    manifestDigest: exportTask.manifest_digest,
    timestampAuthority: exportTask.timestamp_authority,
    anchorNetwork: exportTask.anchor_network,
    anchorTransactionId: exportTask.anchor_transaction_id,
    watermarkText: exportTask.watermark_text,
    completedAt: exportTask.completed_at ?? null
  };
}

function summarizeDownloadAuthorization(
  downloadAuthorization: ExportDownloadAuthorizationResponse
): DownloadAuthorizationSummary {
  return {
    downloadToken: downloadAuthorization.download_token,
    fileName: downloadAuthorization.file_name,
    mediaType: downloadAuthorization.media_type,
    expiresAt: downloadAuthorization.expires_at
  };
}

function summarizeDownloadPreview(downloadPreview: DownloadPreview): DownloadPreviewSummary {
  const previewLines =
    downloadPreview.content.length === 0
      ? []
      : downloadPreview.content.replace(/\r\n/g, "\n").split("\n");

  return {
    fileName: downloadPreview.fileName,
    contentType: downloadPreview.contentType,
    lineCount: previewLines.length,
    characterCount: downloadPreview.content.length,
    previewLines: previewLines.slice(0, PREVIEW_LINE_LIMIT),
    truncated: previewLines.length > PREVIEW_LINE_LIMIT
  };
}

function summarizeDrilldown(
  snapshotPage: SnapshotPage,
  pivot: PivotAnalysis,
  bucketKey: string,
  dimension: string
): DrilldownSummary {
  const bucket = pivot.buckets.find((candidate) => candidate.key === bucketKey) ?? null;
  const maskedFieldCount = snapshotPage.field_policies.filter((policy) => policy.masked).length;

  return {
    snapshotId: snapshotPage.snapshot_id,
    dimension,
    bucketKey,
    bucketValue: bucket?.value ?? null,
    metric: pivot.metric,
    rowCount: snapshotPage.rows.length,
    columnCount: snapshotPage.columns.length,
    maskedFieldCount,
    plainFieldCount: snapshotPage.field_policies.length - maskedFieldCount,
    hasMoreRows: snapshotPage.next_cursor !== null,
    watermarkText: snapshotPage.watermark_text,
    fieldPolicies: summarizeFieldPolicies(snapshotPage)
  };
}

function summarizeAuditView(
  response: AuditSearchResponse,
  auditFilters: AuditSearchConfig
): AuditViewSummary {
  return {
    chainValid: response.chain_valid,
    totalMatches: response.total_matches,
    actionLabel: auditFilters.action || "all actions",
    limit: auditFilters.limit,
    events: response.events.map((event) => ({
      eventId: event.event_id,
      timestamp: event.timestamp,
      actorUserId: event.actor_user_id,
      action: event.action,
      result: event.result,
      projectId: event.project_id ?? null,
      resourceId: event.resource_id,
      context: event.context
    }))
  };
}

function templateToWorkbenchConfig(template: AnalysisTemplate): TemplateWorkbenchConfig {
  return {
    dataSourceId: template.data_source_id,
    sourceType: "rest",
    detailFields: template.config.detail_fields,
    pageSize: template.config.page_size ?? 2,
    pivotDimension: template.config.pivot_dimension,
    pivotMetric: template.config.pivot_metric,
    pivotMetricField: template.config.pivot_metric_field ?? null,
    pivotPercentile: template.config.pivot_percentile ?? null
  };
}

export function buildWorkbenchRuntimeState({
  task,
  queryPriority,
  snapshotPage,
  securityNotice,
  stepUpRequired,
  exportTask,
  downloadAuthorization,
  downloadPreview
}: {
  task: QueryTaskStatus | null;
  queryPriority: QueryPriorityLevel;
  snapshotPage: SnapshotPage | null;
  securityNotice: SecurityNotice | null;
  stepUpRequired: boolean;
  exportTask: EvidenceExportResponse | null;
  downloadAuthorization: ExportDownloadAuthorizationResponse | null;
  downloadPreview: DownloadPreview | null;
}): WorkbenchRuntimeState {
  const backendRuntime = task?.runtime ?? null;
  const taskState = task?.state ?? "idle";
  const snapshotAccessState =
    backendRuntime?.secure_snapshot_access ??
    (snapshotPage ? "authorized_encrypted_snapshot" : "no_snapshot_selected");
  const downloadAuthorizationState = downloadPreview
    ? "preview_ready"
    : downloadAuthorization
      ? "authorized"
      : "not_requested";
  const securityState = stepUpRequired
    ? "step_up_required"
    : securityNotice?.kind === "failure"
      ? "failure"
      : "clear";
  const taskInFlight = taskState === "pending" || taskState === "running";
  const securityClear = securityState === "clear";
  const secureSnapshotReady =
    Boolean(backendRuntime?.controls.can_access_snapshot) ||
    snapshotAccessState === "authorized_encrypted_snapshot" ||
    snapshotAccessState === "authorized_cache_snapshot";
  const controls = {
    canSubmitQuery: securityClear && !taskInFlight,
    canCancelTask: Boolean(backendRuntime?.controls.can_cancel),
    canRetryQuery:
      securityClear &&
      (Boolean(backendRuntime?.controls.can_retry) ||
        taskState === "failed" ||
        taskState === "cancelled"),
    canCompleteStepUp: stepUpRequired,
    canAuthorizeDownload: Boolean(
      securityClear && secureSnapshotReady && exportTask?.download_ready && !downloadAuthorization
    ),
    canPreviewDownload: Boolean(securityClear && secureSnapshotReady && downloadAuthorization && !downloadPreview)
  };
  const appliedPriority = (task?.priority?.label as QueryPriorityLevel | undefined) ?? queryPriority;

  return {
    queryPriority: appliedPriority,
    taskState,
    backendRuntimeState: backendRuntime?.runtime_state ?? taskState,
    adapterRuntimeState:
      backendRuntime?.adapter_runtime_state ?? backendRuntime?.adapter_availability ?? "not reported",
    snapshotAccessState,
    securityState,
    downloadAuthorizationState,
    controls,
    summaryRows: [
      { label: "Task Priority", value: `${appliedPriority} (${task?.priority?.value ?? "pending"})` },
      { label: "Runtime State", value: backendRuntime?.runtime_state ?? taskState },
      { label: "Adapter Runtime", value: backendRuntime?.adapter_runtime_state ?? "not reported" },
      { label: "Secure Snapshot Access", value: snapshotAccessState },
      { label: "Step-Up", value: securityState === "step_up_required" ? "required" : "clear" },
      { label: "Download Authorization", value: downloadAuthorizationState }
    ]
  };
}

export async function refreshAnalysisTemplatesCommand({
  client,
  selectedTemplateId
}: {
  client: Pick<TemplateClient, "listAnalysisTemplates">;
  selectedTemplateId: string;
}) {
  const response = await client.listAnalysisTemplates();
  return {
    templates: response.templates,
    selectedTemplateId: response.templates.some((template) => template.template_id === selectedTemplateId)
      ? selectedTemplateId
      : (response.templates[0]?.template_id ?? "")
  };
}

export async function loadSnapshotArtifactsCommand({
  client,
  snapshotId,
  template,
  fallbackConfig
}: {
  client: Pick<AnalysisClient, "getSnapshotPage" | "getPivot">;
  snapshotId: string;
  template?: AnalysisTemplate | null;
  fallbackConfig?: AnalysisWorkbenchConfig | null;
}): Promise<SnapshotArtifacts> {
  const appliedConfig = template ? templateToWorkbenchConfig(template) : fallbackConfig;
  const pageSize = appliedConfig?.pageSize ?? 2;
  const pivotDimension = appliedConfig?.pivotDimension ?? "department";
  const pivotOptions = {
    metric: appliedConfig?.pivotMetric,
    metricField: appliedConfig?.pivotMetricField ?? undefined,
    percentile: appliedConfig?.pivotPercentile ?? undefined
  };
  const [snapshotPage, pivot] = await Promise.all([
    client.getSnapshotPage(snapshotId, pageSize),
    client.getPivot(snapshotId, pivotDimension, pivotOptions)
  ]);
  return { snapshotPage, pivot };
}

export async function applyTaskUpdateCommand({
  nextTask,
  activeTemplate,
  loadSnapshotArtifacts
}: {
  nextTask: QueryTaskStatus;
  activeTemplate: AnalysisTemplate | null;
  loadSnapshotArtifacts: (snapshotId: string, template?: AnalysisTemplate | null) => Promise<unknown>;
}) {
  if (nextTask.state === "completed" && nextTask.snapshot_id) {
    await loadSnapshotArtifacts(nextTask.snapshot_id, activeTemplate);
    return {
      statusMessage: `Query ${nextTask.task_id} completed and artifacts loaded.`
    };
  }

  if (nextTask.state === "failed" || nextTask.state === "cancelled") {
    return {
      securityNotice: {
        kind: "failure",
        title: "Query execution halted",
        body: nextTask.error ?? `Task ${nextTask.state}.`
      } satisfies SecurityNotice,
      statusMessage: nextTask.error ?? `Query ${nextTask.state}.`
    };
  }

  return {};
}

export async function submitAsyncQueryCommand({
  client,
  workbenchConfig
}: {
  client: Pick<AnalysisClient, "submitQuery">;
  workbenchConfig: Pick<
    AnalysisWorkbenchConfig,
    "dataSourceId" | "sourceType" | "detailFields" | "queryPriority"
  >;
}) {
  const priority =
    workbenchConfig.queryPriority === "normal" ? undefined : workbenchConfig.queryPriority;
  const response = await client.submitQuery({
    dataSourceId: workbenchConfig.dataSourceId,
    sourceType: workbenchConfig.sourceType,
    fields: workbenchConfig.detailFields,
    ...(priority ? { priority } : {})
  });
  return {
    activeDataSourceId: workbenchConfig.dataSourceId,
    taskStreamPath: response.websocket_path,
    task: {
      task_id: response.task_id,
      state: response.status,
      snapshot_id: null,
      cache_hit: false,
      error: null,
      priority: response.priority,
      runtime: response.runtime
    } satisfies QueryTaskStatus
  };
}

export async function saveCurrentTemplateCommand({
  client,
  templateName,
  templateDescription,
  workbenchConfig
}: {
  client: Pick<TemplateClient, "createAnalysisTemplate">;
  templateName: string;
  templateDescription: string;
  workbenchConfig: AnalysisWorkbenchConfig;
}) {
  const pivotMetricField =
    workbenchConfig.pivotMetric === "record_count"
      ? null
      : (workbenchConfig.pivotMetricField ?? workbenchConfig.detailFields[0] ?? null);
  const template = await client.createAnalysisTemplate({
    name: templateName,
    description: templateDescription || null,
    dataSourceId: workbenchConfig.dataSourceId,
    config: {
      page_size: workbenchConfig.pageSize,
      detail_fields: workbenchConfig.detailFields,
      pivot_dimension: workbenchConfig.pivotDimension,
      pivot_metric: workbenchConfig.pivotMetric,
      pivot_metric_field: pivotMetricField,
      pivot_percentile: workbenchConfig.pivotPercentile
    }
  });
  return {
    template,
    selectedTemplateId: template.template_id,
    analysisMessage: `Saved template ${template.name}.`
  };
}

export async function loadSelectedTemplateCommand({
  client,
  selectedTemplateId,
  activeDataSourceId,
  currentSnapshotId,
  loadSnapshotArtifacts
}: {
  client: Pick<TemplateClient, "getAnalysisTemplate">;
  selectedTemplateId: string;
  activeDataSourceId: string;
  currentSnapshotId: string | null;
  loadSnapshotArtifacts: (snapshotId: string, template?: AnalysisTemplate | null) => Promise<SnapshotArtifacts>;
}) {
  const template = await client.getAnalysisTemplate(selectedTemplateId);
  const result: {
    template: AnalysisTemplate;
    templateName: string;
    templateDescription: string;
    analysisMessage: string;
    workbenchConfig: TemplateWorkbenchConfig;
    snapshotArtifacts?: SnapshotArtifacts;
  } = {
    template,
    templateName: template.name,
    templateDescription: template.description ?? "",
    analysisMessage: `Loaded template ${template.name}.`,
    workbenchConfig: templateToWorkbenchConfig(template)
  };

  if (template.data_source_id !== activeDataSourceId) {
    result.analysisMessage = `Template ${template.name} targets ${template.data_source_id}; run a matching query to apply it.`;
    return result;
  }

  if (currentSnapshotId) {
    result.snapshotArtifacts = await loadSnapshotArtifacts(currentSnapshotId, template);
  }

  return result;
}

export function selectTemplateCommand(template: AnalysisTemplate) {
  return {
    selectedTemplateId: template.template_id,
    templateName: template.name,
    templateDescription: template.description ?? "",
    workbenchConfig: templateToWorkbenchConfig(template)
  };
}

export async function toggleTemplateVisibilityCommand({
  client,
  template
}: {
  client: Pick<TemplateClient, "publishAnalysisTemplate" | "unpublishAnalysisTemplate">;
  template: AnalysisTemplate;
}) {
  const nextTemplate =
    template.visibility === "published"
      ? await client.unpublishAnalysisTemplate(template.template_id)
      : await client.publishAnalysisTemplate(template.template_id);
  return {
    nextTemplate,
    analysisMessage: `${nextTemplate.name} is now ${nextTemplate.visibility}.`
  };
}

export async function deleteTemplateCommand({
  client,
  template,
  activeTemplateId,
  selectedTemplateId
}: {
  client: Pick<TemplateClient, "deleteAnalysisTemplate">;
  template: AnalysisTemplate;
  activeTemplateId: string | null;
  selectedTemplateId: string;
}) {
  await client.deleteAnalysisTemplate(template.template_id);
  return {
    clearActiveTemplate: activeTemplateId === template.template_id,
    clearSelectedTemplate: selectedTemplateId === template.template_id,
    analysisMessage: `Deleted template ${template.name}.`
  };
}

export async function generateEvidencePackageCommand({
  client,
  snapshotId,
  exportConfig
}: {
  client: Pick<EvidenceClient, "exportEvidence">;
  snapshotId: string;
  exportConfig: EvidenceExportConfig;
}) {
  const exportTask = await client.exportEvidence({
    snapshotId,
    template: exportConfig.template,
    exportBody: exportConfig.exportBody
  });
  return {
    exportTask,
    summary: summarizeEvidenceExport(exportTask)
  };
}

export async function authorizeEvidenceDownloadCommand({
  client,
  exportTask
}: {
  client: Pick<EvidenceClient, "authorizeDownload">;
  exportTask: EvidenceExportResponse | null;
}) {
  if (!exportTask) {
    return null;
  }

  const authorization = await client.authorizeDownload(exportTask.task_id, 300);
  return {
    authorization,
    summary: summarizeDownloadAuthorization(authorization)
  };
}

export async function previewEvidenceDownloadCommand({
  client,
  downloadAuthorization
}: {
  client: Pick<EvidenceClient, "downloadExport">;
  downloadAuthorization: ExportDownloadAuthorizationResponse | null;
}) {
  if (!downloadAuthorization) {
    return null;
  }

  const preview = await client.downloadExport(downloadAuthorization.download_token);
  return {
    preview,
    summary: summarizeDownloadPreview(preview)
  };
}

export async function loadDrilldownCommand({
  client,
  pivot,
  detailFields,
  pivotDimension,
  bucketKey
}: {
  client: Pick<AnalysisClient, "getDrilldown">;
  pivot: PivotAnalysis | null;
  detailFields: string[];
  pivotDimension: string;
  bucketKey: string;
}) {
  if (!pivot) {
    return null;
  }

  const page = await client.getDrilldown({
    snapshotId: pivot.snapshot_id,
    dimension: pivotDimension,
    value: bucketKey,
    fields: detailFields
  });

  return {
    page,
    summary: summarizeDrilldown(page, pivot, bucketKey, pivotDimension)
  };
}

export async function loadAuditViewCommand({
  client,
  auditFilters
}: {
  client: Pick<AuditClient, "searchAudit">;
  auditFilters: AuditSearchConfig;
}) {
  const response = await client.searchAudit({
    action: auditFilters.action || undefined,
    limit: auditFilters.limit
  });
  return summarizeAuditView(response, auditFilters);
}
