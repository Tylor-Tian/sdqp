import {
  startTransition,
  useEffect,
  useEffectEvent,
  useRef,
  useState
} from "react";
import {
  type AuditSearchConfig,
  type AuditViewSummary,
  type AnalysisWorkbenchConfig,
  type DownloadAuthorizationSummary,
  type DownloadPreviewSummary,
  type DrilldownSummary,
  type EvidenceExportSummary,
  type EvidenceExportConfig,
  applyTaskUpdateCommand,
  authorizeEvidenceDownloadCommand,
  buildWorkbenchRuntimeState,
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
import {
  completeStepUpCommand,
  delegateApprovalCommand,
  evaluateDevicePostureCommand,
  freezeProjectCommand,
  loadApprovalQueueCommand,
  refreshSessionCommand,
  startLoginCommand,
  submitPermissionRequestCommand,
  switchProjectCommand
} from "./controlSurfaceController";
import {
  applySessionState,
  handleAuthWorkspaceError,
  hydrateWorkspaceSession,
  resetWorkspaceState,
  type RiskResult,
  type SecurityNotice
} from "./authWorkspaceController";
import {
  type AnalysisTemplate,
  type ApprovalTask,
  type DownloadPreview,
  type EvidenceExportResponse,
  type ExportDownloadAuthorizationResponse,
  type FrontendClient,
  type MfaChallengeDetails,
  type PermissionApplication,
  type PermissionGrantsResponse,
  type PivotAnalysis,
  type QueryPriorityLevel,
  type ProjectsResponse,
  type QueryTaskStatus,
  type SessionTokens,
  type SnapshotPage,
  type UebaAlerts,
  type UebaBaselines
} from "./api";
import { observeTaskStatus } from "./taskStatusOrchestrator";

export type FieldOption = {
  name: string;
  label: string;
  note: string;
};

export type PersonaOption = {
  key: string;
  username: string;
  label: string;
  mfaCode: string;
};

export type DataSourceOption = {
  id: string;
  label: string;
  sourceType: string;
};

export type EvidenceTemplateOption = {
  value: string;
  label: string;
};

export type AuditActionOption = {
  value: string;
  label: string;
};

type ChallengeState = {
  pendingSessionId: string;
  method: string;
  details?: MfaChallengeDetails | null;
} | null;

export const FIELD_OPTIONS: FieldOption[] = [
  { name: "employee_id", label: "Employee ID", note: "Low-sensitivity identifier" },
  { name: "department", label: "Department", note: "Primary drilldown dimension" },
  { name: "employee_email", label: "Employee Email", note: "Sensitive field / deny-wins validation" }
];

export const PERSONAS: PersonaOption[] = [
  { key: "analyst", username: "analyst", label: "Analyst", mfaCode: "000000" },
  { key: "security", username: "security", label: "Security", mfaCode: "000000" },
  { key: "manager", username: "manager", label: "Manager", mfaCode: "000000" },
  { key: "sysadmin", username: "sysadmin", label: "Sysadmin", mfaCode: "webauthn-ok" }
];

export const DATA_SOURCE_OPTIONS: DataSourceOption[] = [
  { id: "datasource-rest", label: "REST HR Feed", sourceType: "rest" },
  { id: "datasource-rpc", label: "RPC HR Feed", sourceType: "rpc" },
  { id: "datasource-hive", label: "Hive Snapshot", sourceType: "hive" }
];

export const EVIDENCE_TEMPLATE_OPTIONS: EvidenceTemplateOption[] = [
  { value: "china", label: "China Judicial" },
  { value: "eu", label: "EU Regulatory" },
  { value: "us", label: "US Litigation" }
];

export const AUDIT_ACTION_OPTIONS: AuditActionOption[] = [
  { value: "", label: "All Actions" },
  { value: "query", label: "Query" },
  { value: "export", label: "Export" },
  { value: "approval", label: "Approval" }
];

export const PAGE_SIZE_OPTIONS = [2, 5, 10];
export const AUDIT_LIMIT_OPTIONS = [10, 25, 50];
export const QUERY_PRIORITY_OPTIONS: Array<{ value: QueryPriorityLevel; label: string }> = [
  { value: "normal", label: "Normal" },
  { value: "high", label: "High" },
  { value: "critical", label: "Critical" },
  { value: "low", label: "Low" }
];

export const PIVOT_METRIC_OPTIONS = [
  { value: "record_count", label: "Record Count" },
  { value: "sum", label: "Sum" },
  { value: "avg", label: "Average" }
];

const DEFAULT_SELECTED_FIELDS = FIELD_OPTIONS.filter((field) => field.name !== "employee_email").map(
  (field) => field.name
);
const DEFAULT_DATA_SOURCE_ID = DATA_SOURCE_OPTIONS[0]?.id ?? "datasource-rest";
const DEFAULT_SOURCE_TYPE = DATA_SOURCE_OPTIONS[0]?.sourceType ?? "rest";
const DEFAULT_PAGE_SIZE = 2;
const DEFAULT_QUERY_PRIORITY: QueryPriorityLevel = "normal";
const DEFAULT_PIVOT_DIMENSION = "department";
const DEFAULT_PIVOT_METRIC = "record_count";
const DEFAULT_EXPORT_TEMPLATE = EVIDENCE_TEMPLATE_OPTIONS[0]?.value ?? "china";
const DEFAULT_EXPORT_BODY = "stage12 export";
const DEFAULT_AUDIT_ACTION = "query";
const DEFAULT_AUDIT_LIMIT = 10;

function resolveSourceType(dataSourceId: string) {
  return DATA_SOURCE_OPTIONS.find((option) => option.id === dataSourceId)?.sourceType ?? DEFAULT_SOURCE_TYPE;
}

export function buildFieldCatalog() {
  return FIELD_OPTIONS;
}

export function buildPersonaCatalog() {
  return PERSONAS;
}

export function useConsoleAppModel({
  client,
  pollIntervalMs
}: {
  client: FrontendClient;
  pollIntervalMs: number;
}) {
  const [personaKey, setPersonaKey] = useState("analyst");
  const [challenge, setChallenge] = useState<ChallengeState>(null);
  const [session, setSession] = useState<SessionTokens | null>(null);
  const [projects, setProjects] = useState<ProjectsResponse["projects"]>([]);
  const [projectId, setProjectId] = useState("");
  const [projectStateMessage, setProjectStateMessage] = useState("");
  const [permissionApplication, setPermissionApplication] = useState<PermissionApplication | null>(null);
  const [permissionGrants, setPermissionGrants] = useState<PermissionGrantsResponse["grants"]>([]);
  const [approvalTasks, setApprovalTasks] = useState<ApprovalTask[]>([]);
  const [approvalMessage, setApprovalMessage] = useState("");
  const [task, setTask] = useState<QueryTaskStatus | null>(null);
  const [snapshotPage, setSnapshotPage] = useState<SnapshotPage | null>(null);
  const [pivot, setPivot] = useState<PivotAnalysis | null>(null);
  const [drilldownPage, setDrilldownPage] = useState<SnapshotPage | null>(null);
  const [analysisTemplates, setAnalysisTemplates] = useState<AnalysisTemplate[]>([]);
  const [selectedTemplateId, setSelectedTemplateId] = useState("");
  const [templateName, setTemplateName] = useState("Fraud triage");
  const [templateDescription, setTemplateDescription] = useState("");
  const [activeTemplate, setActiveTemplate] = useState<AnalysisTemplate | null>(null);
  const [analysisMessage, setAnalysisMessage] = useState("");
  const [activeDataSourceId, setActiveDataSourceId] = useState(DEFAULT_DATA_SOURCE_ID);
  const [activeSourceType, setActiveSourceType] = useState(DEFAULT_SOURCE_TYPE);
  const [selectedFields, setSelectedFields] = useState(DEFAULT_SELECTED_FIELDS);
  const [queryPriority, setQueryPriority] = useState<QueryPriorityLevel>(DEFAULT_QUERY_PRIORITY);
  const [pageSize, setPageSize] = useState(DEFAULT_PAGE_SIZE);
  const [pivotDimension, setPivotDimension] = useState(DEFAULT_PIVOT_DIMENSION);
  const [pivotMetric, setPivotMetric] = useState(DEFAULT_PIVOT_METRIC);
  const [pivotMetricField, setPivotMetricField] = useState<string | null>(null);
  const [pivotPercentile, setPivotPercentile] = useState<number | null>(null);
  const [exportTemplate, setExportTemplate] = useState(DEFAULT_EXPORT_TEMPLATE);
  const [exportBody, setExportBody] = useState(DEFAULT_EXPORT_BODY);
  const [exportTask, setExportTask] = useState<EvidenceExportResponse | null>(null);
  const [exportSummary, setExportSummary] = useState<EvidenceExportSummary | null>(null);
  const [downloadAuthorization, setDownloadAuthorization] =
    useState<ExportDownloadAuthorizationResponse | null>(null);
  const [downloadAuthorizationSummary, setDownloadAuthorizationSummary] =
    useState<DownloadAuthorizationSummary | null>(null);
  const [downloadPreview, setDownloadPreview] = useState<DownloadPreview | null>(null);
  const [downloadPreviewSummary, setDownloadPreviewSummary] =
    useState<DownloadPreviewSummary | null>(null);
  const [riskResult, setRiskResult] = useState<RiskResult | null>(null);
  const [auditAction, setAuditAction] = useState(DEFAULT_AUDIT_ACTION);
  const [auditLimit, setAuditLimit] = useState(DEFAULT_AUDIT_LIMIT);
  const [, setAuditMessage] = useState("");
  const [auditView, setAuditView] = useState<AuditViewSummary | null>(null);
  const [alerts, setAlerts] = useState<UebaAlerts | null>(null);
  const [baselines, setBaselines] = useState<UebaBaselines | null>(null);
  const [drilldownSummary, setDrilldownSummary] = useState<DrilldownSummary | null>(null);
  const [statusMessage, setStatusMessage] = useState("Ready to initiate MFA.");
  const [securityNotice, setSecurityNotice] = useState<SecurityNotice | null>(null);
  const [isHydrating, setIsHydrating] = useState(false);
  const taskStreamPathRef = useRef<string | null>(null);

  const persona = PERSONAS.find((item) => item.key === personaKey) ?? PERSONAS[0];
  const activeRefreshToken = session?.refreshToken ?? "refresh-placeholder";

  const applySession = (nextSession: SessionTokens | null, nextProjectId = projectId) => {
    applySessionState(
      {
        client,
        setSession,
        personaUsername: persona.username,
        projectId
      },
      nextSession,
      nextProjectId
    );
  };

  const resetWorkspace = () => {
    resetWorkspaceState({
      setProjects,
      setProjectId,
      setProjectStateMessage,
      setPermissionApplication,
      setPermissionGrants,
      setApprovalTasks,
      setApprovalMessage,
      setTask,
      setSnapshotPage,
      setPivot,
      setDrilldownPage,
      setAnalysisTemplates,
      setSelectedTemplateId,
      setTemplateName,
      setTemplateDescription,
      setActiveTemplate,
      setAnalysisMessage,
      setActiveDataSourceId,
      setExportTask,
      setDownloadAuthorization,
      setDownloadPreview,
      setRiskResult,
      setAuditMessage,
      setAlerts,
      setBaselines,
      taskStreamPathRef
    });
    setActiveSourceType(DEFAULT_SOURCE_TYPE);
    setSelectedFields(DEFAULT_SELECTED_FIELDS);
    setQueryPriority(DEFAULT_QUERY_PRIORITY);
    setPageSize(DEFAULT_PAGE_SIZE);
    setPivotDimension(DEFAULT_PIVOT_DIMENSION);
    setPivotMetric(DEFAULT_PIVOT_METRIC);
    setPivotMetricField(null);
    setPivotPercentile(null);
    setExportTemplate(DEFAULT_EXPORT_TEMPLATE);
    setExportBody(DEFAULT_EXPORT_BODY);
    setExportSummary(null);
    setDownloadAuthorizationSummary(null);
    setDownloadPreviewSummary(null);
    setAuditAction(DEFAULT_AUDIT_ACTION);
    setAuditLimit(DEFAULT_AUDIT_LIMIT);
    setAuditView(null);
    setDrilldownSummary(null);
  };

  const handleError = (error: unknown) => {
    handleAuthWorkspaceError({
      error,
      applySession,
      clearChallenge: () => setChallenge(null),
      resetWorkspace,
      setRiskResult,
      setSecurityNotice,
      setStatusMessage
    });
  };

  const handlePollingError = useEffectEvent((error: unknown) => {
    handleError(error);
  });

  async function runAction<T>(operation: () => Promise<T>, successMessage?: string): Promise<T | null> {
    try {
      const result = await operation();
      setSecurityNotice(null);
      if (successMessage) {
        setStatusMessage(successMessage);
      }
      return result;
    } catch (error) {
      handleError(error);
      return null;
    }
  }

  const workbenchConfig: AnalysisWorkbenchConfig = {
    dataSourceId: activeDataSourceId,
    sourceType: activeSourceType,
    detailFields: selectedFields,
    queryPriority,
    pageSize,
    pivotDimension,
    pivotMetric,
    pivotMetricField,
    pivotPercentile
  };

  const evidenceExportConfig: EvidenceExportConfig = {
    template: exportTemplate,
    exportBody
  };

  const auditSearchConfig: AuditSearchConfig = {
    action: auditAction,
    limit: auditLimit
  };

  const workbenchRuntimeState = buildWorkbenchRuntimeState({
    task,
    queryPriority,
    snapshotPage,
    securityNotice,
    stepUpRequired: Boolean(riskResult?.required),
    exportTask,
    downloadAuthorization,
    downloadPreview
  });
  const activeChallengePanel = challenge
    ? challenge
    : riskResult?.required
      ? {
          pendingSessionId: session?.sessionId ?? "active-session",
          method: riskResult.challenge?.method ?? "step_up",
          details: riskResult.challenge ?? null,
          kind: "step-up" as const
        }
      : null;

  const refreshAnalysisTemplates = useEffectEvent(async () => {
    const response = await refreshAnalysisTemplatesCommand({
      client,
      selectedTemplateId
    });
    startTransition(() => {
      setAnalysisTemplates(response.templates);
      setSelectedTemplateId(response.selectedTemplateId);
    });
    return response.templates;
  });

  const loadSnapshotArtifacts = useEffectEvent(async (snapshotId: string, template?: AnalysisTemplate | null) => {
    const { snapshotPage: nextSnapshotPage, pivot: nextPivot } = await loadSnapshotArtifactsCommand({
      client,
      snapshotId,
      template,
      fallbackConfig: workbenchConfig
    });
    startTransition(() => {
      setSnapshotPage(nextSnapshotPage);
      setPivot(nextPivot);
      setDrilldownPage(null);
      setDrilldownSummary(null);
    });
    return { snapshotPage: nextSnapshotPage, pivot: nextPivot };
  });

  const applyTaskUpdate = useEffectEvent(async (nextTask: QueryTaskStatus) => {
    setTask(nextTask);
    const result = await applyTaskUpdateCommand({
      nextTask,
      activeTemplate,
      loadSnapshotArtifacts
    });
    if (result.securityNotice) {
      setSecurityNotice(result.securityNotice);
    }
    if (result.statusMessage) {
      setStatusMessage(result.statusMessage);
    }
  });

  useEffect(() => {
    if (!task?.task_id) {
      return undefined;
    }

    const subscription = observeTaskStatus({
      client,
      taskId: task.task_id,
      streamPath: taskStreamPathRef.current ?? undefined,
      pollIntervalMs,
      onStatus: applyTaskUpdate,
      onPollingFallback: () => {
        setStatusMessage("Task stream unavailable, falling back to polling.");
      },
      onPollingError: handlePollingError
    });

    return () => {
      subscription.close();
    };
  }, [applyTaskUpdate, client, handlePollingError, pollIntervalMs, task?.task_id]);

  async function finishMfa() {
    if (!challenge) {
      return;
    }

    setIsHydrating(true);
    setStatusMessage("Hydrating workspace...");
    try {
      await hydrateWorkspaceSession({
        client,
        challenge,
        pendingSessionId: challenge.pendingSessionId,
        mfaCode: persona.mfaCode,
        applySession,
        setProjects,
        setProjectId,
        setPermissionGrants,
        setAlerts,
        setBaselines,
        refreshAnalysisTemplates,
        clearChallenge: () => setChallenge(null)
      });
    } finally {
      setIsHydrating(false);
    }
  }

  const handleDataSourceChange = (nextDataSourceId: string) => {
    setActiveDataSourceId(nextDataSourceId);
    setActiveSourceType(resolveSourceType(nextDataSourceId));
  };

  const handleSelectedFieldToggle = (fieldName: string, checked: boolean) => {
    const nextSelectedFields = checked
      ? Array.from(new Set([...selectedFields, fieldName]))
      : selectedFields.filter((field) => field !== fieldName);

    if (nextSelectedFields.length === 0) {
      return;
    }

    setSelectedFields(nextSelectedFields);
    if (!nextSelectedFields.includes(pivotDimension)) {
      setPivotDimension(nextSelectedFields[0] ?? DEFAULT_PIVOT_DIMENSION);
    }
    if (
      pivotMetric !== DEFAULT_PIVOT_METRIC &&
      (!pivotMetricField || !nextSelectedFields.includes(pivotMetricField))
    ) {
      setPivotMetricField(nextSelectedFields[0] ?? null);
    }
  };

  const handlePivotMetricChange = (nextPivotMetric: string) => {
    setPivotMetric(nextPivotMetric);
    if (nextPivotMetric === DEFAULT_PIVOT_METRIC) {
      setPivotMetricField(null);
      setPivotPercentile(null);
      return;
    }
    if (!pivotMetricField || !selectedFields.includes(pivotMetricField)) {
      setPivotMetricField(selectedFields[0] ?? null);
    }
  };

  const handleExportTemplateChange = (nextTemplate: string) => {
    setExportTemplate(nextTemplate);
    setExportTask(null);
    setExportSummary(null);
    setDownloadAuthorization(null);
    setDownloadAuthorizationSummary(null);
    setDownloadPreview(null);
    setDownloadPreviewSummary(null);
  };

  const handleExportBodyChange = (nextBody: string) => {
    setExportBody(nextBody);
    setExportTask(null);
    setExportSummary(null);
    setDownloadAuthorization(null);
    setDownloadAuthorizationSummary(null);
    setDownloadPreview(null);
    setDownloadPreviewSummary(null);
  };

  const handleAuditActionChange = (nextAction: string) => {
    setAuditAction(nextAction);
    setAuditMessage("");
    setAuditView(null);
  };

  const handleAuditLimitChange = (nextLimit: number) => {
    if (!Number.isFinite(nextLimit) || nextLimit <= 0) {
      return;
    }
    setAuditLimit(nextLimit);
    setAuditMessage("");
    setAuditView(null);
  };

  const completeStepUp = async () => {
    const result = await completeStepUpCommand({
      client,
      refreshToken: activeRefreshToken,
      mfaCode: persona.mfaCode,
      challenge: riskResult?.challenge ?? null
    });
    applySession(result.session, projectId);
    setRiskResult(result.riskResult);
  };

  const submitAsyncQuery = async () => {
    const response = await submitAsyncQueryCommand({
      client,
      workbenchConfig
    });
    setActiveDataSourceId(response.activeDataSourceId);
    setActiveSourceType(resolveSourceType(response.activeDataSourceId));
    taskStreamPathRef.current = response.taskStreamPath;
    setSnapshotPage(null);
    setPivot(null);
    setDrilldownPage(null);
    setDrilldownSummary(null);
    setExportTask(null);
    setExportSummary(null);
    setDownloadAuthorization(null);
    setDownloadAuthorizationSummary(null);
    setDownloadPreview(null);
    setDownloadPreviewSummary(null);
    setTask(response.task);
  };

  const cancelActiveTask = async () => {
    if (!task?.task_id) {
      return;
    }
    await client.cancelTask(task.task_id);
    const nextTask = await client.getTaskStatus(task.task_id);
    setTask(nextTask);
  };

  const authorizeActiveDownload = async () => {
    if (!exportTask) {
      return;
    }

    const authorization = await authorizeEvidenceDownloadCommand({
      client,
      exportTask
    });
    if (authorization) {
      setDownloadAuthorization(authorization.authorization);
      setDownloadAuthorizationSummary(authorization.summary);
      setDownloadPreview(null);
      setDownloadPreviewSummary(null);
    }
  };

  const previewAuthorizedDownload = async () => {
    if (!downloadAuthorization) {
      return;
    }

    const preview = await previewEvidenceDownloadCommand({
      client,
      downloadAuthorization
    });
    if (preview) {
      setDownloadPreview(preview.preview);
      setDownloadPreviewSummary(preview.summary);
    }
  };

  const heroPanelProps = {
    personaKey,
    personas: PERSONAS,
    challengePending: Boolean(challenge),
    hasSession: Boolean(session),
    statusMessage,
    isHydrating,
    onPersonaKeyChange: setPersonaKey,
    onStartLogin: () =>
      void runAction(async () => {
        setChallenge(
          await startLoginCommand({
            client,
            username: persona.username
          })
        );
      }, `Issued MFA challenge for ${persona.label}.`),
    onCompleteMfa: () => void runAction(() => finishMfa(), "MFA verified and workspace hydrated."),
    onRefreshSession: () =>
      void runAction(async () => {
        const nextSession = await refreshSessionCommand({
          client
        });
        applySession(nextSession, projectId);
      }, "Session refreshed.")
  };

  const projectControlPanelProps = {
    isHydrating,
    projectId,
    projects,
    projectStateMessage,
    onSwitchProject: (nextProjectId: string) =>
      void runAction(async () => {
        setProjectId(nextProjectId);
        const result = await switchProjectCommand({
          client,
          session,
          personaUsername: persona.username,
          nextProjectId,
          refreshAnalysisTemplates
        });
        setPermissionGrants(result.permissionGrants);
      }, `Switched to ${nextProjectId}.`),
    onFreezeProject: (nextProjectId: string) =>
      void runAction(async () => {
        const result = await freezeProjectCommand({
          client,
          projectId: nextProjectId
        });
        setProjectStateMessage(result.projectStateMessage);
      }, `Project ${nextProjectId} frozen.`)
  };

  const permissionsPanelProps = {
    isHydrating,
    permissionApplication,
    permissionGrants,
    onSubmitPermissionRequest: () =>
      void runAction(async () => {
        setPermissionApplication(
          await submitPermissionRequestCommand({
            client,
            requestedFields: selectedFields
          })
        );
      }, "Permission request submitted.")
  };

  const securityPanelProps = {
    isHydrating,
    riskResult,
    onEvaluateDevicePosture: () =>
      void runAction(async () => {
        const result = await evaluateDevicePostureCommand({
          client,
          refreshToken: activeRefreshToken
        });
        setRiskResult(result.riskResult);
        if (result.securityNotice) {
          setSecurityNotice(result.securityNotice);
        }
        setStatusMessage(result.statusMessage);
      }),
    onCompleteStepUp: () =>
      void runAction(completeStepUp, "Step-up verification completed.")
  };

  const approvalQueuePanelProps = {
    isHydrating,
    approvalTasks,
    approvalMessage,
    onLoadApprovalQueue: () =>
      void runAction(async () => {
        setApprovalTasks(
          await loadApprovalQueueCommand({
            client
          })
        );
      }, "Approval queue loaded."),
    onDelegateApproval: (instanceId: string) =>
      void runAction(async () => {
        const result = await delegateApprovalCommand({
          client,
          instanceId
        });
        setApprovalMessage(result.approvalMessage);
      }, "Approval delegation completed.")
  };

  const queryWorkbenchPanelProps = {
    isHydrating,
    dataSourceId: activeDataSourceId,
    dataSourceOptions: DATA_SOURCE_OPTIONS.map(({ id, label }) => ({ id, label })),
    fieldOptions: FIELD_OPTIONS,
    selectedFields,
    queryPriority,
    queryPriorityOptions: QUERY_PRIORITY_OPTIONS,
    task,
    runtimeState: workbenchRuntimeState,
    onDataSourceIdChange: handleDataSourceChange,
    onSelectedFieldToggle: handleSelectedFieldToggle,
    onQueryPriorityChange: setQueryPriority,
    onSubmitAsyncQuery: () =>
      void runAction(submitAsyncQuery, "Async query submitted."),
    onCancelTask: () => void runAction(cancelActiveTask, "Query cancellation requested."),
    onRetryQuery: () => void runAction(submitAsyncQuery, "Query retry submitted."),
    onCompleteStepUp: () => void runAction(completeStepUp, "Step-up verification completed."),
    onAuthorizeDownload: () =>
      void runAction(authorizeActiveDownload, "Download authorization issued."),
    onPreviewDownload: () => void runAction(previewAuthorizedDownload, "Download preview loaded.")
  };

  const uebaAuditPanelProps = {
    isHydrating,
    alerts,
    baselines,
    auditAction,
    auditActionOptions: AUDIT_ACTION_OPTIONS,
    auditLimit,
    auditLimitOptions: AUDIT_LIMIT_OPTIONS,
    auditView,
    onAuditActionChange: handleAuditActionChange,
    onAuditLimitChange: handleAuditLimitChange,
    onLoadAuditView: () =>
      void runAction(async () => {
        const nextAuditView = await loadAuditViewCommand({
          client,
          auditFilters: auditSearchConfig
        });
        setAuditMessage("");
        setAuditView(nextAuditView);
      }, "Audit view loaded.")
  };

  const analysisTemplatesPanelProps = {
    isHydrating,
    hasSnapshot: Boolean(snapshotPage),
    analysisTemplates,
    selectedTemplateId,
    templateName,
    templateDescription,
    pageSize,
    pageSizeOptions: PAGE_SIZE_OPTIONS,
    pivotDimension,
    pivotDimensionOptions: FIELD_OPTIONS.map((field) => field.name),
    pivotMetric,
    pivotMetricOptions: PIVOT_METRIC_OPTIONS,
    pivotMetricField,
    pivotMetricFieldOptions: selectedFields,
    analysisMessage,
    onTemplateNameChange: setTemplateName,
    onTemplateDescriptionChange: setTemplateDescription,
    onSelectedTemplateIdChange: setSelectedTemplateId,
    onPageSizeChange: setPageSize,
    onPivotDimensionChange: setPivotDimension,
    onPivotMetricChange: handlePivotMetricChange,
    onPivotMetricFieldChange: (value: string) => setPivotMetricField(value || null),
    onSaveCurrentTemplate: () =>
      void runAction(async () => {
        const result = await saveCurrentTemplateCommand({
          client,
          templateName,
          templateDescription,
          workbenchConfig
        });
        setActiveTemplate(result.template);
        setSelectedTemplateId(result.selectedTemplateId);
        setAnalysisMessage(result.analysisMessage);
        await refreshAnalysisTemplates();
      }, "Analysis template saved."),
    onLoadSelectedTemplate: () =>
      void runAction(async () => {
        const result = await loadSelectedTemplateCommand({
          client,
          selectedTemplateId,
          activeDataSourceId,
          currentSnapshotId: snapshotPage?.snapshot_id ?? task?.snapshot_id ?? null,
          loadSnapshotArtifacts
        });
        setActiveTemplate(result.template);
        setTemplateName(result.templateName);
        setTemplateDescription(result.templateDescription);
        setAnalysisMessage(result.analysisMessage);
        handleDataSourceChange(result.workbenchConfig.dataSourceId);
        setSelectedFields(result.workbenchConfig.detailFields);
        setPageSize(result.workbenchConfig.pageSize);
        setPivotDimension(result.workbenchConfig.pivotDimension);
        setPivotMetric(result.workbenchConfig.pivotMetric);
        setPivotMetricField(result.workbenchConfig.pivotMetricField);
        setPivotPercentile(result.workbenchConfig.pivotPercentile);
      }, "Analysis template loaded."),
    onSelectTemplate: (template: AnalysisTemplate) => {
      const selection = selectTemplateCommand(template);
      setSelectedTemplateId(selection.selectedTemplateId);
      setTemplateName(selection.templateName);
      setTemplateDescription(selection.templateDescription);
      handleDataSourceChange(selection.workbenchConfig.dataSourceId);
      setSelectedFields(selection.workbenchConfig.detailFields);
      setPageSize(selection.workbenchConfig.pageSize);
      setPivotDimension(selection.workbenchConfig.pivotDimension);
      setPivotMetric(selection.workbenchConfig.pivotMetric);
      setPivotMetricField(selection.workbenchConfig.pivotMetricField);
      setPivotPercentile(selection.workbenchConfig.pivotPercentile);
    },
    onToggleTemplateVisibility: (template: AnalysisTemplate) =>
      void runAction(async () => {
        const result = await toggleTemplateVisibilityCommand({
          client,
          template
        });
        if (activeTemplate?.template_id === result.nextTemplate.template_id) {
          setActiveTemplate(result.nextTemplate);
        }
        setAnalysisMessage(result.analysisMessage);
        await refreshAnalysisTemplates();
      }),
    onDeleteTemplate: (template: AnalysisTemplate) =>
      void runAction(async () => {
        const result = await deleteTemplateCommand({
          client,
          template,
          activeTemplateId: activeTemplate?.template_id ?? null,
          selectedTemplateId
        });
        if (result.clearActiveTemplate) {
          setActiveTemplate(null);
        }
        if (result.clearSelectedTemplate) {
          setSelectedTemplateId("");
        }
        setAnalysisMessage(result.analysisMessage);
        await refreshAnalysisTemplates();
      })
  };

  const evidenceExportPanelProps = {
    isHydrating,
    hasSnapshot: Boolean(snapshotPage),
    exportTemplate,
    exportTemplateOptions: EVIDENCE_TEMPLATE_OPTIONS,
    exportBody,
    exportSummary,
    downloadAuthorizationSummary,
    downloadPreview,
    downloadPreviewSummary,
    pivot,
    drilldownPage,
    drilldownSummary,
    onExportTemplateChange: handleExportTemplateChange,
    onExportBodyChange: handleExportBodyChange,
    onGenerateEvidencePackage: () =>
      void runAction(async () => {
        const result = await generateEvidencePackageCommand({
          client,
          snapshotId: snapshotPage?.snapshot_id ?? "snapshot-a",
          exportConfig: evidenceExportConfig
        });
        setExportTask(result.exportTask);
        setExportSummary(result.summary);
        setDownloadAuthorization(null);
        setDownloadAuthorizationSummary(null);
        setDownloadPreview(null);
        setDownloadPreviewSummary(null);
      }, "Evidence package generated."),
    onAuthorizeDownload: () => {
      if (!exportTask) {
        return;
      }

      void runAction(authorizeActiveDownload, "Download authorization issued.");
    },
    onPreviewDownload: () => {
      if (!downloadAuthorization) {
        return;
      }

      void runAction(previewAuthorizedDownload, "Download preview loaded.");
    },
    onLoadDrilldown: (bucketKey: string) => {
      if (!pivot) {
        return;
      }

      void runAction(async () => {
        const page = await loadDrilldownCommand({
          client,
          pivot,
          detailFields: selectedFields,
          pivotDimension,
          bucketKey
        });
        if (page) {
          setDrilldownPage(page.page);
          setDrilldownSummary(page.summary);
        }
      }, `Loaded drilldown for ${bucketKey}.`);
    }
  };

  return {
    showWorkspace: Boolean(session || challenge),
    securityNoticeBannerProps: {
      notice: securityNotice
    },
    mfaChallengePanelProps: {
      challenge: activeChallengePanel
    },
    heroPanelProps,
    projectControlPanelProps,
    permissionsPanelProps,
    securityPanelProps,
    approvalQueuePanelProps,
    queryWorkbenchPanelProps,
    uebaAuditPanelProps,
    detailPagePanelProps: {
      snapshotPage
    },
    analysisTemplatesPanelProps,
    evidenceExportPanelProps
  };
}
