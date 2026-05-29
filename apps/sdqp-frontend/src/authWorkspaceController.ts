import type { Dispatch, SetStateAction } from "react";
import {
  ApiError,
  type FrontendClient,
  type MfaChallengeDetails,
  type PermissionApplication,
  type PermissionGrantsResponse,
  type ProjectsResponse,
  type SessionTokens,
  type SnapshotPage,
  type UebaAlerts,
  type UebaBaselines
} from "./api";
import type { AnalysisTemplate, ApprovalTask, DownloadPreview, EvidenceExportResponse, ExportDownloadAuthorizationResponse, PivotAnalysis } from "./api";

export type RiskResult = {
  required: boolean;
  action: string;
  challenge?: MfaChallengeDetails | null;
};

export type SecurityNotice = {
  kind: "timeout" | "step-up" | "failure";
  title: string;
  body: string;
};

type SessionClient = Pick<FrontendClient, "setSession">;
type HydrationClient = Pick<
  FrontendClient,
  | "verifyMfa"
  | "createWebAuthnAssertion"
  | "getProjects"
  | "getPermissionGrants"
  | "getUebaAlerts"
  | "getUebaBaselines"
>;

async function createWebAuthnAssertion(
  client: HydrationClient,
  request: MfaChallengeDetails["webauthnRequest"]
) {
  if (!request) {
    return null;
  }
  if (!client.createWebAuthnAssertion) {
    throw new ApiError("WebAuthn challenge cannot be completed in this environment.", 400);
  }
  return client.createWebAuthnAssertion(request);
}

export type WorkspaceResetters = {
  setProjects: Dispatch<SetStateAction<ProjectsResponse["projects"]>>;
  setProjectId: Dispatch<SetStateAction<string>>;
  setProjectStateMessage: Dispatch<SetStateAction<string>>;
  setPermissionApplication: Dispatch<SetStateAction<PermissionApplication | null>>;
  setPermissionGrants: Dispatch<SetStateAction<PermissionGrantsResponse["grants"]>>;
  setApprovalTasks: Dispatch<SetStateAction<ApprovalTask[]>>;
  setApprovalMessage: Dispatch<SetStateAction<string>>;
  setTask: Dispatch<SetStateAction<{ task_id: string; state: string; snapshot_id: string | null; cache_hit: boolean; error: string | null } | null>>;
  setSnapshotPage: Dispatch<SetStateAction<SnapshotPage | null>>;
  setPivot: Dispatch<SetStateAction<PivotAnalysis | null>>;
  setDrilldownPage: Dispatch<SetStateAction<SnapshotPage | null>>;
  setAnalysisTemplates: Dispatch<SetStateAction<AnalysisTemplate[]>>;
  setSelectedTemplateId: Dispatch<SetStateAction<string>>;
  setTemplateName: Dispatch<SetStateAction<string>>;
  setTemplateDescription: Dispatch<SetStateAction<string>>;
  setActiveTemplate: Dispatch<SetStateAction<AnalysisTemplate | null>>;
  setAnalysisMessage: Dispatch<SetStateAction<string>>;
  setActiveDataSourceId: Dispatch<SetStateAction<string>>;
  setExportTask: Dispatch<SetStateAction<EvidenceExportResponse | null>>;
  setDownloadAuthorization: Dispatch<SetStateAction<ExportDownloadAuthorizationResponse | null>>;
  setDownloadPreview: Dispatch<SetStateAction<DownloadPreview | null>>;
  setRiskResult: Dispatch<SetStateAction<RiskResult | null>>;
  setAuditMessage: Dispatch<SetStateAction<string>>;
  setAlerts: Dispatch<SetStateAction<UebaAlerts | null>>;
  setBaselines: Dispatch<SetStateAction<UebaBaselines | null>>;
  taskStreamPathRef: { current: string | null };
};

export type ApplySessionOptions = {
  client: SessionClient;
  setSession: Dispatch<SetStateAction<SessionTokens | null>>;
  personaUsername: string;
  projectId: string;
};

export type HandleAuthWorkspaceErrorOptions = {
  error: unknown;
  applySession: (nextSession: SessionTokens | null, nextProjectId?: string) => void;
  clearChallenge: () => void;
  resetWorkspace: () => void;
  setRiskResult: Dispatch<SetStateAction<RiskResult | null>>;
  setSecurityNotice: Dispatch<SetStateAction<SecurityNotice | null>>;
  setStatusMessage: Dispatch<SetStateAction<string>>;
};

export type HydrateWorkspaceSessionOptions = {
  client: HydrationClient;
  challenge:
    | {
        pendingSessionId: string;
        method: string;
        details?: MfaChallengeDetails | null;
      }
    | null;
  pendingSessionId: string;
  mfaCode: string;
  applySession: (nextSession: SessionTokens | null, nextProjectId?: string) => void;
  setProjects: Dispatch<SetStateAction<ProjectsResponse["projects"]>>;
  setProjectId: Dispatch<SetStateAction<string>>;
  setPermissionGrants: Dispatch<SetStateAction<PermissionGrantsResponse["grants"]>>;
  setAlerts: Dispatch<SetStateAction<UebaAlerts | null>>;
  setBaselines: Dispatch<SetStateAction<UebaBaselines | null>>;
  refreshAnalysisTemplates: () => Promise<unknown>;
  clearChallenge: () => void;
};

export function applySessionState(
  { client, setSession, personaUsername, projectId }: ApplySessionOptions,
  nextSession: SessionTokens | null,
  nextProjectId = projectId
) {
  client.setSession(nextSession, { username: personaUsername, projectId: nextProjectId });
  setSession(nextSession);
}

export function resetWorkspaceState({
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
}: WorkspaceResetters) {
  setProjects([]);
  setProjectId("");
  setProjectStateMessage("");
  setPermissionApplication(null);
  setPermissionGrants([]);
  setApprovalTasks([]);
  setApprovalMessage("");
  setTask(null);
  setSnapshotPage(null);
  setPivot(null);
  setDrilldownPage(null);
  setAnalysisTemplates([]);
  setSelectedTemplateId("");
  setTemplateName("Fraud triage");
  setTemplateDescription("");
  setActiveTemplate(null);
  setAnalysisMessage("");
  setActiveDataSourceId("datasource-rest");
  setExportTask(null);
  setDownloadAuthorization(null);
  setDownloadPreview(null);
  setRiskResult(null);
  setAuditMessage("");
  setAlerts(null);
  setBaselines(null);
  taskStreamPathRef.current = null;
}

export function handleAuthWorkspaceError({
  error,
  applySession,
  clearChallenge,
  resetWorkspace,
  setRiskResult,
  setSecurityNotice,
  setStatusMessage
}: HandleAuthWorkspaceErrorOptions) {
  if (error instanceof ApiError) {
    if (error.stepUpRequired) {
      setRiskResult({
        required: true,
        action: "step_up",
        challenge: error.stepUpChallenge
      });
      setSecurityNotice({
        kind: "step-up",
        title: "Step-up required",
        body:
          error.stepUpChallenge?.reason ??
          "Sensitive actions are paused until step-up verification completes."
      });
      setStatusMessage(error.message);
      return;
    }

    if (error.status === 401) {
      applySession(null, "");
      clearChallenge();
      resetWorkspace();
      setSecurityNotice({
        kind: "timeout",
        title: "Session expired",
        body: "Reauthenticate to continue operating in this console."
      });
      setStatusMessage("Session timed out.");
      return;
    }

    if (error.status === 403) {
      setRiskResult((current) => current ?? { required: true, action: "step_up" });
      setSecurityNotice({
        kind: "step-up",
        title: "Step-up or access upgrade required",
        body: "The server blocked this action. Complete step-up or switch to a permitted persona or project."
      });
      setStatusMessage(error.message);
      return;
    }
  }

  const message = error instanceof Error ? error.message : "Unknown request failure.";
  setSecurityNotice({
    kind: "failure",
    title: "Operation failed",
    body: message
  });
  setStatusMessage(message);
}

export async function hydrateWorkspaceSession({
  client,
  challenge,
  pendingSessionId,
  mfaCode,
  applySession,
  setProjects,
  setProjectId,
  setPermissionGrants,
  setAlerts,
  setBaselines,
  refreshAnalysisTemplates,
  clearChallenge
}: HydrateWorkspaceSessionOptions) {
  const webauthnRequest = challenge?.details?.webauthnRequest ?? null;
  const tokens = await client.verifyMfa(
    webauthnRequest
      ? {
          pendingSessionId,
          webauthnAssertion: await createWebAuthnAssertion(client, webauthnRequest)
        }
      : {
          pendingSessionId,
          code: mfaCode
        }
  );
  const projectResponse = await client.getProjects();
  const nextProjectId = projectResponse.projects[0]?.project_id ?? "";
  applySession(tokens, nextProjectId);
  setProjects(projectResponse.projects);
  setProjectId(nextProjectId);
  const [grantsResponse, nextAlerts, nextBaselines] = await Promise.all([
    client.getPermissionGrants(),
    client.getUebaAlerts(),
    client.getUebaBaselines(),
    refreshAnalysisTemplates()
  ]);
  setPermissionGrants(grantsResponse.grants);
  setAlerts(nextAlerts);
  setBaselines(nextBaselines);
  clearChallenge();
}
