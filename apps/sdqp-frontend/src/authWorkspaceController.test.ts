import { describe, expect, it, vi } from "vitest";
import { ApiError, type FrontendClient, type SessionTokens } from "./api";
import {
  applySessionState,
  handleAuthWorkspaceError,
  hydrateWorkspaceSession,
  resetWorkspaceState,
  type RiskResult
} from "./authWorkspaceController";

function createSetter<T>() {
  const spy = vi.fn<(value: T | ((current: T) => T)) => void>();
  return spy;
}

describe("authWorkspaceController", () => {
  it("applies the session to both the client and local state", () => {
    const client: Pick<FrontendClient, "setSession"> = {
      setSession: vi.fn()
    };
    const setSession = createSetter<SessionTokens | null>();
    const session = {
      accessToken: "access-a",
      refreshToken: "refresh-a",
      sessionId: "session-a"
    };

    applySessionState(
      {
        client,
        setSession,
        personaUsername: "analyst",
        projectId: "project-alpha"
      },
      session,
      "project-beta"
    );

    expect(client.setSession).toHaveBeenCalledWith(session, {
      username: "analyst",
      projectId: "project-beta"
    });
    expect(setSession).toHaveBeenCalledWith(session);
  });

  it("resets the workspace state back to the console defaults", () => {
    const taskStreamPathRef = { current: "/v1/tasks/task-a/ws" };
    const setters = {
      setProjects: createSetter<[]>(),
      setProjectId: createSetter<string>(),
      setProjectStateMessage: createSetter<string>(),
      setPermissionApplication: createSetter<null>(),
      setPermissionGrants: createSetter<[]>(),
      setApprovalTasks: createSetter<[]>(),
      setApprovalMessage: createSetter<string>(),
      setTask: createSetter<null>(),
      setSnapshotPage: createSetter<null>(),
      setPivot: createSetter<null>(),
      setDrilldownPage: createSetter<null>(),
      setAnalysisTemplates: createSetter<[]>(),
      setSelectedTemplateId: createSetter<string>(),
      setTemplateName: createSetter<string>(),
      setTemplateDescription: createSetter<string>(),
      setActiveTemplate: createSetter<null>(),
      setAnalysisMessage: createSetter<string>(),
      setActiveDataSourceId: createSetter<string>(),
      setExportTask: createSetter<null>(),
      setDownloadAuthorization: createSetter<null>(),
      setDownloadPreview: createSetter<null>(),
      setRiskResult: createSetter<null>(),
      setAuditMessage: createSetter<string>(),
      setAlerts: createSetter<null>(),
      setBaselines: createSetter<null>(),
      taskStreamPathRef
    };

    resetWorkspaceState(setters);

    expect(setters.setProjectId).toHaveBeenCalledWith("");
    expect(setters.setTemplateName).toHaveBeenCalledWith("Fraud triage");
    expect(setters.setActiveDataSourceId).toHaveBeenCalledWith("datasource-rest");
    expect(setters.setRiskResult).toHaveBeenCalledWith(null);
    expect(taskStreamPathRef.current).toBeNull();
  });

  it("maps 401 errors to session timeout handling", () => {
    const applySession = vi.fn();
    const clearChallenge = vi.fn();
    const resetWorkspace = vi.fn();
    const setSecurityNotice = createSetter<{
      kind: "timeout" | "step-up" | "failure";
      title: string;
      body: string;
    } | null>();
    const setStatusMessage = createSetter<string>();
    let riskResult: RiskResult | null = null;
    const setRiskResult = vi.fn((update: RiskResult | null | ((current: RiskResult | null) => RiskResult | null)) => {
      riskResult = typeof update === "function" ? update(riskResult) : update;
    });

    handleAuthWorkspaceError({
      error: new ApiError("Expired refresh session", 401),
      applySession,
      clearChallenge,
      resetWorkspace,
      setRiskResult,
      setSecurityNotice,
      setStatusMessage
    });

    expect(applySession).toHaveBeenCalledWith(null, "");
    expect(clearChallenge).toHaveBeenCalledTimes(1);
    expect(resetWorkspace).toHaveBeenCalledTimes(1);
    expect(setSecurityNotice).toHaveBeenCalledWith({
      kind: "timeout",
      title: "Session expired",
      body: "Reauthenticate to continue operating in this console."
    });
    expect(setStatusMessage).toHaveBeenCalledWith("Session timed out.");
    expect(riskResult).toBeNull();
  });

  it("maps 401 step-up errors to challenge guidance without clearing the session", () => {
    const applySession = vi.fn();
    const clearChallenge = vi.fn();
    const resetWorkspace = vi.fn();
    const setSecurityNotice = createSetter<{
      kind: "timeout" | "step-up" | "failure";
      title: string;
      body: string;
    } | null>();
    const setStatusMessage = createSetter<string>();
    let riskResult: RiskResult | null = null;
    const setRiskResult = vi.fn((update: RiskResult | null | ((current: RiskResult | null) => RiskResult | null)) => {
      riskResult = typeof update === "function" ? update(riskResult) : update;
    });

    handleAuthWorkspaceError({
      error: new ApiError("step-up authentication required", 401, {
        stepUpRequired: true,
        stepUpChallenge: {
          challengeId: "challenge-a",
          method: "webauthn",
          reason: "continuous risk assessment requires step-up",
          expiresAt: "2026-04-11T12:00:00Z",
          webauthnRequest: {
            challenge: "challenge",
            rpId: "sdqp.local",
            origin: "https://sdqp.local",
            credentialId: "credential",
            timeoutMs: 300000,
            userVerification: "required"
          }
        }
      }),
      applySession,
      clearChallenge,
      resetWorkspace,
      setRiskResult,
      setSecurityNotice,
      setStatusMessage
    });

    expect(applySession).not.toHaveBeenCalled();
    expect(clearChallenge).not.toHaveBeenCalled();
    expect(resetWorkspace).not.toHaveBeenCalled();
    expect(riskResult).toEqual({
      required: true,
      action: "step_up",
      challenge: {
        challengeId: "challenge-a",
        method: "webauthn",
        reason: "continuous risk assessment requires step-up",
        expiresAt: "2026-04-11T12:00:00Z",
        webauthnRequest: {
          challenge: "challenge",
          rpId: "sdqp.local",
          origin: "https://sdqp.local",
          credentialId: "credential",
          timeoutMs: 300000,
          userVerification: "required"
        }
      }
    });
    expect(setSecurityNotice).toHaveBeenCalledWith({
      kind: "step-up",
      title: "Step-up required",
      body: "continuous risk assessment requires step-up"
    });
    expect(setStatusMessage).toHaveBeenCalledWith("step-up authentication required");
  });

  it("maps 403 errors to step-up guidance without clobbering an existing risk result", () => {
    const setSecurityNotice = createSetter<{
      kind: "timeout" | "step-up" | "failure";
      title: string;
      body: string;
    } | null>();
    const setStatusMessage = createSetter<string>();
    let riskResult: RiskResult | null = { required: false, action: "allow" };
    const setRiskResult = vi.fn((update: RiskResult | null | ((current: RiskResult | null) => RiskResult | null)) => {
      riskResult = typeof update === "function" ? update(riskResult) : update;
    });

    handleAuthWorkspaceError({
      error: new ApiError("Forbidden approval queue", 403),
      applySession: vi.fn(),
      clearChallenge: vi.fn(),
      resetWorkspace: vi.fn(),
      setRiskResult,
      setSecurityNotice,
      setStatusMessage
    });

    expect(riskResult).toEqual({ required: false, action: "allow" });
    expect(setSecurityNotice).toHaveBeenCalledWith({
      kind: "step-up",
      title: "Step-up or access upgrade required",
      body: "The server blocked this action. Complete step-up or switch to a permitted persona or project."
    });
    expect(setStatusMessage).toHaveBeenCalledWith("Forbidden approval queue");
  });

  it("hydrates the workspace after MFA verification", async () => {
    const session = {
      accessToken: "access-a",
      refreshToken: "refresh-a",
      sessionId: "session-a"
    };
    const client: Pick<
      FrontendClient,
      "verifyMfa" | "getProjects" | "getPermissionGrants" | "getUebaAlerts" | "getUebaBaselines"
    > = {
      verifyMfa: vi.fn().mockResolvedValue(session),
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
      getPermissionGrants: vi.fn().mockResolvedValue({
        grants: [
          {
            grant_id: "grant-a",
            data_source_id: "datasource-rest",
            status: "active",
            fields: ["employee_id"],
            valid_until: "2026-03-30T10:00:00Z"
          }
        ]
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
      })
    };
    const applySession = vi.fn();
    const setProjects = createSetter<
      Array<{
        project_id: string;
        tenant_id: string;
        state: string;
        can_accept_new_permissions: boolean;
        can_export: boolean;
        read_only: boolean;
      }>
    >();
    const setProjectId = createSetter<string>();
    const setPermissionGrants = createSetter<
      Array<{
        grant_id: string;
        data_source_id: string;
        status: string;
        fields: string[];
        valid_until: string;
      }>
    >();
    const setAlerts = createSetter<{
      alerts: [];
      step_up_sessions: number;
      permissions_revoked: number;
      terminated_sessions: number;
    } | null>();
    const setBaselines = createSetter<{
      user_baselines: [];
      entity_baselines: [];
    } | null>();
    const refreshAnalysisTemplates = vi.fn().mockResolvedValue([]);
    const clearChallenge = vi.fn();

    await hydrateWorkspaceSession({
      client,
      challenge: null,
      pendingSessionId: "pending-a",
      mfaCode: "000000",
      applySession,
      setProjects,
      setProjectId,
      setPermissionGrants,
      setAlerts,
      setBaselines,
      refreshAnalysisTemplates,
      clearChallenge
    });

    expect(client.verifyMfa).toHaveBeenCalledWith({
      pendingSessionId: "pending-a",
      code: "000000"
    });
    expect(applySession).toHaveBeenCalledWith(session, "project-alpha");
    expect(setProjectId).toHaveBeenCalledWith("project-alpha");
    expect(setPermissionGrants).toHaveBeenCalledWith([
      {
        grant_id: "grant-a",
        data_source_id: "datasource-rest",
        status: "active",
        fields: ["employee_id"],
        valid_until: "2026-03-30T10:00:00Z"
      }
    ]);
    expect(refreshAnalysisTemplates).toHaveBeenCalledTimes(1);
    expect(clearChallenge).toHaveBeenCalledTimes(1);
  });

  it("hydrates the workspace with a browser webauthn assertion when challenge details require it", async () => {
    const session = {
      accessToken: "access-a",
      refreshToken: "refresh-a",
      sessionId: "session-a"
    };
    const webauthnAssertion = {
      credentialId: "credential-a",
      clientDataJson: "client-data",
      authenticatorData: "auth-data",
      signature: "signature-a"
    };
    const client: Pick<
      FrontendClient,
      | "verifyMfa"
      | "createWebAuthnAssertion"
      | "getProjects"
      | "getPermissionGrants"
      | "getUebaAlerts"
      | "getUebaBaselines"
    > = {
      verifyMfa: vi.fn().mockResolvedValue(session),
      createWebAuthnAssertion: vi.fn().mockResolvedValue(webauthnAssertion),
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
      getPermissionGrants: vi.fn().mockResolvedValue({ grants: [] }),
      getUebaAlerts: vi.fn().mockResolvedValue({
        alerts: [],
        step_up_sessions: 0,
        permissions_revoked: 0,
        terminated_sessions: 0
      }),
      getUebaBaselines: vi.fn().mockResolvedValue({
        user_baselines: [],
        entity_baselines: []
      })
    };

    await hydrateWorkspaceSession({
      client,
      challenge: {
        pendingSessionId: "pending-webauthn",
        method: "webauthn",
        details: {
          challengeId: "challenge-a",
          method: "webauthn",
          reason: "login authentication",
          expiresAt: "2026-04-11T12:00:00Z",
          webauthnRequest: {
            challenge: "challenge-a",
            rpId: "sdqp.local",
            origin: "https://sdqp.local",
            credentialId: "credential-a",
            timeoutMs: 300000,
            userVerification: "required"
          }
        }
      },
      pendingSessionId: "pending-webauthn",
      mfaCode: "ignored",
      applySession: vi.fn(),
      setProjects: createSetter<[]>(),
      setProjectId: createSetter<string>(),
      setPermissionGrants: createSetter<[]>(),
      setAlerts: createSetter<null>(),
      setBaselines: createSetter<null>(),
      refreshAnalysisTemplates: vi.fn().mockResolvedValue([]),
      clearChallenge: vi.fn()
    });

    expect(client.createWebAuthnAssertion).toHaveBeenCalledWith({
      challenge: "challenge-a",
      rpId: "sdqp.local",
      origin: "https://sdqp.local",
      credentialId: "credential-a",
      timeoutMs: 300000,
      userVerification: "required"
    });
    expect(client.verifyMfa).toHaveBeenCalledWith({
      pendingSessionId: "pending-webauthn",
      webauthnAssertion
    });
  });
});
