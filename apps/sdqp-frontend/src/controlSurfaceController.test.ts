import { describe, expect, it, vi } from "vitest";
import type { FrontendClient } from "./api";
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
    verifyMfa: vi.fn(),
    createWebAuthnAssertion: vi.fn(),
    refreshSession: vi.fn().mockResolvedValue({
      accessToken: "access-b",
      refreshToken: "refresh-b",
      sessionId: "session-b"
    }),
    logout: vi.fn(),
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
    getProjects: vi.fn(),
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
    submitQuery: vi.fn(),
    streamTaskStatus: vi.fn(),
    getTaskStatus: vi.fn(),
    getSnapshotPage: vi.fn(),
    getSnapshotPageArrowIpc: vi.fn(),
    getPivot: vi.fn(),
    getPivotArrowIpc: vi.fn(),
    getDrilldown: vi.fn(),
    listAnalysisTemplates: vi.fn(),
    createAnalysisTemplate: vi.fn(),
    getAnalysisTemplate: vi.fn(),
    updateAnalysisTemplate: vi.fn(),
    publishAnalysisTemplate: vi.fn(),
    unpublishAnalysisTemplate: vi.fn(),
    deleteAnalysisTemplate: vi.fn(),
    searchAudit: vi.fn(),
    exportEvidence: vi.fn(),
    getExportTask: vi.fn(),
    authorizeDownload: vi.fn(),
    downloadExport: vi.fn(),
    getUebaAlerts: vi.fn(),
    getUebaBaselines: vi.fn(),
    ...overrides
  };
}

describe("controlSurfaceController", () => {
  it("starts login and refreshes the session through the control-surface commands", async () => {
    const client = createClient();

    const challenge = await startLoginCommand({
      client,
      username: "analyst"
    });
    const session = await refreshSessionCommand({
      client
    });

    expect(client.beginLogin).toHaveBeenCalledWith({
      username: "analyst",
      password: "password123",
      deviceFingerprint: "sdqp-ops-console"
    });
    expect(challenge).toEqual({
      pendingSessionId: "pending-a",
      method: "totp",
      details: null
    });
    expect(session.sessionId).toBe("session-b");
  });

  it("switches projects, freezes projects, and submits permission requests", async () => {
    const client = createClient();
    const refreshAnalysisTemplates = vi.fn().mockResolvedValue([]);

    const switchResult = await switchProjectCommand({
      client,
      session: {
        accessToken: "access-a",
        refreshToken: "refresh-a",
        sessionId: "session-a"
      },
      personaUsername: "analyst",
      nextProjectId: "project-alpha",
      refreshAnalysisTemplates
    });
    const freezeResult = await freezeProjectCommand({
      client,
      projectId: "project-alpha"
    });
    const permissionApplication = await submitPermissionRequestCommand({
      client,
      requestedFields: ["employee_id", "department"]
    });

    expect(client.setSession).toHaveBeenCalledWith(
      {
        accessToken: "access-a",
        refreshToken: "refresh-a",
        sessionId: "session-a"
      },
      {
        username: "analyst",
        projectId: "project-alpha"
      }
    );
    expect(switchResult.permissionGrants).toHaveLength(1);
    expect(refreshAnalysisTemplates).toHaveBeenCalledTimes(1);
    expect(freezeResult.projectStateMessage).toBe("frozen");
    expect(permissionApplication.application_id).toBe("application-a");
  });

  it("evaluates device posture and maps both step-up and allow outcomes", async () => {
    const client = createClient();

    const stepUpResult = await evaluateDevicePostureCommand({
      client,
      refreshToken: "refresh-a"
    });
    const allowResult = await evaluateDevicePostureCommand({
      client: createClient({
        reportDevicePosture: vi.fn().mockResolvedValue({
          risk_score: 12,
          action: "allow",
          compliant: true,
          reasons: ["baseline"],
          step_up_required: false,
          session_revoked: false
        })
      }),
      refreshToken: "refresh-b"
    });

    expect(stepUpResult.riskResult).toEqual({
      required: true,
      action: "step_up",
      challenge: null
    });
    expect(stepUpResult.securityNotice?.title).toBe("Step-up required");
    expect(stepUpResult.statusMessage).toBe("Device posture escalated to step-up.");
    expect(allowResult).toEqual({
      riskResult: {
        required: false,
        action: "allow",
        challenge: null
      },
      statusMessage: "Device posture action: allow."
    });
  });

  it("completes step-up and loads plus delegates approval work", async () => {
    const client = createClient();

    const stepUpResult = await completeStepUpCommand({
      client,
      refreshToken: "refresh-a",
      mfaCode: "000000",
      challenge: null
    });
    const approvalTasks = await loadApprovalQueueCommand({
      client
    });
    const delegateResult = await delegateApprovalCommand({
      client,
      instanceId: "approval-a"
    });

    expect(client.verifyStepUp).toHaveBeenCalledWith({
      refreshToken: "refresh-a",
      code: "000000"
    });
    expect(stepUpResult.session.sessionId).toBe("session-c");
    expect(stepUpResult.riskResult).toEqual({
      required: false,
      action: "allow",
      challenge: null
    });
    expect(approvalTasks[0]?.instance_id).toBe("approval-a");
    expect(delegateResult.approvalMessage).toBe("Executed delegate -> delegated");
  });

  it("completes step-up with a browser webauthn assertion when the challenge requires it", async () => {
    const client = createClient({
      createWebAuthnAssertion: vi.fn().mockResolvedValue({
        credentialId: "credential-a",
        clientDataJson: "client-data",
        authenticatorData: "auth-data",
        signature: "signature-a"
      })
    });

    await completeStepUpCommand({
      client,
      refreshToken: "refresh-a",
      mfaCode: "ignored",
      challenge: {
        challengeId: "challenge-a",
        method: "webauthn",
        reason: "continuous risk assessment requires step-up",
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
    });

    expect(client.createWebAuthnAssertion).toHaveBeenCalledWith({
      challenge: "challenge-a",
      rpId: "sdqp.local",
      origin: "https://sdqp.local",
      credentialId: "credential-a",
      timeoutMs: 300000,
      userVerification: "required"
    });
    expect(client.verifyStepUp).toHaveBeenCalledWith({
      refreshToken: "refresh-a",
      webauthnAssertion: {
        credentialId: "credential-a",
        clientDataJson: "client-data",
        authenticatorData: "auth-data",
        signature: "signature-a"
      }
    });
  });
});
