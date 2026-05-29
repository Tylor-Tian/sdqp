import type {
  ApprovalTask,
  FrontendClient,
  MfaChallengeDetails,
  PermissionApplication,
  PermissionGrantsResponse,
  SessionTokens
} from "./api";
import { ApiError } from "./api";
import type { RiskResult, SecurityNotice } from "./authWorkspaceController";

type LoginClient = Pick<FrontendClient, "beginLogin">;
type SessionClient = Pick<FrontendClient, "refreshSession">;
type ProjectClient = Pick<FrontendClient, "setSession" | "getPermissionGrants" | "changeProjectState">;
type PermissionClient = Pick<FrontendClient, "submitPermissionApplication">;
type SecurityClient = Pick<
  FrontendClient,
  "reportDevicePosture" | "verifyStepUp" | "createWebAuthnAssertion"
>;

async function createWebAuthnAssertion(
  client: SecurityClient,
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
type ApprovalClient = Pick<FrontendClient, "getApprovalTasks" | "submitApprovalAction">;

export async function startLoginCommand({
  client,
  username
}: {
  client: LoginClient;
  username: string;
}) {
  const nextChallenge = await client.beginLogin({
    username,
    password: "password123",
    deviceFingerprint: "sdqp-ops-console"
  });
  return {
    pendingSessionId: nextChallenge.pendingSessionId,
    method: nextChallenge.method,
    details: nextChallenge.challenge ?? null
  };
}

export async function refreshSessionCommand({
  client
}: {
  client: SessionClient;
}) {
  return client.refreshSession();
}

export async function switchProjectCommand({
  client,
  session,
  personaUsername,
  nextProjectId,
  refreshAnalysisTemplates
}: {
  client: Pick<ProjectClient, "setSession" | "getPermissionGrants">;
  session: SessionTokens | null;
  personaUsername: string;
  nextProjectId: string;
  refreshAnalysisTemplates: () => Promise<unknown>;
}) {
  client.setSession(session, {
    username: personaUsername,
    projectId: nextProjectId
  });
  const grantsResponse = await client.getPermissionGrants();
  await refreshAnalysisTemplates();
  return {
    permissionGrants: grantsResponse.grants satisfies PermissionGrantsResponse["grants"]
  };
}

export async function freezeProjectCommand({
  client,
  projectId
}: {
  client: Pick<ProjectClient, "changeProjectState">;
  projectId: string;
}) {
  const result = await client.changeProjectState(projectId, "frozen", "ops rehearsal");
  return {
    projectStateMessage: result.current_state
  };
}

export async function submitPermissionRequestCommand({
  client,
  requestedFields
}: {
  client: PermissionClient;
  requestedFields: string[];
}) {
  return client.submitPermissionApplication({
    dataSourceId: "datasource-rest",
    requestedFields
  }) satisfies Promise<PermissionApplication>;
}

export async function evaluateDevicePostureCommand({
  client,
  refreshToken
}: {
  client: SecurityClient;
  refreshToken: string;
}) {
  const result = await client.reportDevicePosture({
    refreshToken,
    profile: "legacy",
    ipDrift: true,
    queryBurst: 8
  });
  const riskResult = {
    required: result.step_up_required,
    action: result.action,
    challenge: result.step_up_challenge ?? null
  } satisfies RiskResult;

  if (result.step_up_required) {
    return {
      riskResult,
      securityNotice: {
        kind: "step-up",
        title: "Step-up required",
        body: "Sensitive actions are paused until step-up verification completes."
      } satisfies SecurityNotice,
      statusMessage: "Device posture escalated to step-up."
    };
  }

  return {
    riskResult,
    statusMessage: `Device posture action: ${result.action}.`
  };
}

export async function completeStepUpCommand({
  client,
  refreshToken,
  mfaCode,
  challenge
}: {
  client: SecurityClient;
  refreshToken: string;
  mfaCode: string;
  challenge?: MfaChallengeDetails | null;
}) {
  const session = await client.verifyStepUp(
    challenge?.webauthnRequest
      ? {
          refreshToken,
          webauthnAssertion: await createWebAuthnAssertion(client, challenge.webauthnRequest)
        }
      : {
          refreshToken,
          code: mfaCode
        }
  );
  return {
    session,
    riskResult: {
      required: false,
      action: "allow",
      challenge: null
    } satisfies RiskResult
  };
}

export async function loadApprovalQueueCommand({
  client
}: {
  client: Pick<ApprovalClient, "getApprovalTasks">;
}) {
  const result = await client.getApprovalTasks();
  return result.tasks satisfies ApprovalTask[];
}

export async function delegateApprovalCommand({
  client,
  instanceId
}: {
  client: Pick<ApprovalClient, "submitApprovalAction">;
  instanceId: string;
}) {
  const result = await client.submitApprovalAction({
    instanceId,
    action: "delegate",
    delegateTo: "delegate"
  });
  return {
    approvalMessage: `Executed delegate -> ${result.status}`
  };
}
