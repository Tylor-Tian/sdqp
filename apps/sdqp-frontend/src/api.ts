export type SessionTokens = {
  accessToken: string;
  refreshToken: string;
  sessionId: string;
};

export type LoginChallenge = {
  pendingSessionId: string;
  mfaRequired: boolean;
  method: string;
  challengeId?: string | null;
  challenge?: MfaChallengeDetails | null;
  authSource?: string | null;
};

export type WebAuthnRequest = {
  challenge: string;
  rpId: string;
  origin: string;
  credentialId: string;
  timeoutMs: number;
  userVerification: string;
};

export type WebAuthnAssertion = {
  credentialId: string;
  clientDataJson: string;
  authenticatorData: string;
  signature: string;
};

export type MfaChallengeDetails = {
  challengeId: string;
  method: string;
  reason?: string | null;
  expiresAt: string;
  webauthnRequest?: WebAuthnRequest | null;
};

type ErrorPayload = {
  error?: string;
  message?: string;
  step_up_required?: boolean;
  step_up_challenge?: {
    challenge_id: string;
    method: string;
    reason?: string | null;
    expires_at: string;
    webauthn_request?: {
      challenge: string;
      rp_id: string;
      origin: string;
      credential_id: string;
      timeout_ms: number;
      user_verification: string;
    } | null;
  } | null;
};

export type ProjectsResponse = {
  projects: Array<{
    project_id: string;
    tenant_id: string;
    state: string;
    can_accept_new_permissions: boolean;
    can_export: boolean;
    read_only: boolean;
  }>;
};

export type PermissionApplication = {
  application_id: string;
  applicant_user_id: string;
  project_id: string;
  data_source_id: string;
  requested_fields: string[];
  status: string;
};

export type PermissionGrantsResponse = {
  grants: Array<{
    grant_id: string;
    data_source_id: string;
    status: string;
    fields: string[];
    valid_until: string;
  }>;
};

export type ApprovalTask = {
  instance_id: string;
  application_id: string;
  applicant_user_id: string;
  data_source_id: string;
  step_id: string;
  status: string;
  pending_approvers: string[];
  requested_fields: string[];
  due_at: string;
  escalation_target?: string | null;
  delegated_to?: string | null;
};

export type QueryPriorityLevel = "low" | "normal" | "high" | "critical";

export type QueryPriority = {
  label: QueryPriorityLevel | string;
  value: number;
};

export type QueryRuntimeControlSurface = {
  can_cancel: boolean;
  can_retry: boolean;
  can_access_snapshot: boolean;
};

export type QueryWorkbenchRuntimeState = {
  task_id: string;
  priority: QueryPriority;
  runtime_state: string;
  adapter_runtime_state?: string | null;
  adapter_availability?: string | null;
  secure_snapshot_access: string;
  controls: QueryRuntimeControlSurface;
};

export type QueryTaskStatus = {
  task_id: string;
  state: string;
  snapshot_id: string | null;
  cache_hit: boolean;
  error: string | null;
  priority?: QueryPriority;
  runtime?: QueryWorkbenchRuntimeState;
};

export type QuerySubmitResult = {
  task_id: string;
  status: string;
  websocket_path: string;
  priority?: QueryPriority;
  runtime?: QueryWorkbenchRuntimeState;
};

export type TaskStatusStreamOptions = {
  path?: string;
  replayLast?: boolean;
  onStatus: (status: QueryTaskStatus) => void;
  onError?: (error: unknown) => void;
};

export type TaskStatusStreamSubscription = {
  close(): void;
};

export type FieldDisplayPolicy = {
  field_name: string;
  masked: boolean;
  render_mode: string;
  watermark_strength: string;
};

export type SnapshotPage = {
  snapshot_id: string;
  columns: string[];
  rows: Array<Record<string, string>>;
  next_cursor: number | null;
  field_policies: FieldDisplayPolicy[];
  watermark_text: string;
};

export type SnapshotPageArrowMetadata = Omit<SnapshotPage, "rows">;

export type PivotAnalysis = {
  snapshot_id: string;
  dimension: string;
  metric: string;
  metric_field?: string | null;
  percentile?: number | null;
  buckets: Array<{ key: string; value: number }>;
  watermark_text: string;
};

export type PivotAnalysisArrowMetadata = Omit<PivotAnalysis, "buckets">;

export type AnalysisResponseFormat = "json" | "arrow_ipc";

export type ArrowIpcPayload<TMetadata> = {
  content: ArrayBuffer;
  contentType: string;
  metadata: TMetadata;
};

export type PivotRequest = {
  metric?: string;
  metricField?: string;
  percentile?: number;
};

export type AnalysisTemplateVisibility = "private" | "published";

export type AnalysisTemplateConfig = {
  page_size?: number | null;
  detail_fields: string[];
  pivot_dimension: string;
  pivot_metric: string;
  pivot_metric_field?: string | null;
  pivot_percentile?: number | null;
};

export type AnalysisTemplate = {
  template_id: string;
  name: string;
  description?: string | null;
  data_source_id: string;
  visibility: AnalysisTemplateVisibility;
  owner_user_id: string;
  editable: boolean;
  published_at?: string | null;
  created_at: string;
  updated_at: string;
  config: AnalysisTemplateConfig;
};

export type AnalysisTemplateList = {
  templates: AnalysisTemplate[];
};

export type AuditSearchResponse = {
  chain_valid: boolean;
  total_matches: number;
  events: Array<{
    event_id: string;
    timestamp: string;
    actor_user_id: string;
    action: string;
    result: string;
    tenant_id: string;
    project_id?: string | null;
    resource_id: string;
    context: string;
    data_fingerprint?: string | null;
  }>;
};

export type EvidenceExportResponse = {
  task_id: string;
  status: string;
  package_id: string;
  snapshot_id: string;
  template: string;
  watermark_token: string;
  watermark_text: string;
  exported_document: string;
  audit_event_count: number;
  audit_chain_valid: boolean;
  timestamp_authority: string;
  timestamp_token: string;
  anchor_network: string;
  anchor_transaction_id: string;
  recipient_user_id: string;
  data_payload_kms_provider: string;
  data_payload_dek_id: string;
  data_payload_scope_binding: string;
  audit_extract_event_count: number;
  certificate_title: string;
  certificate_issued_at: string;
  manifest_digest: string;
  verification_ready: boolean;
  file_name: string;
  media_type: string;
  download_ready: boolean;
  created_at: string;
  completed_at?: string | null;
};

export type ExportDownloadAuthorizationResponse = {
  task_id: string;
  download_token: string;
  file_name: string;
  media_type: string;
  expires_at: string;
};

export type DownloadPreview = {
  content: string;
  contentType: string;
  fileName: string;
};

export type UebaAlerts = {
  alerts: Array<{
    alert_id: string;
    user_id: string;
    rule: string;
    risk_score: number;
    action: string;
    evidence: string;
  }>;
  step_up_sessions: number;
  permissions_revoked: number;
  terminated_sessions: number;
};

export type UebaBaselines = {
  user_baselines: Array<Record<string, unknown>>;
  entity_baselines: Array<{
    entity_type: string;
    entity_id: string;
    baseline_window: string;
    query_count: number;
    export_count: number;
    denied_count: number;
    distinct_users: number;
  }>;
};

export class ApiError extends Error {
  status: number;
  stepUpRequired: boolean;
  stepUpChallenge: MfaChallengeDetails | null;

  constructor(
    message: string,
    status: number,
    options?: {
      stepUpRequired?: boolean;
      stepUpChallenge?: MfaChallengeDetails | null;
    }
  ) {
    super(message);
    this.name = "ApiError";
    this.status = status;
    this.stepUpRequired = options?.stepUpRequired ?? false;
    this.stepUpChallenge = options?.stepUpChallenge ?? null;
  }
}

type BrowserEnv = {
  VITE_SDQP_API_BASE_URL?: string;
};

type RuntimeSession = SessionTokens & {
  tenantId: string;
  projectId: string | null;
  username: string | null;
};

export type FrontendClient = {
  setSession(
    session: SessionTokens | null,
    options?: { username?: string | null; projectId?: string | null }
  ): void;
  beginLogin(payload: {
    username: string;
    password: string;
    deviceFingerprint: string;
  }): Promise<LoginChallenge>;
  verifyMfa(payload: {
    pendingSessionId: string;
    code?: string | null;
    webauthnAssertion?: WebAuthnAssertion | null;
  }): Promise<SessionTokens>;
  createWebAuthnAssertion?(request: WebAuthnRequest): Promise<WebAuthnAssertion>;
  refreshSession(): Promise<SessionTokens>;
  logout(): Promise<{ revoked: boolean }>;
  reportDevicePosture(payload: {
    refreshToken: string;
    profile?: string;
    ipDrift?: boolean;
    impossibleTravel?: boolean;
    exfiltrationHint?: boolean;
    queryBurst?: number;
    deniedBurst?: number;
    exportBurst?: number;
  }): Promise<{
    risk_score: number;
    action: string;
    compliant: boolean;
    reasons: string[];
    step_up_required: boolean;
    step_up_challenge?: MfaChallengeDetails | null;
    session_revoked: boolean;
  }>;
  verifyStepUp(payload: {
    refreshToken: string;
    code?: string | null;
    webauthnAssertion?: WebAuthnAssertion | null;
  }): Promise<SessionTokens>;
  getProjects(): Promise<ProjectsResponse>;
  changeProjectState(projectId: string, nextState: string, reason?: string): Promise<{
    project_id: string;
    previous_state: string;
    current_state: string;
    revoked_permissions: number;
    deleted_snapshots: number;
    checkpoint_id: string;
  }>;
  submitPermissionApplication(payload: {
    dataSourceId: string;
    requestedFields: string[];
  }): Promise<PermissionApplication>;
  getPermissionGrants(): Promise<PermissionGrantsResponse>;
  getApprovalTasks(): Promise<{ tasks: ApprovalTask[] }>;
  submitApprovalAction(payload: {
    instanceId: string;
    action: string;
    delegateTo?: string;
  }): Promise<{ instance_id: string; status: string; application_status: string }>;
  submitQuery(payload: {
    dataSourceId: string;
    sourceType: string;
    fields: string[];
    priority?: QueryPriorityLevel;
  }): Promise<QuerySubmitResult>;
  getTaskStatus(taskId: string): Promise<QueryTaskStatus>;
  streamTaskStatus(taskId: string, options: TaskStatusStreamOptions): TaskStatusStreamSubscription;
  cancelTask(taskId: string): Promise<{ task_id: string; cancelled: boolean }>;
  getSnapshotPage(snapshotId: string, pageSize: number, cursor?: number | null): Promise<SnapshotPage>;
  getSnapshotPageArrowIpc(
    snapshotId: string,
    pageSize: number,
    cursor?: number | null
  ): Promise<ArrowIpcPayload<SnapshotPageArrowMetadata>>;
  getPivot(snapshotId: string, dimension: string, options?: PivotRequest): Promise<PivotAnalysis>;
  getPivotArrowIpc(
    snapshotId: string,
    dimension: string,
    options?: PivotRequest
  ): Promise<ArrowIpcPayload<PivotAnalysisArrowMetadata>>;
  getDrilldown(payload: {
    snapshotId: string;
    dimension: string;
    value: string;
    fields: string[];
  }): Promise<SnapshotPage>;
  listAnalysisTemplates(): Promise<AnalysisTemplateList>;
  createAnalysisTemplate(payload: {
    name: string;
    description?: string | null;
    dataSourceId: string;
    config: AnalysisTemplateConfig;
  }): Promise<AnalysisTemplate>;
  getAnalysisTemplate(templateId: string): Promise<AnalysisTemplate>;
  updateAnalysisTemplate(
    templateId: string,
    payload: {
      name: string;
      description?: string | null;
      dataSourceId: string;
      config: AnalysisTemplateConfig;
    }
  ): Promise<AnalysisTemplate>;
  publishAnalysisTemplate(templateId: string): Promise<AnalysisTemplate>;
  unpublishAnalysisTemplate(templateId: string): Promise<AnalysisTemplate>;
  deleteAnalysisTemplate(templateId: string): Promise<{ template_id: string; deleted: boolean }>;
  searchAudit(filters: { action?: string; limit?: number }): Promise<AuditSearchResponse>;
  exportEvidence(payload: {
    snapshotId: string;
    template: string;
    exportBody?: string;
  }): Promise<EvidenceExportResponse>;
  getExportTask(taskId: string): Promise<EvidenceExportResponse>;
  authorizeDownload(taskId: string, ttlSeconds?: number): Promise<ExportDownloadAuthorizationResponse>;
  downloadExport(downloadToken: string): Promise<DownloadPreview>;
  getUebaAlerts(): Promise<UebaAlerts>;
  getUebaBaselines(): Promise<UebaBaselines>;
};

export function resolveApiBaseUrl(env: BrowserEnv = import.meta.env): string {
  const configured = env.VITE_SDQP_API_BASE_URL?.trim();
  if (!configured) {
    return "";
  }

  return configured.replace(/\/+$/, "");
}

function decodeClaims(token: string): { tenant_id: string } {
  const payload = token.split(".")[1];
  if (!payload) {
    return { tenant_id: "tenant-alpha" };
  }

  const normalized = payload.replace(/-/g, "+").replace(/_/g, "/");
  const padded = normalized.padEnd(Math.ceil(normalized.length / 4) * 4, "=");
  const decoded = JSON.parse(window.atob(padded));
  return { tenant_id: decoded.tenant_id ?? "tenant-alpha" };
}

function base64UrlToBytes(value: string): Uint8Array {
  const normalized = value.replace(/-/g, "+").replace(/_/g, "/");
  const padded = normalized.padEnd(Math.ceil(normalized.length / 4) * 4, "=");
  const decoded = window.atob(padded);
  return Uint8Array.from(decoded, (char) => char.charCodeAt(0));
}

function bytesToBase64Url(value: ArrayBuffer | Uint8Array): string {
  const bytes = value instanceof Uint8Array ? value : new Uint8Array(value);
  let binary = "";
  for (const byte of bytes) {
    binary += String.fromCharCode(byte);
  }
  return window
    .btoa(binary)
    .replace(/\+/g, "-")
    .replace(/\//g, "_")
    .replace(/=+$/g, "");
}

function normalizeErrorPayload(payload: ErrorPayload | null | undefined, status: number) {
  return {
    message: payload?.error ?? payload?.message ?? `Request failed: ${status}`,
    stepUpRequired: Boolean(payload?.step_up_required),
    stepUpChallenge: normalizeMfaChallenge(payload?.step_up_challenge)
  };
}

async function readErrorPayload(response: Response) {
  const payload = (await response
    .json()
    .catch(() => ({ error: `Request failed: ${response.status}` }))) as ErrorPayload;
  return normalizeErrorPayload(payload, response.status);
}

async function readJson<T>(response: Response): Promise<T> {
  if (!response.ok) {
    const payload = await readErrorPayload(response);
    throw new ApiError(payload.message, response.status, {
      stepUpRequired: payload.stepUpRequired,
      stepUpChallenge: payload.stepUpChallenge
    });
  }

  return (await response.json()) as T;
}

function decodeBase64Json<T>(value: string | null): T {
  if (!value) {
    throw new ApiError("Missing Arrow IPC metadata header", 500);
  }

  const decoded = window.atob(value);
  return JSON.parse(decoded) as T;
}

function normalizeMfaChallenge(
  value:
    | MfaChallengeDetails
    | {
        challenge_id: string;
        method: string;
        reason?: string | null;
        expires_at: string;
        webauthn_request?: {
          challenge: string;
          rp_id: string;
          origin: string;
          credential_id: string;
          timeout_ms: number;
          user_verification: string;
        } | null;
      }
    | null
    | undefined
): MfaChallengeDetails | null {
  if (!value) {
    return null;
  }
  const candidate = value as {
    challengeId?: string;
    challenge_id?: string;
    method: string;
    reason?: string | null;
    expiresAt?: string;
    expires_at?: string;
    webauthnRequest?: WebAuthnRequest | null;
    webauthn_request?: {
      challenge: string;
      rp_id: string;
      origin: string;
      credential_id: string;
      timeout_ms: number;
      user_verification: string;
    } | null;
  };
  const webauthnRequest = candidate.webauthnRequest
    ? candidate.webauthnRequest
    : candidate.webauthn_request
      ? {
          challenge: candidate.webauthn_request.challenge,
          rpId: candidate.webauthn_request.rp_id,
          origin: candidate.webauthn_request.origin,
          credentialId: candidate.webauthn_request.credential_id,
          timeoutMs: candidate.webauthn_request.timeout_ms,
          userVerification: candidate.webauthn_request.user_verification
        }
      : null;
  return {
    challengeId: candidate.challengeId ?? candidate.challenge_id ?? "",
    method: candidate.method,
    reason: candidate.reason ?? null,
    expiresAt: candidate.expiresAt ?? candidate.expires_at ?? "",
    webauthnRequest
  };
}

async function createBrowserWebAuthnAssertion(
  request: WebAuthnRequest
): Promise<WebAuthnAssertion> {
  if (
    typeof window === "undefined" ||
    typeof window.PublicKeyCredential === "undefined" ||
    !navigator.credentials?.get
  ) {
    throw new ApiError("WebAuthn is unavailable in this browser.", 400);
  }

  const credential = (await navigator.credentials.get({
    publicKey: {
      challenge: base64UrlToBytes(request.challenge),
      rpId: request.rpId,
      timeout: request.timeoutMs,
      userVerification: request.userVerification as UserVerificationRequirement,
      allowCredentials: [
        {
          id: base64UrlToBytes(request.credentialId),
          type: "public-key"
        }
      ]
    }
  })) as PublicKeyCredential | null;

  if (!credential) {
    throw new ApiError("WebAuthn authentication was cancelled.", 400);
  }

  const response = credential.response as Partial<{
    clientDataJSON: ArrayBuffer;
    authenticatorData: ArrayBuffer;
    signature: ArrayBuffer;
  }>;
  if (!response.clientDataJSON || !response.authenticatorData || !response.signature) {
    throw new ApiError("WebAuthn assertion response is malformed.", 400);
  }

  return {
    credentialId: bytesToBase64Url(credential.rawId),
    clientDataJson: bytesToBase64Url(response.clientDataJSON),
    authenticatorData: bytesToBase64Url(response.authenticatorData),
    signature: bytesToBase64Url(response.signature)
  };
}

export function createBrowserClient(baseUrl = resolveApiBaseUrl()): FrontendClient {
  let runtime: RuntimeSession | null = null;

  function websocketOrigin(): string {
    if (baseUrl) {
      return baseUrl.replace(/^http/i, "ws");
    }

    if (typeof window !== "undefined") {
      return window.location.origin.replace(/^http/i, "ws");
    }

    return "ws://localhost";
  }

  function buildTaskStreamUrl(taskId: string, options: TaskStatusStreamOptions): string {
    const target = options.path ?? `/v1/tasks/${taskId}/ws`;
    const url = new URL(target, websocketOrigin());
    url.searchParams.set("replay_last", String(options.replayLast ?? true));
    if (runtime) {
      url.searchParams.set("access_token", runtime.accessToken);
      url.searchParams.set("tenant_id", runtime.tenantId);
      if (runtime.projectId) {
        url.searchParams.set("project_id", runtime.projectId);
      }
    }
    return url.toString();
  }

  async function request<T>(path: string, init?: RequestInit, scope: "public" | "tenant" | "project" = "project"): Promise<T> {
    const headers = new Headers(init?.headers);
    if (init?.body) {
      headers.set("content-type", "application/json");
    }

    if (scope !== "public" && runtime) {
      headers.set("authorization", `Bearer ${runtime.accessToken}`);
      headers.set("x-tenant-id", runtime.tenantId);
      if (scope === "project" && runtime.projectId) {
        headers.set("x-project-id", runtime.projectId);
      }
    }

    const response = await fetch(baseUrl ? `${baseUrl}${path}` : path, { ...init, headers });
    return readJson<T>(response);
  }

  async function requestBinary<TMetadata>(
    path: string,
    init?: RequestInit,
    scope: "public" | "tenant" | "project" = "project"
  ): Promise<ArrowIpcPayload<TMetadata>> {
    const headers = new Headers(init?.headers);
    if (init?.body) {
      headers.set("content-type", "application/json");
    }

    if (scope !== "public" && runtime) {
      headers.set("authorization", `Bearer ${runtime.accessToken}`);
      headers.set("x-tenant-id", runtime.tenantId);
      if (scope === "project" && runtime.projectId) {
        headers.set("x-project-id", runtime.projectId);
      }
    }

    const response = await fetch(baseUrl ? `${baseUrl}${path}` : path, { ...init, headers });
    if (!response.ok) {
      const payload = await readErrorPayload(response);
      throw new ApiError(payload.message, response.status, {
        stepUpRequired: payload.stepUpRequired,
        stepUpChallenge: payload.stepUpChallenge
      });
    }

    return {
      content: await response.arrayBuffer(),
      contentType: response.headers.get("content-type") ?? "application/octet-stream",
      metadata: decodeBase64Json<TMetadata>(response.headers.get("x-sdqp-response-meta"))
    };
  }

  return {
    setSession(session, options) {
      if (!session) {
        runtime = null;
        return;
      }
      const claims = decodeClaims(session.accessToken);
      runtime = {
        ...session,
        tenantId: claims.tenant_id,
        projectId: options?.projectId ?? runtime?.projectId ?? null,
        username: options?.username ?? runtime?.username ?? null
      };
    },

    beginLogin(payload) {
      return request<LoginChallenge>("/auth/login", {
        method: "POST",
        body: JSON.stringify({
          username: payload.username,
          password: payload.password,
          device_fingerprint: payload.deviceFingerprint
        })
      }, "public").then((value) => ({
        pendingSessionId: value.pendingSessionId ?? (value as unknown as { pending_session_id: string }).pending_session_id,
        mfaRequired: value.mfaRequired ?? (value as unknown as { mfa_required: boolean }).mfa_required,
        method: value.method,
        challengeId: value.challengeId ?? (value as unknown as { challenge_id?: string }).challenge_id,
        challenge: normalizeMfaChallenge(
          (value as LoginChallenge & {
            challenge?: MfaChallengeDetails | null;
          }).challenge ??
            (value as unknown as {
              challenge?: {
                challenge_id: string;
                method: string;
                reason?: string | null;
                expires_at: string;
                webauthn_request?: {
                  challenge: string;
                  rp_id: string;
                  origin: string;
                  credential_id: string;
                  timeout_ms: number;
                  user_verification: string;
                } | null;
              } | null;
            }).challenge
        ),
        authSource: value.authSource ?? (value as unknown as { auth_source?: string }).auth_source
      }));
    },

    verifyMfa(payload) {
      return request<{ access_token: string; refresh_token: string; session_id: string }>("/auth/mfa/verify", {
        method: "POST",
        body: JSON.stringify({
          pending_session_id: payload.pendingSessionId,
          code: payload.code ?? null,
          webauthn_assertion: payload.webauthnAssertion
            ? {
                credential_id: payload.webauthnAssertion.credentialId,
                client_data_json: payload.webauthnAssertion.clientDataJson,
                authenticator_data: payload.webauthnAssertion.authenticatorData,
                signature: payload.webauthnAssertion.signature
              }
            : null
        })
      }, "public").then((value) => ({
        accessToken: value.access_token,
        refreshToken: value.refresh_token,
        sessionId: value.session_id
      }));
    },

    createWebAuthnAssertion(request) {
      return createBrowserWebAuthnAssertion(request);
    },

    refreshSession() {
      return request<{ access_token: string; refresh_token: string; session_id: string }>("/auth/refresh", {
        method: "POST",
        body: JSON.stringify({ refresh_token: runtime?.refreshToken })
      }, "public").then((value) => ({
        accessToken: value.access_token,
        refreshToken: value.refresh_token,
        sessionId: value.session_id
      }));
    },

    logout() {
      return request<{ revoked: boolean }>("/auth/logout", {
        method: "POST",
        body: JSON.stringify({ refresh_token: runtime?.refreshToken })
      }, "public");
    },

    reportDevicePosture(payload) {
      return request("/auth/device-posture", {
        method: "POST",
        body: JSON.stringify({
          refresh_token: payload.refreshToken,
          profile: payload.profile ?? null,
          ip_drift: Boolean(payload.ipDrift),
          impossible_travel: Boolean(payload.impossibleTravel),
          exfiltration_hint: Boolean(payload.exfiltrationHint),
          query_burst: payload.queryBurst ?? null,
          denied_burst: payload.deniedBurst ?? null,
          export_burst: payload.exportBurst ?? null
        })
      }, "public").then((value) => {
        const response = value as {
          risk_score: number;
          action: string;
          compliant: boolean;
          reasons: string[];
          step_up_required: boolean;
          step_up_challenge?: unknown;
          session_revoked: boolean;
        };
        return {
          ...response,
          step_up_challenge: normalizeMfaChallenge(response.step_up_challenge as never)
        };
      });
    },

    verifyStepUp(payload) {
      return request<{ access_token: string; refresh_token: string; session_id: string }>("/auth/step-up/verify", {
        method: "POST",
        body: JSON.stringify({
          refresh_token: payload.refreshToken,
          code: payload.code ?? null,
          webauthn_assertion: payload.webauthnAssertion
            ? {
                credential_id: payload.webauthnAssertion.credentialId,
                client_data_json: payload.webauthnAssertion.clientDataJson,
                authenticator_data: payload.webauthnAssertion.authenticatorData,
                signature: payload.webauthnAssertion.signature
              }
            : null
        })
      }, "public").then((value) => ({
        accessToken: value.access_token,
        refreshToken: value.refresh_token,
        sessionId: value.session_id
      }));
    },

    getProjects() {
      return request<ProjectsResponse>("/v1/projects", undefined, "tenant");
    },

    changeProjectState(projectId, nextState, reason) {
      return request(`/v1/projects/${projectId}/state`, {
        method: "POST",
        body: JSON.stringify({ next_state: nextState, reason: reason ?? null })
      }, "tenant");
    },

    submitPermissionApplication(payload) {
      return request("/v1/permissions/applications", {
        method: "POST",
        body: JSON.stringify({
          data_source_id: payload.dataSourceId,
          requested_fields: payload.requestedFields
        })
      });
    },

    getPermissionGrants() {
      return request<PermissionGrantsResponse>("/v1/permissions/grants");
    },

    getApprovalTasks() {
      return request<{ tasks: ApprovalTask[] }>("/v1/approvals/tasks");
    },

    submitApprovalAction(payload) {
      return request("/v1/approvals/callback", {
        method: "POST",
        body: JSON.stringify({
          instance_id: payload.instanceId,
          action: payload.action,
          delegate_to: payload.delegateTo ?? null
        })
      });
    },

    submitQuery(payload) {
      return request("/v1/queries", {
        method: "POST",
        body: JSON.stringify({
          data_source_id: payload.dataSourceId,
          source_type: payload.sourceType,
          fields: payload.fields,
          priority: payload.priority ?? "normal"
        })
      });
    },

    getTaskStatus(taskId) {
      return request<QueryTaskStatus>(`/v1/tasks/${taskId}/status`);
    },

    streamTaskStatus(taskId, options) {
      const socket = new WebSocket(buildTaskStreamUrl(taskId, options));
      let disposed = false;
      let errorReported = false;
      const reportError = (error: unknown) => {
        if (disposed || errorReported) {
          return;
        }
        errorReported = true;
        options.onError?.(error);
      };

      socket.onmessage = (event) => {
        try {
          const payload = JSON.parse(String(event.data)) as QueryTaskStatus;
          options.onStatus(payload);
        } catch {
          reportError(new ApiError("invalid task stream payload", 500));
        }
      };
      socket.onerror = () => {
        reportError(new ApiError("task status websocket failed", 0));
      };
      socket.onclose = (event) => {
        if (disposed || event.code === 1000 || event.code === 1005) {
          return;
        }
        reportError(new ApiError(event.reason || "task status websocket closed", event.code || 0));
      };

      return {
        close() {
          disposed = true;
          if (socket.readyState === WebSocket.CONNECTING || socket.readyState === WebSocket.OPEN) {
            socket.close(1000, "client dispose");
          }
        }
      };
    },

    cancelTask(taskId) {
      return request<{ task_id: string; cancelled: boolean }>(`/v1/tasks/${taskId}/cancel`, {
        method: "DELETE"
      });
    },

    getSnapshotPage(snapshotId, pageSize, cursor) {
      const search = new URLSearchParams({ page_size: String(pageSize) });
      if (cursor != null) {
        search.set("cursor", String(cursor));
      }
      return request<SnapshotPage>(`/v1/snapshots/${snapshotId}/page?${search.toString()}`);
    },

    getSnapshotPageArrowIpc(snapshotId, pageSize, cursor) {
      const search = new URLSearchParams({
        page_size: String(pageSize),
        response_format: "arrow_ipc"
      });
      if (cursor != null) {
        search.set("cursor", String(cursor));
      }
      return requestBinary<SnapshotPageArrowMetadata>(
        `/v1/snapshots/${snapshotId}/page?${search.toString()}`
      );
    },

    getPivot(snapshotId, dimension, options = {}) {
      const body: Record<string, unknown> = {
        snapshot_id: snapshotId,
        dimension
      };
      if (options.metric) {
        body.metric = options.metric;
      }
      if (options.metricField) {
        body.metric_field = options.metricField;
      }
      if (options.percentile != null) {
        body.percentile = options.percentile;
      }
      return request<PivotAnalysis>("/v1/analysis/pivot", {
        method: "POST",
        body: JSON.stringify(body)
      });
    },

    getPivotArrowIpc(snapshotId, dimension, options = {}) {
      const body: Record<string, unknown> = {
        snapshot_id: snapshotId,
        dimension,
        response_format: "arrow_ipc"
      };
      if (options.metric) {
        body.metric = options.metric;
      }
      if (options.metricField) {
        body.metric_field = options.metricField;
      }
      if (options.percentile != null) {
        body.percentile = options.percentile;
      }
      return requestBinary<PivotAnalysisArrowMetadata>("/v1/analysis/pivot", {
        method: "POST",
        body: JSON.stringify(body)
      });
    },

    getDrilldown(payload) {
      return request<SnapshotPage>("/v1/analysis/pivot/drilldown", {
        method: "POST",
        body: JSON.stringify({
          snapshot_id: payload.snapshotId,
          dimension: payload.dimension,
          value: payload.value,
          fields: payload.fields
        })
      });
    },

    listAnalysisTemplates() {
      return request<AnalysisTemplateList>("/v1/analysis/templates");
    },

    createAnalysisTemplate(payload) {
      return request<AnalysisTemplate>("/v1/analysis/templates", {
        method: "POST",
        body: JSON.stringify({
          name: payload.name,
          description: payload.description ?? null,
          data_source_id: payload.dataSourceId,
          config: payload.config
        })
      });
    },

    getAnalysisTemplate(templateId) {
      return request<AnalysisTemplate>(`/v1/analysis/templates/${templateId}`);
    },

    updateAnalysisTemplate(templateId, payload) {
      return request<AnalysisTemplate>(`/v1/analysis/templates/${templateId}`, {
        method: "PUT",
        body: JSON.stringify({
          name: payload.name,
          description: payload.description ?? null,
          data_source_id: payload.dataSourceId,
          config: payload.config
        })
      });
    },

    publishAnalysisTemplate(templateId) {
      return request<AnalysisTemplate>(`/v1/analysis/templates/${templateId}/publish`, {
        method: "POST",
        body: JSON.stringify({})
      });
    },

    unpublishAnalysisTemplate(templateId) {
      return request<AnalysisTemplate>(`/v1/analysis/templates/${templateId}/unpublish`, {
        method: "POST",
        body: JSON.stringify({})
      });
    },

    deleteAnalysisTemplate(templateId) {
      return request<{ template_id: string; deleted: boolean }>(
        `/v1/analysis/templates/${templateId}`,
        {
          method: "DELETE"
        }
      );
    },

    searchAudit(filters) {
      const search = new URLSearchParams();
      if (filters.action) {
        search.set("action", filters.action);
      }
      if (filters.limit) {
        search.set("limit", String(filters.limit));
      }
      return request<AuditSearchResponse>(`/v1/audit/events/search?${search.toString()}`);
    },

    exportEvidence(payload) {
      return request<EvidenceExportResponse>("/v1/exports/evidence", {
        method: "POST",
        body: JSON.stringify({
          snapshot_id: payload.snapshotId,
          template: payload.template,
          export_body: payload.exportBody ?? null
        })
      });
    },

    getExportTask(taskId) {
      return request<EvidenceExportResponse>(`/v1/exports/tasks/${taskId}`);
    },

    authorizeDownload(taskId, ttlSeconds) {
      return request<ExportDownloadAuthorizationResponse>(`/v1/exports/tasks/${taskId}/authorize-download`, {
        method: "POST",
        body: JSON.stringify({ ttl_seconds: ttlSeconds ?? 300 })
      });
    },

    async downloadExport(downloadToken) {
      const response = await fetch(baseUrl ? `${baseUrl}/v1/exports/download/${downloadToken}` : `/v1/exports/download/${downloadToken}`, {
        headers: {
          authorization: runtime ? `Bearer ${runtime.accessToken}` : "",
          "x-tenant-id": runtime?.tenantId ?? "",
          "x-project-id": runtime?.projectId ?? ""
        }
      });
      if (!response.ok) {
        const contentType = response.headers.get("content-type") ?? "";
        if (contentType.includes("application/json")) {
          const payload = await readErrorPayload(response);
          throw new ApiError(payload.message, response.status, {
            stepUpRequired: payload.stepUpRequired,
            stepUpChallenge: payload.stepUpChallenge
          });
        }
        const fallbackText = await response.text().catch(() => "");
        throw new ApiError(fallbackText || `Request failed: ${response.status}`, response.status);
      }
      return {
        content: await response.text(),
        contentType: response.headers.get("content-type") ?? "text/plain",
        fileName: response.headers.get("content-disposition") ?? "download.txt"
      };
    },

    getUebaAlerts() {
      return request<UebaAlerts>("/v1/ueba/alerts");
    },

    getUebaBaselines() {
      return request<UebaBaselines>("/v1/ueba/baselines");
    }
  };
}
