import { fireEvent, render, screen } from "@testing-library/react";
import { describe, expect, it, vi } from "vitest";
import type {
  ApprovalTask,
  PermissionApplication,
  PermissionGrantsResponse,
  ProjectsResponse
} from "../api";
import { ApprovalQueuePanel } from "./ApprovalQueuePanel";
import { ConsoleHeroPanel } from "./ConsoleHeroPanel";
import { MfaChallengePanel } from "./MfaChallengePanel";
import { PermissionsPanel } from "./PermissionsPanel";
import { ProjectControlPanel } from "./ProjectControlPanel";
import { SecurityNoticeBanner } from "./SecurityNoticeBanner";
import { SecurityPanel } from "./SecurityPanel";

const projects: ProjectsResponse["projects"] = [
  {
    project_id: "project-alpha",
    tenant_id: "tenant-alpha",
    state: "active",
    can_accept_new_permissions: true,
    can_export: true,
    read_only: false
  }
];

const permissionApplication: PermissionApplication = {
  application_id: "application-a",
  applicant_user_id: "user-analyst",
  project_id: "project-alpha",
  data_source_id: "datasource-rest",
  requested_fields: ["employee_id", "department"],
  status: "pending"
};

const permissionGrants: PermissionGrantsResponse["grants"] = [
  {
    grant_id: "grant-a",
    data_source_id: "datasource-rest",
    status: "active",
    fields: ["employee_id", "department"],
    valid_until: "2026-03-30T10:00:00Z"
  }
];

const approvalTasks: ApprovalTask[] = [
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
];

describe("control panels", () => {
  it("routes hero session actions through the extracted console hero panel", () => {
    const onPersonaKeyChange = vi.fn();
    const onStartLogin = vi.fn();
    const onCompleteMfa = vi.fn();
    const onRefreshSession = vi.fn();

    render(
      <ConsoleHeroPanel
        personaKey="analyst"
        personas={[
          { key: "analyst", username: "analyst", label: "Analyst", mfaCode: "000000" },
          { key: "security", username: "security", label: "Security", mfaCode: "000000" }
        ]}
        challengePending
        hasSession
        statusMessage="Workspace hydrated."
        isHydrating={false}
        onPersonaKeyChange={onPersonaKeyChange}
        onStartLogin={onStartLogin}
        onCompleteMfa={onCompleteMfa}
        onRefreshSession={onRefreshSession}
      />
    );

    fireEvent.change(screen.getByRole("combobox", { name: "Persona" }), {
      target: { value: "security" }
    });
    fireEvent.click(screen.getByRole("button", { name: "Start Login" }));
    fireEvent.click(screen.getByRole("button", { name: "Complete MFA" }));
    fireEvent.click(screen.getByRole("button", { name: "Refresh Session" }));

    expect(onPersonaKeyChange).toHaveBeenCalledWith("security");
    expect(onStartLogin).toHaveBeenCalledTimes(1);
    expect(onCompleteMfa).toHaveBeenCalledTimes(1);
    expect(onRefreshSession).toHaveBeenCalledTimes(1);
    expect(screen.getByText("Workspace hydrated.")).toBeInTheDocument();
  });

  it("renders extracted security notice and MFA challenge panels", () => {
    const { container } = render(
      <>
        <SecurityNoticeBanner
          notice={{
            kind: "timeout",
            title: "Session expired",
            body: "Reauthenticate to continue operating in this console."
          }}
        />
        <MfaChallengePanel challenge={{ pendingSessionId: "pending-a", method: "totp" }} />
      </>
    );

    expect(screen.getByText("Session expired")).toBeInTheDocument();
    expect(screen.getByText("pending-a / totp")).toBeInTheDocument();
    expect(container.querySelector(".securityBanner--timeout")).not.toBeNull();
  });

  it("routes project switch and freeze actions through the extracted project control panel", () => {
    const onSwitchProject = vi.fn();
    const onFreezeProject = vi.fn();

    render(
      <ProjectControlPanel
        isHydrating={false}
        projectId="project-alpha"
        projects={projects}
        projectStateMessage="frozen"
        onSwitchProject={onSwitchProject}
        onFreezeProject={onFreezeProject}
      />
    );

    fireEvent.click(screen.getByRole("button", { name: "Switch Project" }));
    fireEvent.click(screen.getByRole("button", { name: "Freeze Project" }));

    expect(onSwitchProject).toHaveBeenCalledWith("project-alpha");
    expect(onFreezeProject).toHaveBeenCalledWith("project-alpha");
    expect(screen.getByText("frozen")).toBeInTheDocument();
  });

  it("routes permission actions through the extracted permissions panel", () => {
    const onSubmitPermissionRequest = vi.fn();

    render(
      <PermissionsPanel
        isHydrating={false}
        permissionApplication={permissionApplication}
        permissionGrants={permissionGrants}
        onSubmitPermissionRequest={onSubmitPermissionRequest}
      />
    );

    fireEvent.click(screen.getByRole("button", { name: "Submit Permission Request" }));

    expect(onSubmitPermissionRequest).toHaveBeenCalledTimes(1);
    expect(screen.getByText("application-a")).toBeInTheDocument();
    expect(screen.getByText("employee_id, department")).toBeInTheDocument();
  });

  it("routes security posture and approval actions through the extracted control panels", () => {
    const onEvaluateDevicePosture = vi.fn();
    const onCompleteStepUp = vi.fn();
    const onLoadApprovalQueue = vi.fn();
    const onDelegateApproval = vi.fn();

    render(
      <>
        <SecurityPanel
          isHydrating={false}
          riskResult={{ required: true, action: "step_up" }}
          onEvaluateDevicePosture={onEvaluateDevicePosture}
          onCompleteStepUp={onCompleteStepUp}
        />
        <ApprovalQueuePanel
          isHydrating={false}
          approvalTasks={approvalTasks}
          approvalMessage="Executed delegate -> delegated"
          onLoadApprovalQueue={onLoadApprovalQueue}
          onDelegateApproval={onDelegateApproval}
        />
      </>
    );

    fireEvent.click(screen.getByRole("button", { name: "Evaluate Device Posture" }));
    fireEvent.click(screen.getByRole("button", { name: "Complete Step-Up" }));
    fireEvent.click(screen.getByRole("button", { name: "Load Approval Queue" }));
    fireEvent.click(screen.getByRole("button", { name: "Delegate" }));

    expect(onEvaluateDevicePosture).toHaveBeenCalledTimes(1);
    expect(onCompleteStepUp).toHaveBeenCalledTimes(1);
    expect(onLoadApprovalQueue).toHaveBeenCalledTimes(1);
    expect(onDelegateApproval).toHaveBeenCalledWith("approval-a");
    expect(screen.getByText("Step-Up Required")).toBeInTheDocument();
    expect(screen.getByText("Executed delegate -> delegated")).toBeInTheDocument();
  });
});
