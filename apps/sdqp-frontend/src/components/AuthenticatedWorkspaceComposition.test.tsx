import { render, screen } from "@testing-library/react";
import type { ComponentProps } from "react";
import { describe, expect, it, vi } from "vitest";
import type { AnalysisWorkspaceShellProps } from "./AnalysisWorkspaceShell";
import { AuthenticatedWorkspaceComposition } from "./AuthenticatedWorkspaceComposition";
import type { ApprovalQueuePanel } from "./ApprovalQueuePanel";
import type { DetailPagePanel } from "./DetailPagePanel";
import type { PermissionsPanel } from "./PermissionsPanel";
import type { ProjectControlPanel } from "./ProjectControlPanel";
import type { QueryWorkbenchPanel } from "./QueryWorkbenchPanel";
import type { SecurityPanel } from "./SecurityPanel";
import type { UebaAuditPanel } from "./UebaAuditPanel";

vi.mock("./ProjectControlPanel", () => ({
  ProjectControlPanel: () => <div data-testid="project-control-panel">project</div>
}));

vi.mock("./PermissionsPanel", () => ({
  PermissionsPanel: () => <div data-testid="permissions-panel">permissions</div>
}));

vi.mock("./SecurityPanel", () => ({
  SecurityPanel: () => <div data-testid="security-panel">security</div>
}));

vi.mock("./ApprovalQueuePanel", () => ({
  ApprovalQueuePanel: () => <div data-testid="approval-queue-panel">approval</div>
}));

vi.mock("./QueryWorkbenchPanel", () => ({
  QueryWorkbenchPanel: () => <div data-testid="query-workbench-panel">query</div>
}));

vi.mock("./UebaAuditPanel", () => ({
  UebaAuditPanel: () => <div data-testid="ueba-audit-panel">ueba</div>
}));

vi.mock("./DetailPagePanel", () => ({
  DetailPagePanel: () => <div data-testid="detail-page-panel">detail</div>
}));

vi.mock("./AnalysisWorkspaceShell", () => ({
  AnalysisWorkspaceShell: () => <div data-testid="analysis-workspace-shell">analysis</div>
}));

function buildProps() {
  return {
    showWorkspace: true,
    projectControlPanelProps: {} as ComponentProps<typeof ProjectControlPanel>,
    permissionsPanelProps: {} as ComponentProps<typeof PermissionsPanel>,
    securityPanelProps: {} as ComponentProps<typeof SecurityPanel>,
    approvalQueuePanelProps: {} as ComponentProps<typeof ApprovalQueuePanel>,
    queryWorkbenchPanelProps: {} as ComponentProps<typeof QueryWorkbenchPanel>,
    uebaAuditPanelProps: {} as ComponentProps<typeof UebaAuditPanel>,
    detailPagePanelProps: {} as ComponentProps<typeof DetailPagePanel>,
    analysisTemplatesPanelProps: {} as AnalysisWorkspaceShellProps["analysisTemplatesPanelProps"],
    evidenceExportPanelProps: {} as AnalysisWorkspaceShellProps["evidenceExportPanelProps"]
  };
}

describe("AuthenticatedWorkspaceComposition", () => {
  it("renders the dedicated authenticated-workspace composition through the existing shell surfaces", () => {
    render(<AuthenticatedWorkspaceComposition {...buildProps()} />);

    expect(screen.getByTestId("authenticated-workspace-shell")).toBeInTheDocument();
    expect(screen.getByTestId("project-control-panel")).toBeInTheDocument();
    expect(screen.getByTestId("permissions-panel")).toBeInTheDocument();
    expect(screen.getByTestId("security-panel")).toBeInTheDocument();
    expect(screen.getByTestId("approval-queue-panel")).toBeInTheDocument();
    expect(screen.getByTestId("query-workbench-panel")).toBeInTheDocument();
    expect(screen.getByTestId("ueba-audit-panel")).toBeInTheDocument();
    expect(screen.getByTestId("detail-page-panel")).toBeInTheDocument();
    expect(screen.getByTestId("analysis-workspace-shell")).toBeInTheDocument();
  });

  it("omits the authenticated workspace when the console is not yet hydrated", () => {
    render(<AuthenticatedWorkspaceComposition {...buildProps()} showWorkspace={false} />);

    expect(screen.queryByTestId("authenticated-workspace-shell")).not.toBeInTheDocument();
    expect(screen.queryByTestId("analysis-workspace-shell")).not.toBeInTheDocument();
  });
});
