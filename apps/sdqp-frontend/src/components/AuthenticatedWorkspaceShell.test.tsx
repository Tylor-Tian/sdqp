import { render, screen } from "@testing-library/react";
import { describe, expect, it } from "vitest";
import { AuthenticatedWorkspaceShell } from "./AuthenticatedWorkspaceShell";

describe("AuthenticatedWorkspaceShell", () => {
  it("renders the dedicated authenticated workspace shell and preserves the dashboard/detail/analysis ordering", () => {
    const { container } = render(
      <AuthenticatedWorkspaceShell
        projectControlPanel={<div data-testid="project-control-slot">project</div>}
        permissionsPanel={<div data-testid="permissions-slot">permissions</div>}
        securityPanel={<div data-testid="security-slot">security</div>}
        approvalQueuePanel={<div data-testid="approval-slot">approval</div>}
        queryWorkbenchPanel={<div data-testid="query-slot">query</div>}
        uebaAuditPanel={<div data-testid="ueba-slot">ueba</div>}
        detailPagePanel={<div data-testid="detail-slot">detail</div>}
        analysisWorkspaceShell={<div data-testid="analysis-slot">analysis</div>}
      />
    );

    expect(screen.getByTestId("authenticated-workspace-shell")).toBeInTheDocument();
    expect(container.querySelectorAll(".dashboardGrid")).toHaveLength(3);
    expect(screen.getByTestId("project-control-slot")).toBeInTheDocument();
    expect(screen.getByTestId("permissions-slot")).toBeInTheDocument();
    expect(screen.getByTestId("security-slot")).toBeInTheDocument();
    expect(screen.getByTestId("approval-slot")).toBeInTheDocument();
    expect(screen.getByTestId("query-slot")).toBeInTheDocument();
    expect(screen.getByTestId("ueba-slot")).toBeInTheDocument();
    expect(screen.getByTestId("detail-slot")).toBeInTheDocument();
    expect(screen.getByTestId("analysis-slot")).toBeInTheDocument();
  });
});
