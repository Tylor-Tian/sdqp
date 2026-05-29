import type { ReactNode } from "react";

export type AuthenticatedWorkspaceShellProps = {
  projectControlPanel: ReactNode;
  permissionsPanel: ReactNode;
  securityPanel: ReactNode;
  approvalQueuePanel: ReactNode;
  queryWorkbenchPanel: ReactNode;
  uebaAuditPanel: ReactNode;
  detailPagePanel: ReactNode;
  analysisWorkspaceShell: ReactNode;
};

export function AuthenticatedWorkspaceShell({
  projectControlPanel,
  permissionsPanel,
  securityPanel,
  approvalQueuePanel,
  queryWorkbenchPanel,
  uebaAuditPanel,
  detailPagePanel,
  analysisWorkspaceShell
}: AuthenticatedWorkspaceShellProps) {
  return (
    <section data-testid="authenticated-workspace-shell">
      <div className="dashboardGrid">
        {projectControlPanel}
        {permissionsPanel}
      </div>

      <div className="dashboardGrid">
        {securityPanel}
        {approvalQueuePanel}
      </div>

      <div className="dashboardGrid">
        {queryWorkbenchPanel}
        {uebaAuditPanel}
      </div>

      {detailPagePanel}
      {analysisWorkspaceShell}
    </section>
  );
}
