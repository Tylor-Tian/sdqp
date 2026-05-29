import type { ComponentProps } from "react";
import { ApprovalQueuePanel } from "./ApprovalQueuePanel";
import { AnalysisWorkspaceShell, type AnalysisWorkspaceShellProps } from "./AnalysisWorkspaceShell";
import { AuthenticatedWorkspaceShell } from "./AuthenticatedWorkspaceShell";
import { DetailPagePanel } from "./DetailPagePanel";
import { PermissionsPanel } from "./PermissionsPanel";
import { ProjectControlPanel } from "./ProjectControlPanel";
import { QueryWorkbenchPanel } from "./QueryWorkbenchPanel";
import { SecurityPanel } from "./SecurityPanel";
import { UebaAuditPanel } from "./UebaAuditPanel";

export type AuthenticatedWorkspaceCompositionProps = {
  showWorkspace: boolean;
  projectControlPanelProps: ComponentProps<typeof ProjectControlPanel>;
  permissionsPanelProps: ComponentProps<typeof PermissionsPanel>;
  securityPanelProps: ComponentProps<typeof SecurityPanel>;
  approvalQueuePanelProps: ComponentProps<typeof ApprovalQueuePanel>;
  queryWorkbenchPanelProps: ComponentProps<typeof QueryWorkbenchPanel>;
  uebaAuditPanelProps: ComponentProps<typeof UebaAuditPanel>;
  detailPagePanelProps: ComponentProps<typeof DetailPagePanel>;
} & Pick<AnalysisWorkspaceShellProps, "analysisTemplatesPanelProps" | "evidenceExportPanelProps">;

export function AuthenticatedWorkspaceComposition({
  showWorkspace,
  projectControlPanelProps,
  permissionsPanelProps,
  securityPanelProps,
  approvalQueuePanelProps,
  queryWorkbenchPanelProps,
  uebaAuditPanelProps,
  detailPagePanelProps,
  analysisTemplatesPanelProps,
  evidenceExportPanelProps
}: AuthenticatedWorkspaceCompositionProps) {
  if (!showWorkspace) {
    return null;
  }

  return (
    <AuthenticatedWorkspaceShell
      projectControlPanel={<ProjectControlPanel {...projectControlPanelProps} />}
      permissionsPanel={<PermissionsPanel {...permissionsPanelProps} />}
      securityPanel={<SecurityPanel {...securityPanelProps} />}
      approvalQueuePanel={<ApprovalQueuePanel {...approvalQueuePanelProps} />}
      queryWorkbenchPanel={<QueryWorkbenchPanel {...queryWorkbenchPanelProps} />}
      uebaAuditPanel={<UebaAuditPanel {...uebaAuditPanelProps} />}
      detailPagePanel={<DetailPagePanel {...detailPagePanelProps} />}
      analysisWorkspaceShell={
        <AnalysisWorkspaceShell
          analysisTemplatesPanelProps={analysisTemplatesPanelProps}
          evidenceExportPanelProps={evidenceExportPanelProps}
        />
      }
    />
  );
}
