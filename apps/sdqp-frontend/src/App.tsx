import "./App.css";
import { createBrowserClient, type FrontendClient } from "./api";
import { ConsoleContentComposition } from "./components/ConsoleContentComposition";
import { WorkspaceRootShell } from "./components/WorkspaceRootShell";
import { useConsoleAppModel } from "./useConsoleAppModel";

export { buildFieldCatalog, buildPersonaCatalog } from "./useConsoleAppModel";

export function App({
  client = createBrowserClient(),
  pollIntervalMs = 450
}: {
  client?: FrontendClient;
  pollIntervalMs?: number;
}) {
  const appModel = useConsoleAppModel({
    client,
    pollIntervalMs
  });

  return (
    <WorkspaceRootShell>
      <ConsoleContentComposition
        heroPanelProps={appModel.heroPanelProps}
        securityNoticeBannerProps={appModel.securityNoticeBannerProps}
        mfaChallengePanelProps={appModel.mfaChallengePanelProps}
        showWorkspace={appModel.showWorkspace}
        projectControlPanelProps={appModel.projectControlPanelProps}
        permissionsPanelProps={appModel.permissionsPanelProps}
        securityPanelProps={appModel.securityPanelProps}
        approvalQueuePanelProps={appModel.approvalQueuePanelProps}
        queryWorkbenchPanelProps={appModel.queryWorkbenchPanelProps}
        uebaAuditPanelProps={appModel.uebaAuditPanelProps}
        detailPagePanelProps={appModel.detailPagePanelProps}
        analysisTemplatesPanelProps={appModel.analysisTemplatesPanelProps}
        evidenceExportPanelProps={appModel.evidenceExportPanelProps}
      />
    </WorkspaceRootShell>
  );
}
