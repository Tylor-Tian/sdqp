import type { ComponentProps } from "react";
import { AnalysisTemplatesPanel } from "./AnalysisTemplatesPanel";
import { EvidenceExportPanel } from "./EvidenceExportPanel";

export type AnalysisWorkspaceShellProps = {
  analysisTemplatesPanelProps: ComponentProps<typeof AnalysisTemplatesPanel>;
  evidenceExportPanelProps: ComponentProps<typeof EvidenceExportPanel>;
};

export function AnalysisWorkspaceShell({
  analysisTemplatesPanelProps,
  evidenceExportPanelProps
}: AnalysisWorkspaceShellProps) {
  return (
    <section className="analysisPanel" data-testid="analysis-workspace-shell">
      <AnalysisTemplatesPanel {...analysisTemplatesPanelProps} />
      <EvidenceExportPanel {...evidenceExportPanelProps} />
    </section>
  );
}
