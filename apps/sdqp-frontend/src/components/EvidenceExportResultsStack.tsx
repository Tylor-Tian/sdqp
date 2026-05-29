import type { DownloadPreview } from "../api";
import type {
  DownloadAuthorizationSummary,
  DownloadPreviewSummary,
  EvidenceExportSummary
} from "../analysisEvidenceController";
import { DownloadAuthorizationPanel } from "./DownloadAuthorizationPanel";
import { DownloadPreviewPanel } from "./DownloadPreviewPanel";
import { EvidencePackageSummaryPanel } from "./EvidencePackageSummaryPanel";

export function EvidenceExportResultsStack({
  exportSummary,
  downloadAuthorizationSummary,
  downloadPreview,
  downloadPreviewSummary
}: {
  exportSummary: EvidenceExportSummary | null;
  downloadAuthorizationSummary: DownloadAuthorizationSummary | null;
  downloadPreview: DownloadPreview | null;
  downloadPreviewSummary: DownloadPreviewSummary | null;
}) {
  if (!exportSummary && !downloadAuthorizationSummary && !downloadPreviewSummary) {
    return null;
  }

  return (
    <div data-testid="evidence-export-results-stack">
      {exportSummary ? <EvidencePackageSummaryPanel exportSummary={exportSummary} /> : null}
      {downloadAuthorizationSummary ? (
        <DownloadAuthorizationPanel
          watermarkText={exportSummary?.watermarkText}
          downloadAuthorizationSummary={downloadAuthorizationSummary}
        />
      ) : null}
      {downloadPreviewSummary ? (
        <DownloadPreviewPanel
          watermarkText={exportSummary?.watermarkText}
          downloadPreview={downloadPreview}
          downloadPreviewSummary={downloadPreviewSummary}
        />
      ) : null}
    </div>
  );
}
