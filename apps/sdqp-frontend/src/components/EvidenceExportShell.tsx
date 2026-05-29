import type {
  DownloadPreview,
  PivotAnalysis,
  SnapshotPage
} from "../api";
import type {
  DownloadAuthorizationSummary,
  DownloadPreviewSummary,
  DrilldownSummary,
  EvidenceExportSummary
} from "../analysisEvidenceController";
import { EvidenceExportComposerPanel } from "./EvidenceExportComposerPanel";
import { EvidenceExportResultsStack } from "./EvidenceExportResultsStack";
import { PivotDrilldownPanel } from "./PivotDrilldownPanel";

export type EvidenceExportShellProps = {
  isHydrating: boolean;
  hasSnapshot: boolean;
  exportTemplate: string;
  exportTemplateOptions: Array<{
    value: string;
    label: string;
  }>;
  exportBody: string;
  exportSummary: EvidenceExportSummary | null;
  downloadAuthorizationSummary: DownloadAuthorizationSummary | null;
  downloadPreview: DownloadPreview | null;
  downloadPreviewSummary: DownloadPreviewSummary | null;
  pivot: PivotAnalysis | null;
  drilldownPage: SnapshotPage | null;
  drilldownSummary: DrilldownSummary | null;
  onExportTemplateChange: (value: string) => void;
  onExportBodyChange: (value: string) => void;
  onGenerateEvidencePackage: () => void;
  onAuthorizeDownload: () => void;
  onPreviewDownload: () => void;
  onLoadDrilldown: (bucketKey: string) => void;
};

export function EvidenceExportShell({
  isHydrating,
  hasSnapshot,
  exportTemplate,
  exportTemplateOptions,
  exportBody,
  exportSummary,
  downloadAuthorizationSummary,
  downloadPreview,
  downloadPreviewSummary,
  pivot,
  drilldownPage,
  drilldownSummary,
  onExportTemplateChange,
  onExportBodyChange,
  onGenerateEvidencePackage,
  onAuthorizeDownload,
  onPreviewDownload,
  onLoadDrilldown
}: EvidenceExportShellProps) {
  return (
    <>
      <div className="analysisPanel__header">
        <h2>Evidence Export</h2>
      </div>
      <EvidenceExportComposerPanel
        isHydrating={isHydrating}
        hasSnapshot={hasSnapshot}
        exportTemplate={exportTemplate}
        exportTemplateOptions={exportTemplateOptions}
        exportBody={exportBody}
        canAuthorizeDownload={exportSummary !== null}
        canPreviewDownload={downloadAuthorizationSummary !== null}
        onExportTemplateChange={onExportTemplateChange}
        onExportBodyChange={onExportBodyChange}
        onGenerateEvidencePackage={onGenerateEvidencePackage}
        onAuthorizeDownload={onAuthorizeDownload}
        onPreviewDownload={onPreviewDownload}
      />
      <EvidenceExportResultsStack
        exportSummary={exportSummary}
        downloadAuthorizationSummary={downloadAuthorizationSummary}
        downloadPreview={downloadPreview}
        downloadPreviewSummary={downloadPreviewSummary}
      />
      <PivotDrilldownPanel
        isHydrating={isHydrating}
        pivot={pivot}
        drilldownPage={drilldownPage}
        drilldownSummary={drilldownSummary}
        onLoadDrilldown={onLoadDrilldown}
      />
    </>
  );
}
