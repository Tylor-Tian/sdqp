import { fireEvent, render, screen } from "@testing-library/react";
import { describe, expect, it, vi } from "vitest";
import type { DownloadPreview, PivotAnalysis, SnapshotPage } from "../api";
import type {
  DownloadAuthorizationSummary,
  DownloadPreviewSummary,
  DrilldownSummary,
  EvidenceExportSummary
} from "../analysisEvidenceController";
import { EvidenceExportShell } from "./EvidenceExportShell";

const snapshotPage: SnapshotPage = {
  snapshot_id: "snapshot-a",
  columns: ["employee_id", "department"],
  rows: [{ employee_id: "E-100", department: "fraud" }],
  next_cursor: null,
  field_policies: [
    {
      field_name: "employee_id",
      masked: false,
      render_mode: "canvas",
      watermark_strength: "low"
    },
    {
      field_name: "department",
      masked: false,
      render_mode: "canvas",
      watermark_strength: "low"
    }
  ],
  watermark_text: "tenant-alpha / project-alpha / user-analyst"
};

const exportSummary: EvidenceExportSummary = {
  packageId: "package-a",
  snapshotId: "snapshot-a",
  template: "china",
  fileName: "evidence.txt",
  mediaType: "text/plain",
  auditEventCount: 3,
  auditChainValid: true,
  verificationReady: true,
  manifestDigest: "digest-a",
  timestampAuthority: "mock-tsa",
  anchorNetwork: "mock-chain",
  anchorTransactionId: "tx-a",
  watermarkText: "tenant-alpha / project-alpha / user-analyst",
  completedAt: "2026-03-30T09:01:00Z"
};

const downloadAuthorizationSummary: DownloadAuthorizationSummary = {
  downloadToken: "download-a",
  fileName: "evidence.txt",
  mediaType: "text/plain",
  expiresAt: "2026-03-30T09:10:00Z"
};

const downloadPreview: DownloadPreview = {
  content: "download preview",
  contentType: "text/plain",
  fileName: "evidence.txt"
};

const downloadPreviewSummary: DownloadPreviewSummary = {
  fileName: "evidence.txt",
  contentType: "text/plain",
  lineCount: 1,
  characterCount: 16,
  previewLines: ["download preview"],
  truncated: false
};

const pivot: PivotAnalysis = {
  snapshot_id: "snapshot-a",
  dimension: "department",
  metric: "record_count",
  buckets: [{ key: "fraud", value: 1 }],
  watermark_text: "tenant-alpha / project-alpha / user-analyst"
};

const drilldownSummary: DrilldownSummary = {
  snapshotId: "snapshot-a",
  dimension: "department",
  bucketKey: "fraud",
  bucketValue: 1,
  metric: "record_count",
  rowCount: 1,
  columnCount: 2,
  maskedFieldCount: 0,
  plainFieldCount: 2,
  hasMoreRows: false,
  watermarkText: "tenant-alpha / project-alpha / user-analyst",
  fieldPolicies: ["employee_id / plain / low", "department / plain / low"]
};

describe("EvidenceExportShell", () => {
  it("renders the dedicated evidence-export shell surface and forwards nested actions", () => {
    const onExportTemplateChange = vi.fn();
    const onExportBodyChange = vi.fn();
    const onGenerateEvidencePackage = vi.fn();
    const onAuthorizeDownload = vi.fn();
    const onPreviewDownload = vi.fn();
    const onLoadDrilldown = vi.fn();

    render(
      <EvidenceExportShell
        isHydrating={false}
        hasSnapshot
        exportTemplate="china"
        exportTemplateOptions={[
          { value: "china", label: "China Judicial" },
          { value: "eu", label: "EU Regulatory" }
        ]}
        exportBody="stage12 export"
        exportSummary={exportSummary}
        downloadAuthorizationSummary={downloadAuthorizationSummary}
        downloadPreview={downloadPreview}
        downloadPreviewSummary={downloadPreviewSummary}
        pivot={pivot}
        drilldownPage={snapshotPage}
        drilldownSummary={drilldownSummary}
        onExportTemplateChange={onExportTemplateChange}
        onExportBodyChange={onExportBodyChange}
        onGenerateEvidencePackage={onGenerateEvidencePackage}
        onAuthorizeDownload={onAuthorizeDownload}
        onPreviewDownload={onPreviewDownload}
        onLoadDrilldown={onLoadDrilldown}
      />
    );

    fireEvent.change(screen.getByLabelText("Export Template"), {
      target: { value: "eu" }
    });
    fireEvent.change(screen.getByLabelText("Export Body"), {
      target: { value: "cross-border export" }
    });
    fireEvent.click(screen.getByRole("button", { name: "Generate Evidence Package" }));
    fireEvent.click(screen.getByRole("button", { name: "Authorize Download" }));
    fireEvent.click(screen.getByRole("button", { name: "Preview Download" }));
    fireEvent.click(screen.getByRole("button", { name: "Load drilldown fraud 1" }));

    expect(screen.getByText("Evidence Export")).toBeInTheDocument();
    expect(screen.getByTestId("evidence-export-composer-panel")).toBeInTheDocument();
    expect(screen.getByTestId("evidence-export-results-stack")).toBeInTheDocument();
    expect(screen.getByTestId("pivot-drilldown-panel")).toBeInTheDocument();
    expect(onExportTemplateChange).toHaveBeenCalledWith("eu");
    expect(onExportBodyChange).toHaveBeenCalledWith("cross-border export");
    expect(onGenerateEvidencePackage).toHaveBeenCalledTimes(1);
    expect(onAuthorizeDownload).toHaveBeenCalledTimes(1);
    expect(onPreviewDownload).toHaveBeenCalledTimes(1);
    expect(onLoadDrilldown).toHaveBeenCalledWith("fraud");
  });
});
