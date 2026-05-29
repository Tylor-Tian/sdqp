import { render, screen } from "@testing-library/react";
import { describe, expect, it } from "vitest";
import type { DownloadPreview } from "../api";
import type {
  DownloadAuthorizationSummary,
  DownloadPreviewSummary,
  EvidenceExportSummary
} from "../analysisEvidenceController";
import { EvidenceExportResultsStack } from "./EvidenceExportResultsStack";

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

describe("EvidenceExportResultsStack", () => {
  it("renders the dedicated evidence-export results stack surface", () => {
    render(
      <EvidenceExportResultsStack
        exportSummary={exportSummary}
        downloadAuthorizationSummary={downloadAuthorizationSummary}
        downloadPreview={downloadPreview}
        downloadPreviewSummary={downloadPreviewSummary}
      />
    );

    expect(screen.getByTestId("evidence-export-results-stack")).toBeInTheDocument();
    expect(screen.getByTestId("evidence-package-summary-panel")).toBeInTheDocument();
    expect(screen.getByTestId("download-authorization-panel")).toBeInTheDocument();
    expect(screen.getByTestId("download-preview-panel")).toBeInTheDocument();
    expect(screen.getByText("package-a")).toBeInTheDocument();
    expect(screen.getByText(/token download-a/)).toBeInTheDocument();
    expect(screen.getByText("L1: download preview")).toBeInTheDocument();
  });

  it("returns nothing when no export results are available", () => {
    const { container } = render(
      <EvidenceExportResultsStack
        exportSummary={null}
        downloadAuthorizationSummary={null}
        downloadPreview={null}
        downloadPreviewSummary={null}
      />
    );

    expect(screen.queryByTestId("evidence-export-results-stack")).not.toBeInTheDocument();
    expect(container).toBeEmptyDOMElement();
  });
});
