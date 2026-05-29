import { render, screen } from "@testing-library/react";
import { describe, expect, it } from "vitest";
import type { EvidenceExportSummary } from "../analysisEvidenceController";
import { EvidencePackageSummaryPanel } from "./EvidencePackageSummaryPanel";

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

describe("EvidencePackageSummaryPanel", () => {
  it("renders the dedicated evidence-package summary surface", () => {
    render(<EvidencePackageSummaryPanel exportSummary={exportSummary} />);

    expect(screen.getByTestId("evidence-package-summary-panel")).toBeInTheDocument();
    expect(screen.getByText("package-a")).toBeInTheDocument();
    expect(screen.getByText("Export Metadata")).toBeInTheDocument();
    expect(screen.getByText("Manifest & Audit")).toBeInTheDocument();
    expect(screen.getByText("Trust Anchors")).toBeInTheDocument();
    expect(screen.getByText("completed 2026-03-30T09:01:00Z")).toBeInTheDocument();
    expect(screen.getByTestId("watermark-overlay-evidence-export")).toHaveTextContent(
      "tenant-alpha / project-alpha / user-analyst"
    );
  });

  it("omits the completion notice when the summary is still pending", () => {
    render(
      <EvidencePackageSummaryPanel
        exportSummary={{ ...exportSummary, verificationReady: false, completedAt: null }}
      />
    );

    expect(screen.getByText("Pending")).toBeInTheDocument();
    expect(screen.queryByText(/completed /)).not.toBeInTheDocument();
  });
});
