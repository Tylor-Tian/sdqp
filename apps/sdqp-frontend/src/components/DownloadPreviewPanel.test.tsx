import { render, screen } from "@testing-library/react";
import { describe, expect, it } from "vitest";
import type { DownloadPreview } from "../api";
import type { DownloadPreviewSummary } from "../analysisEvidenceController";
import { DownloadPreviewPanel } from "./DownloadPreviewPanel";

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

describe("DownloadPreviewPanel", () => {
  it("renders the dedicated download-preview surface", () => {
    render(
      <DownloadPreviewPanel
        watermarkText="tenant-alpha / project-alpha / user-analyst"
        downloadPreview={downloadPreview}
        downloadPreviewSummary={downloadPreviewSummary}
      />
    );

    expect(screen.getByTestId("download-preview-panel")).toBeInTheDocument();
    expect(screen.getByText("Preview Metadata")).toBeInTheDocument();
    expect(screen.getByText("Preview Excerpt")).toBeInTheDocument();
    expect(screen.getByText("evidence.txt / text/plain")).toBeInTheDocument();
    expect(screen.getByText("1 lines / 16 characters")).toBeInTheDocument();
    expect(screen.getByText("full preview captured")).toBeInTheDocument();
    expect(screen.getByText("L1: download preview")).toBeInTheDocument();
    expect(screen.getByTestId("watermark-overlay-download-preview")).toHaveTextContent(
      "tenant-alpha / project-alpha / user-analyst"
    );
  });

  it("keeps the metadata card while omitting the excerpt when no preview payload is present", () => {
    render(
      <DownloadPreviewPanel
        watermarkText={null}
        downloadPreview={null}
        downloadPreviewSummary={{
          ...downloadPreviewSummary,
          lineCount: 5,
          characterCount: 42,
          previewLines: ["download preview", "line 2", "line 3", "line 4"],
          truncated: true
        }}
      />
    );

    expect(screen.getByTestId("download-preview-panel")).toBeInTheDocument();
    expect(screen.getByText("Preview Metadata")).toBeInTheDocument();
    expect(screen.getByText("5 lines / 42 characters")).toBeInTheDocument();
    expect(screen.getByText("excerpt truncated to first 4 lines")).toBeInTheDocument();
    expect(screen.queryByText("Preview Excerpt")).not.toBeInTheDocument();
    expect(screen.queryByTestId("watermark-overlay-download-preview")).not.toBeInTheDocument();
  });
});
