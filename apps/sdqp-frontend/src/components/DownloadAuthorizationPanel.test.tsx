import { render, screen } from "@testing-library/react";
import { describe, expect, it } from "vitest";
import type { DownloadAuthorizationSummary } from "../analysisEvidenceController";
import { DownloadAuthorizationPanel } from "./DownloadAuthorizationPanel";

const downloadAuthorizationSummary: DownloadAuthorizationSummary = {
  downloadToken: "download-a",
  fileName: "evidence.txt",
  mediaType: "text/plain",
  expiresAt: "2026-03-30T09:10:00Z"
};

describe("DownloadAuthorizationPanel", () => {
  it("renders the dedicated download-authorization surface", () => {
    render(
      <DownloadAuthorizationPanel
        watermarkText="tenant-alpha / project-alpha / user-analyst"
        downloadAuthorizationSummary={downloadAuthorizationSummary}
      />
    );

    expect(screen.getByTestId("download-authorization-panel")).toBeInTheDocument();
    expect(screen.getByText("Download Authorization")).toBeInTheDocument();
    expect(screen.getByText("token download-a")).toBeInTheDocument();
    expect(screen.getByText("evidence.txt / text/plain")).toBeInTheDocument();
    expect(screen.getByText("expires 2026-03-30T09:10:00Z")).toBeInTheDocument();
    expect(screen.getByTestId("watermark-overlay-download-authorization")).toHaveTextContent(
      "tenant-alpha / project-alpha / user-analyst"
    );
  });

  it("omits the watermark overlay when the watermark text is absent", () => {
    render(
      <DownloadAuthorizationPanel
        watermarkText={null}
        downloadAuthorizationSummary={downloadAuthorizationSummary}
      />
    );

    expect(screen.getByTestId("download-authorization-panel")).toBeInTheDocument();
    expect(screen.queryByTestId("watermark-overlay-download-authorization")).not.toBeInTheDocument();
  });
});
