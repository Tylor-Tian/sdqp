import type { DownloadPreview } from "../api";
import type { DownloadPreviewSummary } from "../analysisEvidenceController";
import { WatermarkFrame } from "./WatermarkOverlay";

function formatPreviewLine(line: string, index: number) {
  return `L${index + 1}: ${line || "(blank line)"}`;
}

export function DownloadPreviewPanel({
  watermarkText,
  downloadPreview,
  downloadPreviewSummary
}: {
  watermarkText: string | null | undefined;
  downloadPreview: DownloadPreview | null;
  downloadPreviewSummary: DownloadPreviewSummary;
}) {
  return (
    <div data-testid="download-preview-panel">
      <WatermarkFrame
        text={watermarkText}
        tileCount={10}
        testId="watermark-overlay-download-preview"
      >
        <div className="stackList">
          <article className="listCard">
            <strong>Preview Metadata</strong>
            <p>{`${downloadPreviewSummary.fileName} / ${downloadPreviewSummary.contentType}`}</p>
            <p>{`${downloadPreviewSummary.lineCount} lines / ${downloadPreviewSummary.characterCount} characters`}</p>
            <p>
              {downloadPreviewSummary.truncated
                ? "excerpt truncated to first 4 lines"
                : "full preview captured"}
            </p>
          </article>
          {downloadPreview ? (
            <article className="listCard">
              <strong>Preview Excerpt</strong>
              {downloadPreviewSummary.previewLines.map((line, index) => (
                <p key={`preview-${index}-${line}`}>{formatPreviewLine(line, index)}</p>
              ))}
            </article>
          ) : null}
        </div>
      </WatermarkFrame>
    </div>
  );
}
