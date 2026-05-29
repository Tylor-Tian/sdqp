import type { DownloadAuthorizationSummary } from "../analysisEvidenceController";
import { WatermarkFrame } from "./WatermarkOverlay";

export function DownloadAuthorizationPanel({
  watermarkText,
  downloadAuthorizationSummary
}: {
  watermarkText: string | null | undefined;
  downloadAuthorizationSummary: DownloadAuthorizationSummary;
}) {
  return (
    <div data-testid="download-authorization-panel">
      <WatermarkFrame
        text={watermarkText}
        tileCount={10}
        testId="watermark-overlay-download-authorization"
      >
        <div className="stackList">
          <article className="listCard">
            <strong>Download Authorization</strong>
            <p>{`token ${downloadAuthorizationSummary.downloadToken}`}</p>
            <p>{`${downloadAuthorizationSummary.fileName} / ${downloadAuthorizationSummary.mediaType}`}</p>
            <p>{`expires ${downloadAuthorizationSummary.expiresAt}`}</p>
          </article>
        </div>
      </WatermarkFrame>
    </div>
  );
}
