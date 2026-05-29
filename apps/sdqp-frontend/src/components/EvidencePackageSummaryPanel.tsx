import type { EvidenceExportSummary } from "../analysisEvidenceController";
import { WatermarkFrame } from "./WatermarkOverlay";

export function EvidencePackageSummaryPanel({
  exportSummary
}: {
  exportSummary: EvidenceExportSummary;
}) {
  return (
    <div data-testid="evidence-package-summary-panel">
      <WatermarkFrame
        text={exportSummary.watermarkText}
        tileCount={12}
        testId="watermark-overlay-evidence-export"
      >
        <div className="sessionSummary">
          <article className="metricPanel">
            <p className="metricPanel__label">Package</p>
            <p className="metricPanel__value">{exportSummary.packageId}</p>
          </article>
          <article className="metricPanel">
            <p className="metricPanel__label">Audit Events</p>
            <p className="metricPanel__value">{exportSummary.auditEventCount}</p>
          </article>
          <article className="metricPanel">
            <p className="metricPanel__label">Verification</p>
            <p className="metricPanel__value">
              {exportSummary.verificationReady ? "Ready" : "Pending"}
            </p>
          </article>
        </div>
        <div className="stackList">
          <article className="listCard">
            <strong>Export Metadata</strong>
            <p>{`${exportSummary.fileName} / ${exportSummary.mediaType}`}</p>
            <p>{`template ${exportSummary.template} / snapshot ${exportSummary.snapshotId}`}</p>
          </article>
          <article className="listCard">
            <strong>Manifest & Audit</strong>
            <p>{exportSummary.manifestDigest}</p>
            <p>
              {`${exportSummary.auditEventCount} audit events / chain ${
                exportSummary.auditChainValid ? "valid" : "invalid"
              }`}
            </p>
          </article>
          <article className="listCard">
            <strong>Trust Anchors</strong>
            <p>{`${exportSummary.timestampAuthority} / ${exportSummary.anchorNetwork}`}</p>
            <p>{exportSummary.anchorTransactionId}</p>
          </article>
        </div>
        {exportSummary.completedAt ? (
          <p className="inlineNotice">{`completed ${exportSummary.completedAt}`}</p>
        ) : null}
      </WatermarkFrame>
    </div>
  );
}
