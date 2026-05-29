import type { ReactNode } from "react";
import type { SnapshotPage } from "../api";
import type { DrilldownSummary } from "../analysisEvidenceController";
import { WatermarkFrame } from "./WatermarkOverlay";

function InspectionCard({
  title,
  lines,
  children
}: {
  title: string;
  lines?: string[];
  children?: ReactNode;
}) {
  return (
    <article className="listCard">
      <strong>{title}</strong>
      {lines?.map((line, index) => (
        <p key={`${title}-${index}-${line}`}>{line}</p>
      ))}
      {children}
    </article>
  );
}

function formatDrilldownRow(snapshotPage: SnapshotPage, rowIndex: number) {
  const row = snapshotPage.rows[rowIndex];
  if (!row) {
    return null;
  }

  const cells = snapshotPage.columns.map((column) => `${column}=${row[column] ?? "-"}`).join(" | ");
  return `Row ${rowIndex + 1}: ${cells}`;
}

export function DrilldownInspectionPanel({
  drilldownPage,
  drilldownSummary
}: {
  drilldownPage: SnapshotPage | null;
  drilldownSummary: DrilldownSummary;
}) {
  return (
    <div data-testid="drilldown-inspection-panel">
      <WatermarkFrame
        text={drilldownSummary.watermarkText}
        tileCount={10}
        testId="watermark-overlay-drilldown"
      >
        <div className="stackList">
          <InspectionCard
            title="Drilldown Context"
            lines={[
              `${drilldownSummary.dimension} = ${drilldownSummary.bucketKey}`,
              drilldownSummary.bucketValue === null
                ? `${drilldownSummary.metric} bucket loaded`
                : `${drilldownSummary.metric} = ${drilldownSummary.bucketValue}`,
              `snapshot ${drilldownSummary.snapshotId}`
            ]}
          />
          <InspectionCard
            title="Snapshot Coverage"
            lines={[
              `${drilldownSummary.rowCount} rows / ${drilldownSummary.columnCount} columns`,
              `${drilldownSummary.plainFieldCount} plain / ${drilldownSummary.maskedFieldCount} masked`,
              drilldownSummary.hasMoreRows ? "additional rows available via cursor" : "cursor exhausted"
            ]}
          />
          <InspectionCard title="Field Policies" lines={drilldownSummary.fieldPolicies} />
          {drilldownPage ? (
            <InspectionCard
              title="Sample Rows"
              lines={[0, 1]
                .map((rowIndex) => formatDrilldownRow(drilldownPage, rowIndex))
                .filter((row): row is string => Boolean(row))}
            />
          ) : null}
        </div>
      </WatermarkFrame>
    </div>
  );
}
