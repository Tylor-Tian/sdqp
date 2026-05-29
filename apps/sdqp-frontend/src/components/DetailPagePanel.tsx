import type { FieldDisplayPolicy, SnapshotPage } from "../api";
import { DetailView } from "./DetailView";
import { WatermarkFrame } from "./WatermarkOverlay";

function describePolicies(policies: FieldDisplayPolicy[]) {
  return policies.map((policy) => {
    const status = policy.masked ? "masked" : "plain";
    return `${policy.field_name} / ${status} / ${policy.watermark_strength}`;
  });
}

function summarizeRow(snapshotPage: SnapshotPage, rowIndex: number) {
  const row = snapshotPage.rows[rowIndex];
  if (!row) {
    return null;
  }

  const summary = snapshotPage.columns
    .map((column) => `${column}=${row[column] ?? "-"}`)
    .join(" | ");

  return `Row ${rowIndex + 1}: ${summary}`;
}

function InspectionCard({
  title,
  lines
}: {
  title: string;
  lines: string[];
}) {
  return (
    <article className="listCard">
      <strong>{title}</strong>
      {lines.map((line, index) => (
        <p key={`${title}-${index}-${line}`}>{line}</p>
      ))}
    </article>
  );
}

export function DetailPagePanel({ snapshotPage }: { snapshotPage: SnapshotPage | null }) {
  if (!snapshotPage) {
    return null;
  }

  const policyDescriptions = describePolicies(snapshotPage.field_policies);
  const maskedFieldCount = snapshotPage.field_policies.filter((policy) => policy.masked).length;
  const plainFieldCount = snapshotPage.field_policies.length - maskedFieldCount;
  const rowSummaries = [0, 1]
    .map((rowIndex) => summarizeRow(snapshotPage, rowIndex))
    .filter((summary): summary is string => Boolean(summary));

  return (
    <section className="tablePanel">
      <div className="tablePanel__header">
        <h2>Detail Page</h2>
      </div>
      <WatermarkFrame
        text={snapshotPage.watermark_text}
        tileCount={16}
        testId="watermark-overlay-detail-page"
      >
        <div className="sessionSummary">
          <article className="metricPanel">
            <p className="metricPanel__label">Snapshot</p>
            <p className="metricPanel__value">{snapshotPage.snapshot_id}</p>
          </article>
          <article className="metricPanel">
            <p className="metricPanel__label">Rows</p>
            <p className="metricPanel__value">{snapshotPage.rows.length}</p>
          </article>
          <article className="metricPanel">
            <p className="metricPanel__label">Columns</p>
            <p className="metricPanel__value">{snapshotPage.columns.length}</p>
          </article>
        </div>
        <div className="stackList">
          <InspectionCard
            title="Snapshot Metadata"
            lines={[
              `${snapshotPage.rows.length} rows / ${snapshotPage.columns.length} columns`,
              `${snapshotPage.field_policies.length} field policies applied`
            ]}
          />
          <InspectionCard
            title="Cursor Status"
            lines={[
              snapshotPage.next_cursor === null
                ? "cursor exhausted on current detail page"
                : `next cursor ${snapshotPage.next_cursor} available`,
              rowSummaries.length > 0
                ? `${rowSummaries.length} row summaries rendered`
                : "no rows available"
            ]}
          />
          <InspectionCard
            title="Policy Coverage"
            lines={[
              `${plainFieldCount} plain / ${maskedFieldCount} masked`,
              maskedFieldCount > 0 ? "masked fields remain canvas-protected" : "all visible fields remain plain"
            ]}
          />
          <InspectionCard title="Field Policies" lines={policyDescriptions} />
          {rowSummaries.length > 0 ? <InspectionCard title="Sample Rows" lines={rowSummaries} /> : null}
        </div>
        <DetailView snapshotPage={snapshotPage} />
      </WatermarkFrame>
    </section>
  );
}
