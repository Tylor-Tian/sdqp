import type { PivotAnalysis, SnapshotPage } from "../api";
import type { DrilldownSummary } from "../analysisEvidenceController";
import { DrilldownInspectionPanel } from "./DrilldownInspectionPanel";
import { PivotTable } from "./PivotTable";

export function PivotDrilldownPanel({
  isHydrating,
  pivot,
  drilldownPage,
  drilldownSummary,
  onLoadDrilldown
}: {
  isHydrating: boolean;
  pivot: PivotAnalysis | null;
  drilldownPage: SnapshotPage | null;
  drilldownSummary: DrilldownSummary | null;
  onLoadDrilldown: (bucketKey: string) => void;
}) {
  if (!pivot && !drilldownSummary) {
    return null;
  }

  return (
    <section className="surfacePanel surfacePanel--subsection" data-testid="pivot-drilldown-panel">
      <h3 className="surfacePanel__title">Pivot & Drilldown</h3>
      {pivot ? (
        <PivotTable isHydrating={isHydrating} pivot={pivot} onLoadDrilldown={onLoadDrilldown} />
      ) : null}
      {drilldownSummary ? (
        <DrilldownInspectionPanel
          drilldownPage={drilldownPage}
          drilldownSummary={drilldownSummary}
        />
      ) : null}
    </section>
  );
}
