import type { PivotAnalysis } from "../api";
import { WatermarkFrame } from "./WatermarkOverlay";

export function PivotTable({
  isHydrating,
  pivot,
  onLoadDrilldown
}: {
  isHydrating: boolean;
  pivot: PivotAnalysis;
  onLoadDrilldown: (bucketKey: string) => void;
}) {
  return (
    <div data-testid="pivot-table">
      <WatermarkFrame
        text={pivot.watermark_text}
        tileCount={10}
        testId="watermark-overlay-pivot-analysis"
      >
        <div className="pivotGrid">
          {pivot.buckets.map((bucket) => (
            <button
              className="pivotBucket"
              type="button"
              disabled={isHydrating}
              key={bucket.key}
              aria-label={`Load drilldown ${bucket.key} ${bucket.value}`}
              onClick={() => onLoadDrilldown(bucket.key)}
            >
              <div className="pivotBucket__meta">
                <span>{bucket.key}</span>
                <span>{bucket.value}</span>
              </div>
              <div className="pivotBucket__bar">
                <span style={{ width: "100%" }} />
              </div>
            </button>
          ))}
        </div>
      </WatermarkFrame>
    </div>
  );
}
