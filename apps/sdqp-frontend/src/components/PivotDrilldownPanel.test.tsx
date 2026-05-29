import { fireEvent, render, screen } from "@testing-library/react";
import { describe, expect, it, vi } from "vitest";
import type { PivotAnalysis, SnapshotPage } from "../api";
import type { DrilldownSummary } from "../analysisEvidenceController";
import { PivotDrilldownPanel } from "./PivotDrilldownPanel";

const pivot: PivotAnalysis = {
  snapshot_id: "snapshot-a",
  dimension: "department",
  metric: "record_count",
  buckets: [{ key: "fraud", value: 1 }],
  watermark_text: "tenant-alpha / project-alpha / user-analyst"
};

const drilldownPage: SnapshotPage = {
  snapshot_id: "snapshot-a",
  columns: ["employee_id", "department"],
  rows: [{ employee_id: "E-100", department: "fraud" }],
  next_cursor: null,
  field_policies: [
    {
      field_name: "employee_id",
      masked: false,
      render_mode: "canvas",
      watermark_strength: "low"
    },
    {
      field_name: "department",
      masked: false,
      render_mode: "canvas",
      watermark_strength: "low"
    }
  ],
  watermark_text: "tenant-alpha / project-alpha / user-analyst"
};

const drilldownSummary: DrilldownSummary = {
  snapshotId: "snapshot-a",
  dimension: "department",
  bucketKey: "fraud",
  bucketValue: 1,
  metric: "record_count",
  rowCount: 1,
  columnCount: 2,
  maskedFieldCount: 0,
  plainFieldCount: 2,
  hasMoreRows: false,
  watermarkText: "tenant-alpha / project-alpha / user-analyst",
  fieldPolicies: ["employee_id / plain / low", "department / plain / low"]
};

describe("PivotDrilldownPanel", () => {
  it("renders pivot and drilldown surfaces through the extracted analysis panel", () => {
    const onLoadDrilldown = vi.fn();

    render(
      <PivotDrilldownPanel
        isHydrating={false}
        pivot={pivot}
        drilldownPage={drilldownPage}
        drilldownSummary={drilldownSummary}
        onLoadDrilldown={onLoadDrilldown}
      />
    );

    fireEvent.click(screen.getByRole("button", { name: "Load drilldown fraud 1" }));

    expect(onLoadDrilldown).toHaveBeenCalledWith("fraud");
    expect(screen.getByTestId("pivot-drilldown-panel")).toBeInTheDocument();
    expect(screen.getByTestId("pivot-table")).toBeInTheDocument();
    expect(screen.getByTestId("drilldown-inspection-panel")).toBeInTheDocument();
    expect(screen.getByText("Pivot & Drilldown")).toBeInTheDocument();
    expect(screen.getByText("Drilldown Context")).toBeInTheDocument();
    expect(screen.getByText("Snapshot Coverage")).toBeInTheDocument();
    expect(screen.getByText("Field Policies")).toBeInTheDocument();
    expect(screen.getByText(/Row 1: employee_id=E-100 \| department=fraud/)).toBeInTheDocument();
    expect(screen.getByTestId("watermark-overlay-pivot-analysis")).toHaveTextContent(
      "tenant-alpha / project-alpha / user-analyst"
    );
    expect(screen.getByTestId("watermark-overlay-drilldown")).toHaveTextContent(
      "tenant-alpha / project-alpha / user-analyst"
    );
  });

  it("returns null when there is no pivot or drilldown state", () => {
    const { container } = render(
      <PivotDrilldownPanel
        isHydrating={false}
        pivot={null}
        drilldownPage={null}
        drilldownSummary={null}
        onLoadDrilldown={() => undefined}
      />
    );

    expect(container).toBeEmptyDOMElement();
  });
});
