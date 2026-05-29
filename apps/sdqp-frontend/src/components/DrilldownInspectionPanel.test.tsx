import { render, screen } from "@testing-library/react";
import { describe, expect, it } from "vitest";
import type { SnapshotPage } from "../api";
import type { DrilldownSummary } from "../analysisEvidenceController";
import { DrilldownInspectionPanel } from "./DrilldownInspectionPanel";

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

describe("DrilldownInspectionPanel", () => {
  it("renders the dedicated drilldown inspection surface with sample rows", () => {
    render(
      <DrilldownInspectionPanel
        drilldownPage={drilldownPage}
        drilldownSummary={drilldownSummary}
      />
    );

    expect(screen.getByTestId("drilldown-inspection-panel")).toBeInTheDocument();
    expect(screen.getByText("Drilldown Context")).toBeInTheDocument();
    expect(screen.getByText("Snapshot Coverage")).toBeInTheDocument();
    expect(screen.getByText("Field Policies")).toBeInTheDocument();
    expect(screen.getByText("Sample Rows")).toBeInTheDocument();
    expect(screen.getByText(/Row 1: employee_id=E-100 \| department=fraud/)).toBeInTheDocument();
    expect(screen.getByTestId("watermark-overlay-drilldown")).toHaveTextContent(
      "tenant-alpha / project-alpha / user-analyst"
    );
  });

  it("keeps the drilldown summary visible without sample rows when the page is absent", () => {
    render(<DrilldownInspectionPanel drilldownPage={null} drilldownSummary={drilldownSummary} />);

    expect(screen.getByTestId("drilldown-inspection-panel")).toBeInTheDocument();
    expect(screen.getByText("Drilldown Context")).toBeInTheDocument();
    expect(screen.queryByText("Sample Rows")).not.toBeInTheDocument();
  });
});
