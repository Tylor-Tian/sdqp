import { fireEvent, render, screen } from "@testing-library/react";
import { describe, expect, it, vi } from "vitest";
import type { PivotAnalysis } from "../api";
import { PivotTable } from "./PivotTable";

const pivot: PivotAnalysis = {
  snapshot_id: "snapshot-a",
  dimension: "department",
  metric: "record_count",
  buckets: [
    { key: "fraud", value: 1 },
    { key: "ops", value: 2 }
  ],
  watermark_text: "tenant-alpha / project-alpha / user-analyst"
};

describe("PivotTable", () => {
  it("renders the dedicated pivot-table surface and forwards drilldown actions", () => {
    const onLoadDrilldown = vi.fn();

    render(<PivotTable isHydrating={false} pivot={pivot} onLoadDrilldown={onLoadDrilldown} />);

    fireEvent.click(screen.getByRole("button", { name: "Load drilldown fraud 1" }));

    expect(screen.getByTestId("pivot-table")).toBeInTheDocument();
    expect(screen.getByText("fraud")).toBeInTheDocument();
    expect(screen.getByText("ops")).toBeInTheDocument();
    expect(onLoadDrilldown).toHaveBeenCalledWith("fraud");
    expect(screen.getByTestId("watermark-overlay-pivot-analysis")).toHaveTextContent(
      "tenant-alpha / project-alpha / user-analyst"
    );
  });

  it("disables pivot bucket actions while hydrating", () => {
    render(<PivotTable isHydrating pivot={pivot} onLoadDrilldown={() => undefined} />);

    expect(screen.getByRole("button", { name: "Load drilldown fraud 1" })).toBeDisabled();
    expect(screen.getByRole("button", { name: "Load drilldown ops 2" })).toBeDisabled();
  });
});
