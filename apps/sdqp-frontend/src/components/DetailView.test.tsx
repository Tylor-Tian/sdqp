import { render, screen } from "@testing-library/react";
import { describe, expect, it } from "vitest";
import type { SnapshotPage } from "../api";
import { DetailView } from "./DetailView";

const snapshotPage: SnapshotPage = {
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
      masked: true,
      render_mode: "canvas",
      watermark_strength: "dense"
    }
  ],
  watermark_text: "tenant-alpha / project-alpha / user-analyst"
};

describe("DetailView", () => {
  it("renders the canvas-backed detail grid through the extracted detail-view surface", () => {
    render(<DetailView snapshotPage={snapshotPage} />);

    expect(screen.getByTestId("detail-view")).toBeInTheDocument();
    expect(screen.getByRole("columnheader", { name: "employee_id" })).toBeInTheDocument();
    expect(screen.getByRole("columnheader", { name: "department" })).toBeInTheDocument();
    expect(screen.getByLabelText("employee_id canvas cell")).toBeInTheDocument();
    expect(screen.getByLabelText("department canvas cell")).toBeInTheDocument();
  });

  it("renders fallback cells when a row omits a column value", () => {
    render(
      <DetailView
        snapshotPage={{
          ...snapshotPage,
          rows: [{ employee_id: "E-200" }]
        }}
      />
    );

    expect(screen.getByLabelText("employee_id canvas cell")).toBeInTheDocument();
    expect(screen.getByLabelText("department canvas cell")).toBeInTheDocument();
  });
});
