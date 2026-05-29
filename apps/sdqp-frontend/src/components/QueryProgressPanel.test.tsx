import { render, screen } from "@testing-library/react";
import { describe, expect, it } from "vitest";
import type { QueryTaskStatus } from "../api";
import { QueryProgressPanel } from "./QueryProgressPanel";

describe("QueryProgressPanel", () => {
  it("renders running task progress through the extracted query-progress surface", () => {
    const task: QueryTaskStatus = {
      task_id: "task-a",
      state: "running",
      snapshot_id: null,
      cache_hit: false,
      error: null
    };
    const { container } = render(<QueryProgressPanel task={task} />);

    expect(screen.getByTestId("query-progress-panel")).toBeInTheDocument();
    expect(screen.getByText("Query Progress")).toBeInTheDocument();
    expect(screen.getByText("running")).toBeInTheDocument();
    expect(screen.getByText("task-a")).toBeInTheDocument();
    expect(screen.getByText("result pending")).toBeInTheDocument();
    expect(container.querySelector(".statusMeter__fill")).toHaveStyle({
      transform: "scaleX(0.68)"
    });
  });

  it("renders idle and failed summaries without a workbench shell", () => {
    const failedTask: QueryTaskStatus = {
      task_id: "task-b",
      state: "failed",
      snapshot_id: null,
      cache_hit: false,
      error: "permission denied"
    };

    const { rerender } = render(<QueryProgressPanel task={null} />);

    expect(screen.getByText("idle")).toBeInTheDocument();
    expect(screen.getByText("no task submitted")).toBeInTheDocument();
    expect(screen.getByText("Awaiting async query submission")).toBeInTheDocument();

    rerender(<QueryProgressPanel task={failedTask} />);

    expect(screen.getByText("failed")).toBeInTheDocument();
    expect(screen.getByText("task-b")).toBeInTheDocument();
    expect(screen.getByText("permission denied")).toBeInTheDocument();
  });
});
