import { fireEvent, render, screen } from "@testing-library/react";
import { describe, expect, it, vi } from "vitest";
import type { UebaAlerts, UebaBaselines } from "../api";
import { UebaAuditPanel } from "./UebaAuditPanel";

const alerts: UebaAlerts = {
  alerts: [
    {
      alert_id: "alert-a",
      user_id: "user-analyst",
      rule: "query-burst",
      risk_score: 87,
      action: "step_up",
      evidence: "burst over baseline"
    }
  ],
  step_up_sessions: 1,
  permissions_revoked: 0,
  terminated_sessions: 0
};

const baselines: UebaBaselines = {
  user_baselines: [],
  entity_baselines: [
    {
      entity_type: "data_source",
      entity_id: "datasource-rest",
      baseline_window: "7d",
      query_count: 42,
      export_count: 1,
      denied_count: 0,
      distinct_users: 5
    }
  ]
};

describe("monitoring panels", () => {
  it("routes audit actions through the extracted UEBA/audit panel", () => {
    const onAuditActionChange = vi.fn();
    const onAuditLimitChange = vi.fn();
    const onLoadAuditView = vi.fn();

    render(
      <UebaAuditPanel
        isHydrating={false}
        alerts={alerts}
        baselines={baselines}
        auditAction="query"
        auditActionOptions={[
          { value: "", label: "All Actions" },
          { value: "query", label: "Query" },
          { value: "export", label: "Export" }
        ]}
        auditLimit={10}
        auditLimitOptions={[10, 25, 50]}
        auditView={{
          chainValid: true,
          totalMatches: 1,
          actionLabel: "query",
          limit: 10,
          events: [
            {
              eventId: "event-a",
              timestamp: "2026-03-30T08:00:00Z",
              actorUserId: "user-analyst",
              action: "query",
              result: "success",
              projectId: "project-alpha",
              resourceId: "queries/task-a",
              context: "baseline query"
            }
          ]
        }}
        onAuditActionChange={onAuditActionChange}
        onAuditLimitChange={onAuditLimitChange}
        onLoadAuditView={onLoadAuditView}
      />
    );

    fireEvent.change(screen.getByLabelText("Audit Action"), {
      target: { value: "export" }
    });
    fireEvent.change(screen.getByLabelText("Audit Limit"), {
      target: { value: "25" }
    });
    fireEvent.click(screen.getByRole("button", { name: "Load Audit View" }));

    expect(onAuditActionChange).toHaveBeenCalledWith("export");
    expect(onAuditLimitChange).toHaveBeenCalledWith(25);
    expect(onLoadAuditView).toHaveBeenCalledTimes(1);
    expect(screen.getByText("UEBA")).toBeInTheDocument();
    expect(screen.getByText("Alerts")).toBeInTheDocument();
    expect(screen.getByText("Baselines")).toBeInTheDocument();
    expect(screen.getByText("Matches")).toBeInTheDocument();
    expect(screen.getByText("Chain")).toBeInTheDocument();
    expect(screen.getByText("Audit Match Summary")).toBeInTheDocument();
    expect(screen.getByText("query / success")).toBeInTheDocument();
    expect(screen.getByText("Valid")).toBeInTheDocument();
    expect(screen.getByText("1 matches / query / limit 10")).toBeInTheDocument();
  });
});
