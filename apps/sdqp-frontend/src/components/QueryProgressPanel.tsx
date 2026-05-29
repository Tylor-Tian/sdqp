import type { QueryTaskStatus } from "../api";
import type { WorkbenchRuntimeState } from "../analysisEvidenceController";

function fallbackRuntimeState(task: QueryTaskStatus | null): WorkbenchRuntimeState {
  const taskState = task?.state ?? "idle";
  return {
    queryPriority: "normal",
    taskState,
    backendRuntimeState: taskState,
    adapterRuntimeState: "not reported",
    snapshotAccessState: task?.snapshot_id ? "authorized_encrypted_snapshot" : "no_snapshot_selected",
    securityState: "clear",
    downloadAuthorizationState: "not_requested",
    controls: {
      canSubmitQuery: taskState !== "pending" && taskState !== "running",
      canCancelTask: false,
      canRetryQuery: taskState === "failed" || taskState === "cancelled",
      canCompleteStepUp: false,
      canAuthorizeDownload: false,
      canPreviewDownload: false
    },
    summaryRows: [
      { label: "Task Priority", value: "normal (pending)" },
      { label: "Runtime State", value: `runtime ${taskState}` },
      { label: "Adapter Runtime", value: "not reported" },
      {
        label: "Secure Snapshot Access",
        value: task?.snapshot_id ? "authorized_encrypted_snapshot" : "no_snapshot_selected"
      },
      { label: "Step-Up", value: "clear" },
      { label: "Download Authorization", value: "not_requested" }
    ]
  };
}

function statusProgress(status: string | null) {
  switch (status) {
    case "pending":
      return 0.2;
    case "running":
      return 0.68;
    case "completed":
    case "failed":
    case "cancelled":
      return 1;
    default:
      return 0.04;
  }
}

function summarizeResult(task: QueryTaskStatus | null) {
  if (!task) {
    return "Awaiting async query submission";
  }

  if (task.error) {
    return task.error;
  }

  if (task.snapshot_id) {
    return `snapshot ${task.snapshot_id}`;
  }

  return task.cache_hit ? "cache hit without snapshot" : "result pending";
}

export function QueryProgressPanel({
  task,
  runtimeState,
  isHydrating,
  onCancelTask,
  onRetryQuery,
  onCompleteStepUp,
  onAuthorizeDownload,
  onPreviewDownload
}: {
  task: QueryTaskStatus | null;
  runtimeState?: WorkbenchRuntimeState;
  isHydrating: boolean;
  onCancelTask: () => void;
  onRetryQuery: () => void;
  onCompleteStepUp: () => void;
  onAuthorizeDownload: () => void;
  onPreviewDownload: () => void;
}) {
  const effectiveRuntimeState = runtimeState ?? fallbackRuntimeState(task);
  return (
    <section className="statusPanel statusPanel--compact" data-testid="query-progress-panel">
      <h3 className="surfacePanel__title">Query Progress</h3>
      <div className="statusMeter">
        <div className="statusMeter__bar">
          <div
            className="statusMeter__fill"
            style={{ transform: `scaleX(${statusProgress(task?.state ?? null)})` }}
          />
        </div>
        <div className="statusMeta">
          <div>
            <strong>State</strong>
            <div>{task?.state ?? "idle"}</div>
          </div>
          <div>
            <strong>Task</strong>
            <div>{task?.task_id ?? "no task submitted"}</div>
          </div>
          <div>
            <strong>Result</strong>
            <div>{summarizeResult(task)}</div>
          </div>
        </div>
      </div>
      <div className="statusMeta" data-testid="workbench-runtime-state">
        {effectiveRuntimeState.summaryRows.map((row) => (
          <div key={row.label}>
            <strong>{row.label}</strong>
            <div>{row.value}</div>
          </div>
        ))}
      </div>
      <div className="toolbar">
        <button
          className="button"
          type="button"
          disabled={isHydrating || !effectiveRuntimeState.controls.canCancelTask}
          onClick={onCancelTask}
        >
          Cancel Task
        </button>
        <button
          className="button"
          type="button"
          disabled={isHydrating || !effectiveRuntimeState.controls.canRetryQuery}
          onClick={onRetryQuery}
        >
          Retry Query
        </button>
        <button
          className="button"
          type="button"
          aria-label="Complete Runtime Step-Up"
          disabled={isHydrating || !effectiveRuntimeState.controls.canCompleteStepUp}
          onClick={onCompleteStepUp}
        >
          Complete Step-Up
        </button>
        <button
          className="button"
          type="button"
          aria-label="Authorize Runtime Download"
          disabled={isHydrating || !effectiveRuntimeState.controls.canAuthorizeDownload}
          onClick={onAuthorizeDownload}
        >
          Authorize Download
        </button>
        <button
          className="button"
          type="button"
          aria-label="Preview Runtime Download"
          disabled={isHydrating || !effectiveRuntimeState.controls.canPreviewDownload}
          onClick={onPreviewDownload}
        >
          Preview Download
        </button>
      </div>
    </section>
  );
}
