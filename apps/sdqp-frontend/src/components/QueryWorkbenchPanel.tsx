import type { QueryPriorityLevel, QueryTaskStatus } from "../api";
import type { WorkbenchRuntimeState } from "../analysisEvidenceController";
import { QueryProgressPanel } from "./QueryProgressPanel";

export function QueryWorkbenchPanel({
  isHydrating,
  dataSourceId,
  dataSourceOptions,
  fieldOptions,
  selectedFields,
  queryPriority,
  queryPriorityOptions,
  task,
  runtimeState,
  onDataSourceIdChange,
  onSelectedFieldToggle,
  onQueryPriorityChange,
  onSubmitAsyncQuery,
  onCancelTask,
  onRetryQuery,
  onCompleteStepUp,
  onAuthorizeDownload,
  onPreviewDownload
}: {
  isHydrating: boolean;
  dataSourceId: string;
  dataSourceOptions: Array<{
    id: string;
    label: string;
  }>;
  fieldOptions: Array<{
    name: string;
    label: string;
    note: string;
  }>;
  selectedFields: string[];
  queryPriority: QueryPriorityLevel;
  queryPriorityOptions: Array<{
    value: QueryPriorityLevel;
    label: string;
  }>;
  task: QueryTaskStatus | null;
  runtimeState: WorkbenchRuntimeState;
  onDataSourceIdChange: (value: string) => void;
  onSelectedFieldToggle: (fieldName: string, checked: boolean) => void;
  onQueryPriorityChange: (value: QueryPriorityLevel) => void;
  onSubmitAsyncQuery: () => void;
  onCancelTask: () => void;
  onRetryQuery: () => void;
  onCompleteStepUp: () => void;
  onAuthorizeDownload: () => void;
  onPreviewDownload: () => void;
}) {
  return (
    <section className="surfacePanel">
      <h2 className="surfacePanel__title">Query Workbench</h2>
      <div className="formGrid">
        <label className="formField">
          <span>Data Source</span>
          <select
            className="textInput"
            aria-label="Data Source"
            value={dataSourceId}
            disabled={isHydrating}
            onChange={(event) => onDataSourceIdChange(event.target.value)}
          >
            {dataSourceOptions.map((option) => (
              <option key={option.id} value={option.id}>
                {option.label}
              </option>
            ))}
          </select>
        </label>
        <label className="formField">
          <span>Query Priority</span>
          <select
            className="textInput"
            aria-label="Query Priority"
            value={queryPriority}
            disabled={isHydrating}
            onChange={(event) => onQueryPriorityChange(event.target.value as QueryPriorityLevel)}
          >
            {queryPriorityOptions.map((option) => (
              <option key={option.value} value={option.value}>
                {option.label}
              </option>
            ))}
          </select>
        </label>
      </div>
      <div className="stackList">
        {fieldOptions.map((field) => (
          <label className="listCard" key={field.name}>
            <span>
              <strong>{field.label}</strong>
              <span className="helperText"> {field.note}</span>
            </span>
            <input
              type="checkbox"
              aria-label={`Field ${field.label}`}
              checked={selectedFields.includes(field.name)}
              disabled={isHydrating}
              onChange={(event) => onSelectedFieldToggle(field.name, event.target.checked)}
            />
          </label>
        ))}
      </div>
      <div className="toolbar">
        <button
          className="button button--primary"
          type="button"
          disabled={
            isHydrating || selectedFields.length === 0 || !runtimeState.controls.canSubmitQuery
          }
          onClick={onSubmitAsyncQuery}
        >
          Submit Async Query
        </button>
      </div>
      <QueryProgressPanel
        task={task}
        runtimeState={runtimeState}
        isHydrating={isHydrating}
        onCancelTask={onCancelTask}
        onRetryQuery={onRetryQuery}
        onCompleteStepUp={onCompleteStepUp}
        onAuthorizeDownload={onAuthorizeDownload}
        onPreviewDownload={onPreviewDownload}
      />
    </section>
  );
}
