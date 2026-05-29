import { fireEvent, render, screen } from "@testing-library/react";
import { describe, expect, it, vi } from "vitest";
import type {
  AnalysisTemplate,
  DownloadPreview,
  EvidenceExportResponse,
  PivotAnalysis,
  QueryTaskStatus,
  SnapshotPage
} from "../api";
import { buildWorkbenchRuntimeState } from "../analysisEvidenceController";
import { AnalysisTemplatesPanel } from "./AnalysisTemplatesPanel";
import { DetailPagePanel } from "./DetailPagePanel";
import { EvidenceExportPanel } from "./EvidenceExportPanel";
import { QueryWorkbenchPanel } from "./QueryWorkbenchPanel";

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
      masked: false,
      render_mode: "canvas",
      watermark_strength: "low"
    }
  ],
  watermark_text: "tenant-alpha / project-alpha / user-analyst"
};

const template: AnalysisTemplate = {
  template_id: "template-a",
  name: "Fraud triage",
  description: "Default fraud workspace",
  data_source_id: "datasource-rest",
  visibility: "private",
  owner_user_id: "user-analyst",
  editable: true,
  published_at: null,
  created_at: "2026-04-05T09:00:00Z",
  updated_at: "2026-04-05T09:00:00Z",
  config: {
    page_size: 2,
    detail_fields: ["employee_id", "department"],
    pivot_dimension: "department",
    pivot_metric: "record_count",
    pivot_metric_field: null,
    pivot_percentile: null
  }
};

const downloadPreview: DownloadPreview = {
  content: "download preview",
  contentType: "text/plain",
  fileName: "evidence.txt"
};

const pivot: PivotAnalysis = {
  snapshot_id: "snapshot-a",
  dimension: "department",
  metric: "record_count",
  buckets: [{ key: "fraud", value: 1 }],
  watermark_text: "tenant-alpha / project-alpha / user-analyst"
};

describe("workbench panels", () => {
  it("gates workbench controls on backend runtime, step-up, and secure snapshot access", () => {
    const exportTask = { download_ready: true } as EvidenceExportResponse;
    const runningTask: QueryTaskStatus = {
      task_id: "task-a",
      state: "running",
      snapshot_id: null,
      cache_hit: false,
      error: null,
      priority: { label: "high", value: 75 },
      runtime: {
        task_id: "task-a",
        priority: { label: "high", value: 75 },
        runtime_state: "running",
        adapter_runtime_state: "Started",
        adapter_availability: "Available",
        secure_snapshot_access: "pending_encrypted_snapshot",
        controls: {
          can_cancel: true,
          can_retry: false,
          can_access_snapshot: false
        }
      }
    };

    const runningState = buildWorkbenchRuntimeState({
      task: runningTask,
      queryPriority: "high",
      snapshotPage: null,
      securityNotice: null,
      stepUpRequired: false,
      exportTask,
      downloadAuthorization: null,
      downloadPreview: null
    });

    expect(runningState.controls.canSubmitQuery).toBe(false);
    expect(runningState.controls.canCancelTask).toBe(true);
    expect(runningState.controls.canAuthorizeDownload).toBe(false);

    const completedTask: QueryTaskStatus = {
      ...runningTask,
      state: "completed",
      snapshot_id: "snapshot-a",
      runtime: {
        ...runningTask.runtime!,
        runtime_state: "completed",
        secure_snapshot_access: "authorized_encrypted_snapshot",
        controls: {
          can_cancel: false,
          can_retry: false,
          can_access_snapshot: true
        }
      }
    };
    const completedState = buildWorkbenchRuntimeState({
      task: completedTask,
      queryPriority: "high",
      snapshotPage,
      securityNotice: null,
      stepUpRequired: false,
      exportTask,
      downloadAuthorization: null,
      downloadPreview: null
    });

    expect(completedState.controls.canSubmitQuery).toBe(true);
    expect(completedState.controls.canAuthorizeDownload).toBe(true);

    const stepUpState = buildWorkbenchRuntimeState({
      task: completedTask,
      queryPriority: "high",
      snapshotPage,
      securityNotice: null,
      stepUpRequired: true,
      exportTask,
      downloadAuthorization: null,
      downloadPreview: null
    });

    expect(stepUpState.controls.canCompleteStepUp).toBe(true);
    expect(stepUpState.controls.canAuthorizeDownload).toBe(false);
    expect(stepUpState.controls.canSubmitQuery).toBe(false);
  });

  it("renders query progress through the extracted query workbench panel", () => {
    const onDataSourceIdChange = vi.fn();
    const onSelectedFieldToggle = vi.fn();
    const onQueryPriorityChange = vi.fn();
    const onSubmitAsyncQuery = vi.fn();
    const onCancelTask = vi.fn();
    const onRetryQuery = vi.fn();
    const onCompleteStepUp = vi.fn();
    const onAuthorizeDownload = vi.fn();
    const onPreviewDownload = vi.fn();
    const task: QueryTaskStatus = {
      task_id: "task-a",
      state: "running",
      snapshot_id: null,
      cache_hit: false,
      error: null,
      priority: { label: "high", value: 75 },
      runtime: {
        task_id: "task-a",
        priority: { label: "high", value: 75 },
        runtime_state: "running",
        adapter_runtime_state: "Started",
        adapter_availability: "Available",
        secure_snapshot_access: "pending_encrypted_snapshot",
        controls: {
          can_cancel: true,
          can_retry: false,
          can_access_snapshot: false
        }
      }
    };
    const runtimeState = {
      queryPriority: "high" as const,
      taskState: "running",
      backendRuntimeState: "running",
      adapterRuntimeState: "Started",
      snapshotAccessState: "pending_encrypted_snapshot",
      securityState: "step_up_required" as const,
      downloadAuthorizationState: "authorized" as const,
      controls: {
        canSubmitQuery: true,
        canCancelTask: true,
        canRetryQuery: false,
        canCompleteStepUp: true,
        canAuthorizeDownload: false,
        canPreviewDownload: true
      },
      summaryRows: [
        { label: "Task Priority", value: "high (75)" },
        { label: "Runtime State", value: "running" },
        { label: "Adapter Runtime", value: "Started" },
        { label: "Secure Snapshot Access", value: "pending_encrypted_snapshot" },
        { label: "Step-Up", value: "required" },
        { label: "Download Authorization", value: "authorized" }
      ]
    };
    const { container } = render(
      <QueryWorkbenchPanel
        isHydrating={false}
        dataSourceId="datasource-rest"
        dataSourceOptions={[
          { id: "datasource-rest", label: "REST HR Feed" },
          { id: "datasource-rpc", label: "RPC HR Feed" }
        ]}
        fieldOptions={[
          { name: "employee_id", label: "Employee ID", note: "Low-sensitivity identifier" },
          { name: "department", label: "Department", note: "Primary drilldown dimension" }
        ]}
        selectedFields={["employee_id", "department"]}
        queryPriority="high"
        queryPriorityOptions={[
          { value: "normal", label: "Normal" },
          { value: "high", label: "High" },
          { value: "critical", label: "Critical" }
        ]}
        task={task}
        runtimeState={runtimeState}
        onDataSourceIdChange={onDataSourceIdChange}
        onSelectedFieldToggle={onSelectedFieldToggle}
        onQueryPriorityChange={onQueryPriorityChange}
        onSubmitAsyncQuery={onSubmitAsyncQuery}
        onCancelTask={onCancelTask}
        onRetryQuery={onRetryQuery}
        onCompleteStepUp={onCompleteStepUp}
        onAuthorizeDownload={onAuthorizeDownload}
        onPreviewDownload={onPreviewDownload}
      />
    );

    fireEvent.change(screen.getByLabelText("Data Source"), {
      target: { value: "datasource-rpc" }
    });
    fireEvent.click(screen.getByLabelText("Field Employee ID"));
    fireEvent.change(screen.getByLabelText("Query Priority"), {
      target: { value: "critical" }
    });
    fireEvent.click(screen.getByRole("button", { name: "Submit Async Query" }));
    fireEvent.click(screen.getByRole("button", { name: "Cancel Task" }));
    fireEvent.click(screen.getByRole("button", { name: "Complete Runtime Step-Up" }));
    fireEvent.click(screen.getByRole("button", { name: "Preview Runtime Download" }));

    expect(onDataSourceIdChange).toHaveBeenCalledWith("datasource-rpc");
    expect(onSelectedFieldToggle).toHaveBeenCalledWith("employee_id", false);
    expect(onQueryPriorityChange).toHaveBeenCalledWith("critical");
    expect(onSubmitAsyncQuery).toHaveBeenCalledTimes(1);
    expect(onCancelTask).toHaveBeenCalledTimes(1);
    expect(onRetryQuery).not.toHaveBeenCalled();
    expect(onCompleteStepUp).toHaveBeenCalledTimes(1);
    expect(onPreviewDownload).toHaveBeenCalledTimes(1);
    expect(screen.getByText("Query Progress")).toBeInTheDocument();
    expect(screen.getAllByText("running").length).toBeGreaterThan(0);
    expect(screen.getByText("task-a")).toBeInTheDocument();
    expect(screen.getByText("result pending")).toBeInTheDocument();
    expect(screen.getByText("Task Priority")).toBeInTheDocument();
    expect(screen.getByText("high (75)")).toBeInTheDocument();
    expect(screen.getByText("Secure Snapshot Access")).toBeInTheDocument();
    expect(screen.getByText("pending_encrypted_snapshot")).toBeInTheDocument();
    expect(screen.getByRole("button", { name: "Retry Query" })).toBeDisabled();
    expect(container.querySelector(".statusMeter__fill")).toHaveStyle({
      transform: "scaleX(0.68)"
    });
  });

  it("renders snapshot detail rows through the extracted detail page panel", () => {
    const { container } = render(<DetailPagePanel snapshotPage={snapshotPage} />);

    expect(screen.getByText("Detail Page")).toBeInTheDocument();
    expect(screen.getByText("Snapshot Metadata")).toBeInTheDocument();
    expect(screen.getByText("Cursor Status")).toBeInTheDocument();
    expect(screen.getByText("Policy Coverage")).toBeInTheDocument();
    expect(screen.getByText("Sample Rows")).toBeInTheDocument();
    expect(screen.getByTestId("detail-view")).toBeInTheDocument();
    expect(screen.getByRole("columnheader", { name: "employee_id" })).toBeInTheDocument();
    expect(screen.getByLabelText("employee_id canvas cell")).toBeInTheDocument();
    expect(screen.getByText("employee_id / plain / low")).toBeInTheDocument();
    expect(screen.getByText("cursor exhausted on current detail page")).toBeInTheDocument();
    expect(screen.getByText(/Row 1: employee_id=E-100 \| department=fraud/)).toBeInTheDocument();
    expect(screen.getByTestId("watermark-overlay-detail-page")).toHaveTextContent(
      "tenant-alpha / project-alpha / user-analyst"
    );
    expect(container.querySelectorAll(".inlineNotice")).toHaveLength(0);
  });

  it("routes template actions through the extracted analysis template panel", () => {
    const onTemplateNameChange = vi.fn();
    const onTemplateDescriptionChange = vi.fn();
    const onSelectedTemplateIdChange = vi.fn();
    const onPageSizeChange = vi.fn();
    const onPivotDimensionChange = vi.fn();
    const onPivotMetricChange = vi.fn();
    const onPivotMetricFieldChange = vi.fn();
    const onSaveCurrentTemplate = vi.fn();
    const onLoadSelectedTemplate = vi.fn();
    const onSelectTemplate = vi.fn();
    const onToggleTemplateVisibility = vi.fn();
    const onDeleteTemplate = vi.fn();

    render(
      <AnalysisTemplatesPanel
        isHydrating={false}
        hasSnapshot
        analysisTemplates={[template]}
        selectedTemplateId=""
        templateName="Fraud triage"
        templateDescription="Default fraud workspace"
        pageSize={2}
        pageSizeOptions={[2, 5, 10]}
        pivotDimension="department"
        pivotDimensionOptions={["employee_id", "department"]}
        pivotMetric="record_count"
        pivotMetricOptions={[
          { value: "record_count", label: "Record Count" },
          { value: "sum", label: "Sum" }
        ]}
        pivotMetricField={null}
        pivotMetricFieldOptions={["employee_id", "department"]}
        analysisMessage="Loaded template Fraud triage."
        onTemplateNameChange={onTemplateNameChange}
        onTemplateDescriptionChange={onTemplateDescriptionChange}
        onSelectedTemplateIdChange={onSelectedTemplateIdChange}
        onPageSizeChange={onPageSizeChange}
        onPivotDimensionChange={onPivotDimensionChange}
        onPivotMetricChange={onPivotMetricChange}
        onPivotMetricFieldChange={onPivotMetricFieldChange}
        onSaveCurrentTemplate={onSaveCurrentTemplate}
        onLoadSelectedTemplate={onLoadSelectedTemplate}
        onSelectTemplate={onSelectTemplate}
        onToggleTemplateVisibility={onToggleTemplateVisibility}
        onDeleteTemplate={onDeleteTemplate}
      />
    );

    fireEvent.change(screen.getByLabelText("Template Name"), {
      target: { value: "Fraud triage saved" }
    });
    fireEvent.change(screen.getByLabelText("Saved Template"), {
      target: { value: "template-a" }
    });
    fireEvent.change(screen.getByLabelText("Page Size"), {
      target: { value: "10" }
    });
    fireEvent.change(screen.getByLabelText("Pivot Dimension"), {
      target: { value: "employee_id" }
    });
    fireEvent.change(screen.getByLabelText("Pivot Metric"), {
      target: { value: "sum" }
    });
    fireEvent.click(screen.getByRole("button", { name: "Save Current Template" }));
    fireEvent.click(screen.getByRole("button", { name: "Select" }));
    fireEvent.click(screen.getByRole("button", { name: "Publish" }));
    fireEvent.click(screen.getByRole("button", { name: "Delete" }));

    expect(onTemplateNameChange).toHaveBeenCalledWith("Fraud triage saved");
    expect(onSelectedTemplateIdChange).toHaveBeenCalledWith("template-a");
    expect(onPageSizeChange).toHaveBeenCalledWith(10);
    expect(onPivotDimensionChange).toHaveBeenCalledWith("employee_id");
    expect(onPivotMetricChange).toHaveBeenCalledWith("sum");
    expect(onSaveCurrentTemplate).toHaveBeenCalledTimes(1);
    expect(onSelectTemplate).toHaveBeenCalledWith(template);
    expect(onToggleTemplateVisibility).toHaveBeenCalledWith(template);
    expect(onDeleteTemplate).toHaveBeenCalledWith(template);
    expect(screen.getByText("Loaded template Fraud triage.")).toBeInTheDocument();
  });

  it("routes export and drilldown actions through the extracted evidence export panel", () => {
    const onExportTemplateChange = vi.fn();
    const onExportBodyChange = vi.fn();
    const onGenerateEvidencePackage = vi.fn();
    const onAuthorizeDownload = vi.fn();
    const onPreviewDownload = vi.fn();
    const onLoadDrilldown = vi.fn();

    const { container } = render(
      <EvidenceExportPanel
        isHydrating={false}
        hasSnapshot
        exportTemplate="china"
        exportTemplateOptions={[
          { value: "china", label: "China Judicial" },
          { value: "eu", label: "EU Regulatory" }
        ]}
        exportBody="stage12 export"
        exportSummary={{
          packageId: "package-a",
          snapshotId: "snapshot-a",
          template: "china",
          fileName: "evidence.txt",
          mediaType: "text/plain",
          auditEventCount: 3,
          auditChainValid: true,
          verificationReady: true,
          manifestDigest: "digest-a",
          timestampAuthority: "mock-tsa",
          anchorNetwork: "mock-chain",
          anchorTransactionId: "tx-a",
          watermarkText: "tenant-alpha / project-alpha / user-analyst",
          completedAt: "2026-03-30T09:01:00Z"
        }}
        downloadAuthorizationSummary={{
          downloadToken: "download-a",
          fileName: "evidence.txt",
          mediaType: "text/plain",
          expiresAt: "2026-03-30T09:10:00Z"
        }}
        downloadPreview={downloadPreview}
        downloadPreviewSummary={{
          fileName: "evidence.txt",
          contentType: "text/plain",
          lineCount: 1,
          characterCount: 16,
          previewLines: ["download preview"],
          truncated: false
        }}
        pivot={pivot}
        drilldownPage={snapshotPage}
        drilldownSummary={{
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
          fieldPolicies: [
            "employee_id / plain / low",
            "department / plain / low"
          ]
        }}
        onExportTemplateChange={onExportTemplateChange}
        onExportBodyChange={onExportBodyChange}
        onGenerateEvidencePackage={onGenerateEvidencePackage}
        onAuthorizeDownload={onAuthorizeDownload}
        onPreviewDownload={onPreviewDownload}
        onLoadDrilldown={onLoadDrilldown}
      />
    );

    fireEvent.change(screen.getByLabelText("Export Template"), {
      target: { value: "eu" }
    });
    fireEvent.change(screen.getByLabelText("Export Body"), {
      target: { value: "cross-border export" }
    });
    fireEvent.click(screen.getByRole("button", { name: "Generate Evidence Package" }));
    fireEvent.click(screen.getByRole("button", { name: "Authorize Download" }));
    fireEvent.click(screen.getByRole("button", { name: "Preview Download" }));
    fireEvent.click(screen.getByRole("button", { name: "Load drilldown fraud 1" }));

    expect(onExportTemplateChange).toHaveBeenCalledWith("eu");
    expect(onExportBodyChange).toHaveBeenCalledWith("cross-border export");
    expect(onGenerateEvidencePackage).toHaveBeenCalledTimes(1);
    expect(onAuthorizeDownload).toHaveBeenCalledTimes(1);
    expect(onPreviewDownload).toHaveBeenCalledTimes(1);
    expect(onLoadDrilldown).toHaveBeenCalledWith("fraud");
    expect(screen.getByText("Evidence Export")).toBeInTheDocument();
    expect(screen.getByTestId("evidence-export-composer-panel")).toBeInTheDocument();
    expect(screen.getByTestId("evidence-export-results-stack")).toBeInTheDocument();
    expect(screen.getByTestId("evidence-package-summary-panel")).toBeInTheDocument();
    expect(screen.getByTestId("download-authorization-panel")).toBeInTheDocument();
    expect(screen.getByTestId("download-preview-panel")).toBeInTheDocument();
    expect(screen.getByText("package-a")).toBeInTheDocument();
    expect(screen.getByText("Export Metadata")).toBeInTheDocument();
    expect(screen.getByText("Manifest & Audit")).toBeInTheDocument();
    expect(screen.getByText("Trust Anchors")).toBeInTheDocument();
    expect(screen.getByText("Download Authorization")).toBeInTheDocument();
    expect(screen.getByText(/token download-a/)).toBeInTheDocument();
    expect(screen.getByText("Preview Metadata")).toBeInTheDocument();
    expect(screen.getByText("Preview Excerpt")).toBeInTheDocument();
    expect(screen.getByText("L1: download preview")).toBeInTheDocument();
    expect(screen.getByText("Pivot & Drilldown")).toBeInTheDocument();
    expect(screen.getByTestId("pivot-table")).toBeInTheDocument();
    expect(screen.getByTestId("drilldown-inspection-panel")).toBeInTheDocument();
    expect(screen.getByText("Drilldown Context")).toBeInTheDocument();
    expect(screen.getByText("Field Policies")).toBeInTheDocument();
    expect(screen.getByText(/Row 1: employee_id=E-100/)).toBeInTheDocument();
    expect(screen.getByTestId("watermark-overlay-evidence-export")).toHaveTextContent(
      "tenant-alpha / project-alpha / user-analyst"
    );
    expect(screen.getByTestId("watermark-overlay-download-authorization")).toBeInTheDocument();
    expect(screen.getByTestId("watermark-overlay-download-preview")).toBeInTheDocument();
    expect(screen.getByTestId("watermark-overlay-pivot-analysis")).toBeInTheDocument();
    expect(screen.getByTestId("watermark-overlay-drilldown")).toBeInTheDocument();
    expect(screen.getByText("completed 2026-03-30T09:01:00Z")).toBeInTheDocument();
    expect(container.querySelectorAll(".inlineNotice")).toHaveLength(1);
  });
});
