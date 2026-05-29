import { fireEvent, render, screen } from "@testing-library/react";
import { describe, expect, it, vi } from "vitest";
import type { DownloadPreview, PivotAnalysis, SnapshotPage } from "../api";
import type {
  DownloadAuthorizationSummary,
  DownloadPreviewSummary,
  DrilldownSummary,
  EvidenceExportSummary
} from "../analysisEvidenceController";
import { AnalysisWorkspaceShell } from "./AnalysisWorkspaceShell";

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

const exportSummary: EvidenceExportSummary = {
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
};

const downloadAuthorizationSummary: DownloadAuthorizationSummary = {
  downloadToken: "download-a",
  fileName: "evidence.txt",
  mediaType: "text/plain",
  expiresAt: "2026-03-30T09:10:00Z"
};

const downloadPreview: DownloadPreview = {
  content: "download preview",
  contentType: "text/plain",
  fileName: "evidence.txt"
};

const downloadPreviewSummary: DownloadPreviewSummary = {
  fileName: "evidence.txt",
  contentType: "text/plain",
  lineCount: 1,
  characterCount: 16,
  previewLines: ["download preview"],
  truncated: false
};

const pivot: PivotAnalysis = {
  snapshot_id: "snapshot-a",
  dimension: "department",
  metric: "record_count",
  buckets: [{ key: "fraud", value: 1 }],
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

describe("AnalysisWorkspaceShell", () => {
  it("renders the dedicated analysis workspace shell and forwards both panel surfaces", () => {
    const onTemplateNameChange = vi.fn();
    const onExportBodyChange = vi.fn();

    render(
      <AnalysisWorkspaceShell
        analysisTemplatesPanelProps={{
          isHydrating: false,
          hasSnapshot: true,
          analysisTemplates: [
            {
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
            }
          ],
          selectedTemplateId: "",
          templateName: "Fraud triage",
          templateDescription: "Default fraud workspace",
          pageSize: 2,
          pageSizeOptions: [2, 5, 10],
          pivotDimension: "department",
          pivotDimensionOptions: ["employee_id", "department"],
          pivotMetric: "record_count",
          pivotMetricOptions: [{ value: "record_count", label: "Record Count" }],
          pivotMetricField: null,
          pivotMetricFieldOptions: ["employee_id", "department"],
          analysisMessage: "",
          onTemplateNameChange,
          onTemplateDescriptionChange: vi.fn(),
          onSelectedTemplateIdChange: vi.fn(),
          onPageSizeChange: vi.fn(),
          onPivotDimensionChange: vi.fn(),
          onPivotMetricChange: vi.fn(),
          onPivotMetricFieldChange: vi.fn(),
          onSaveCurrentTemplate: vi.fn(),
          onLoadSelectedTemplate: vi.fn(),
          onSelectTemplate: vi.fn(),
          onToggleTemplateVisibility: vi.fn(),
          onDeleteTemplate: vi.fn()
        }}
        evidenceExportPanelProps={{
          isHydrating: false,
          hasSnapshot: true,
          exportTemplate: "china",
          exportTemplateOptions: [
            { value: "china", label: "China Judicial" },
            { value: "eu", label: "EU Regulatory" }
          ],
          exportBody: "stage12 export",
          exportSummary,
          downloadAuthorizationSummary,
          downloadPreview,
          downloadPreviewSummary,
          pivot,
          drilldownPage: snapshotPage,
          drilldownSummary,
          onExportTemplateChange: vi.fn(),
          onExportBodyChange,
          onGenerateEvidencePackage: vi.fn(),
          onAuthorizeDownload: vi.fn(),
          onPreviewDownload: vi.fn(),
          onLoadDrilldown: vi.fn()
        }}
      />
    );

    fireEvent.change(screen.getByLabelText("Template Name"), {
      target: { value: "Fraud triage saved" }
    });
    fireEvent.change(screen.getByLabelText("Export Body"), {
      target: { value: "cross-border export" }
    });

    expect(screen.getByTestId("analysis-workspace-shell")).toBeInTheDocument();
    expect(screen.getByText("Analysis Templates")).toBeInTheDocument();
    expect(screen.getByText("Evidence Export")).toBeInTheDocument();
    expect(screen.getByTestId("evidence-export-composer-panel")).toBeInTheDocument();
    expect(screen.getByTestId("evidence-export-results-stack")).toBeInTheDocument();
    expect(onTemplateNameChange).toHaveBeenCalledWith("Fraud triage saved");
    expect(onExportBodyChange).toHaveBeenCalledWith("cross-border export");
  });
});
