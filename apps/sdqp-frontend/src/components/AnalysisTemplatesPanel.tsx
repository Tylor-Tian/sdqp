import type { AnalysisTemplate } from "../api";

export function AnalysisTemplatesPanel({
  isHydrating,
  hasSnapshot,
  analysisTemplates,
  selectedTemplateId,
  templateName,
  templateDescription,
  pageSize,
  pageSizeOptions,
  pivotDimension,
  pivotDimensionOptions,
  pivotMetric,
  pivotMetricOptions,
  pivotMetricField,
  pivotMetricFieldOptions,
  analysisMessage,
  onTemplateNameChange,
  onTemplateDescriptionChange,
  onSelectedTemplateIdChange,
  onPageSizeChange,
  onPivotDimensionChange,
  onPivotMetricChange,
  onPivotMetricFieldChange,
  onSaveCurrentTemplate,
  onLoadSelectedTemplate,
  onSelectTemplate,
  onToggleTemplateVisibility,
  onDeleteTemplate
}: {
  isHydrating: boolean;
  hasSnapshot: boolean;
  analysisTemplates: AnalysisTemplate[];
  selectedTemplateId: string;
  templateName: string;
  templateDescription: string;
  pageSize: number;
  pageSizeOptions: number[];
  pivotDimension: string;
  pivotDimensionOptions: string[];
  pivotMetric: string;
  pivotMetricOptions: Array<{
    value: string;
    label: string;
  }>;
  pivotMetricField: string | null;
  pivotMetricFieldOptions: string[];
  analysisMessage: string;
  onTemplateNameChange: (value: string) => void;
  onTemplateDescriptionChange: (value: string) => void;
  onSelectedTemplateIdChange: (value: string) => void;
  onPageSizeChange: (value: number) => void;
  onPivotDimensionChange: (value: string) => void;
  onPivotMetricChange: (value: string) => void;
  onPivotMetricFieldChange: (value: string) => void;
  onSaveCurrentTemplate: () => void;
  onLoadSelectedTemplate: () => void;
  onSelectTemplate: (template: AnalysisTemplate) => void;
  onToggleTemplateVisibility: (template: AnalysisTemplate) => void;
  onDeleteTemplate: (template: AnalysisTemplate) => void;
}) {
  return (
    <>
      <div className="analysisPanel__header">
        <h2>Analysis Templates</h2>
      </div>
      <div className="formGrid">
        <label className="formField">
          <span>Template Name</span>
          <input
            className="textInput"
            aria-label="Template Name"
            value={templateName}
            onChange={(event) => onTemplateNameChange(event.target.value)}
          />
        </label>
        <label className="formField">
          <span>Saved Template</span>
          <select
            className="textInput"
            aria-label="Saved Template"
            value={selectedTemplateId}
            onChange={(event) => onSelectedTemplateIdChange(event.target.value)}
          >
            <option value="">Select a template</option>
            {analysisTemplates.map((template) => (
              <option key={template.template_id} value={template.template_id}>
                {template.name}
              </option>
            ))}
          </select>
        </label>
      </div>
      <label className="formField">
        <span>Template Description</span>
        <input
          className="textInput"
          aria-label="Template Description"
          value={templateDescription}
          onChange={(event) => onTemplateDescriptionChange(event.target.value)}
        />
      </label>
      <div className="formGrid">
        <label className="formField">
          <span>Page Size</span>
          <select
            className="textInput"
            aria-label="Page Size"
            value={String(pageSize)}
            disabled={isHydrating}
            onChange={(event) => onPageSizeChange(Number(event.target.value))}
          >
            {pageSizeOptions.map((option) => (
              <option key={option} value={option}>
                {option}
              </option>
            ))}
          </select>
        </label>
        <label className="formField">
          <span>Pivot Dimension</span>
          <select
            className="textInput"
            aria-label="Pivot Dimension"
            value={pivotDimension}
            disabled={isHydrating}
            onChange={(event) => onPivotDimensionChange(event.target.value)}
          >
            {pivotDimensionOptions.map((option) => (
              <option key={option} value={option}>
                {option}
              </option>
            ))}
          </select>
        </label>
      </div>
      <div className="formGrid">
        <label className="formField">
          <span>Pivot Metric</span>
          <select
            className="textInput"
            aria-label="Pivot Metric"
            value={pivotMetric}
            disabled={isHydrating}
            onChange={(event) => onPivotMetricChange(event.target.value)}
          >
            {pivotMetricOptions.map((option) => (
              <option key={option.value} value={option.value}>
                {option.label}
              </option>
            ))}
          </select>
        </label>
        <label className="formField">
          <span>Metric Field</span>
          <select
            className="textInput"
            aria-label="Metric Field"
            value={pivotMetricField ?? ""}
            disabled={isHydrating || pivotMetric === "record_count" || pivotMetricFieldOptions.length === 0}
            onChange={(event) => onPivotMetricFieldChange(event.target.value)}
          >
            <option value="">Select a field</option>
            {pivotMetricFieldOptions.map((option) => (
              <option key={option} value={option}>
                {option}
              </option>
            ))}
          </select>
        </label>
      </div>
      <div className="toolbar">
        <button
          className="button button--primary"
          type="button"
          disabled={isHydrating || !hasSnapshot}
          onClick={onSaveCurrentTemplate}
        >
          Save Current Template
        </button>
        <button
          className="button button--secondary"
          type="button"
          disabled={isHydrating || !selectedTemplateId}
          onClick={onLoadSelectedTemplate}
        >
          Load Selected Template
        </button>
      </div>
      <div className="stackList">
        {analysisTemplates.map((template) => (
          <article className="listCard" key={template.template_id}>
            <strong>{template.name}</strong>
            <p>{`${template.visibility} / ${template.data_source_id}`}</p>
            <div className="toolbar">
              <button
                className="button button--ghost"
                type="button"
                disabled={isHydrating}
                onClick={() => onSelectTemplate(template)}
              >
                Select
              </button>
              {template.editable ? (
                <button
                  className="button button--ghost"
                  type="button"
                  disabled={isHydrating}
                  onClick={() => onToggleTemplateVisibility(template)}
                >
                  {template.visibility === "published" ? "Unpublish" : "Publish"}
                </button>
              ) : null}
              {template.editable ? (
                <button
                  className="button button--ghost"
                  type="button"
                  disabled={isHydrating}
                  onClick={() => onDeleteTemplate(template)}
                >
                  Delete
                </button>
              ) : null}
            </div>
          </article>
        ))}
      </div>
      {analysisMessage ? <p className="inlineNotice">{analysisMessage}</p> : null}
    </>
  );
}
