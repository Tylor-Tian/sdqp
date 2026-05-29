export function EvidenceExportComposerPanel({
  isHydrating,
  hasSnapshot,
  exportTemplate,
  exportTemplateOptions,
  exportBody,
  canAuthorizeDownload,
  canPreviewDownload,
  onExportTemplateChange,
  onExportBodyChange,
  onGenerateEvidencePackage,
  onAuthorizeDownload,
  onPreviewDownload
}: {
  isHydrating: boolean;
  hasSnapshot: boolean;
  exportTemplate: string;
  exportTemplateOptions: Array<{
    value: string;
    label: string;
  }>;
  exportBody: string;
  canAuthorizeDownload: boolean;
  canPreviewDownload: boolean;
  onExportTemplateChange: (value: string) => void;
  onExportBodyChange: (value: string) => void;
  onGenerateEvidencePackage: () => void;
  onAuthorizeDownload: () => void;
  onPreviewDownload: () => void;
}) {
  return (
    <div data-testid="evidence-export-composer-panel">
      <div className="formGrid">
        <label className="formField">
          <span>Export Template</span>
          <select
            className="textInput"
            aria-label="Export Template"
            value={exportTemplate}
            disabled={isHydrating}
            onChange={(event) => onExportTemplateChange(event.target.value)}
          >
            {exportTemplateOptions.map((option) => (
              <option key={option.value} value={option.value}>
                {option.label}
              </option>
            ))}
          </select>
        </label>
      </div>
      <label className="formField">
        <span>Export Body</span>
        <textarea
          className="textInput"
          aria-label="Export Body"
          value={exportBody}
          rows={3}
          disabled={isHydrating}
          onChange={(event) => onExportBodyChange(event.target.value)}
        />
      </label>
      <div className="toolbar">
        <button
          className="button button--primary"
          type="button"
          disabled={isHydrating || !hasSnapshot}
          onClick={onGenerateEvidencePackage}
        >
          Generate Evidence Package
        </button>
        {canAuthorizeDownload ? (
          <button
            className="button button--secondary"
            type="button"
            disabled={isHydrating}
            onClick={onAuthorizeDownload}
          >
            Authorize Download
          </button>
        ) : null}
        {canPreviewDownload ? (
          <button
            className="button button--ghost"
            type="button"
            disabled={isHydrating}
            onClick={onPreviewDownload}
          >
            Preview Download
          </button>
        ) : null}
      </div>
    </div>
  );
}
