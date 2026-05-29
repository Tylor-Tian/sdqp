import { fireEvent, render, screen } from "@testing-library/react";
import { describe, expect, it, vi } from "vitest";
import { EvidenceExportComposerPanel } from "./EvidenceExportComposerPanel";

describe("EvidenceExportComposerPanel", () => {
  it("renders the dedicated evidence-export composer surface and forwards actions", () => {
    const onExportTemplateChange = vi.fn();
    const onExportBodyChange = vi.fn();
    const onGenerateEvidencePackage = vi.fn();
    const onAuthorizeDownload = vi.fn();
    const onPreviewDownload = vi.fn();

    render(
      <EvidenceExportComposerPanel
        isHydrating={false}
        hasSnapshot
        exportTemplate="china"
        exportTemplateOptions={[
          { value: "china", label: "China Judicial" },
          { value: "eu", label: "EU Regulatory" }
        ]}
        exportBody="stage12 export"
        canAuthorizeDownload
        canPreviewDownload
        onExportTemplateChange={onExportTemplateChange}
        onExportBodyChange={onExportBodyChange}
        onGenerateEvidencePackage={onGenerateEvidencePackage}
        onAuthorizeDownload={onAuthorizeDownload}
        onPreviewDownload={onPreviewDownload}
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

    expect(screen.getByTestId("evidence-export-composer-panel")).toBeInTheDocument();
    expect(onExportTemplateChange).toHaveBeenCalledWith("eu");
    expect(onExportBodyChange).toHaveBeenCalledWith("cross-border export");
    expect(onGenerateEvidencePackage).toHaveBeenCalledTimes(1);
    expect(onAuthorizeDownload).toHaveBeenCalledTimes(1);
    expect(onPreviewDownload).toHaveBeenCalledTimes(1);
  });

  it("hides follow-up actions until export and authorization states exist", () => {
    render(
      <EvidenceExportComposerPanel
        isHydrating
        hasSnapshot={false}
        exportTemplate="china"
        exportTemplateOptions={[{ value: "china", label: "China Judicial" }]}
        exportBody="stage12 export"
        canAuthorizeDownload={false}
        canPreviewDownload={false}
        onExportTemplateChange={vi.fn()}
        onExportBodyChange={vi.fn()}
        onGenerateEvidencePackage={vi.fn()}
        onAuthorizeDownload={vi.fn()}
        onPreviewDownload={vi.fn()}
      />
    );

    expect(screen.getByTestId("evidence-export-composer-panel")).toBeInTheDocument();
    expect(screen.getByRole("button", { name: "Generate Evidence Package" })).toBeDisabled();
    expect(screen.queryByRole("button", { name: "Authorize Download" })).not.toBeInTheDocument();
    expect(screen.queryByRole("button", { name: "Preview Download" })).not.toBeInTheDocument();
  });
});
