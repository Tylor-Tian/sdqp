import { render, screen } from "@testing-library/react";
import { describe, expect, it } from "vitest";
import { WatermarkFrame, WatermarkOverlay } from "./WatermarkOverlay";

describe("WatermarkOverlay", () => {
  it("renders a hybrid svg and canvas watermark layer with hidden descriptor text", () => {
    const { container } = render(
      <WatermarkOverlay
        text="tenant-alpha / project-alpha / user-analyst"
        tileCount={6}
        testId="watermark-overlay"
      />
    );

    const overlay = screen.getByTestId("watermark-overlay");
    expect(overlay.tagName.toLowerCase()).toBe("div");
    expect(overlay).toHaveTextContent("tenant-alpha / project-alpha / user-analyst");
    expect(container.querySelector(".watermarkOverlay__canvas")).toBeTruthy();
    expect(container.querySelector(".watermarkOverlay__vector")).toBeTruthy();
    expect(container.querySelectorAll(".watermarkOverlay__glyph")).toHaveLength(6);
  });

  it("frames content without rendering an overlay when watermark text is absent", () => {
    const { container } = render(
      <WatermarkFrame text={null} testId="watermark-overlay-empty">
        <section>protected content</section>
      </WatermarkFrame>
    );

    expect(screen.getByText("protected content")).toBeInTheDocument();
    expect(container.querySelector(".watermarkFrame")).toBeTruthy();
    expect(screen.queryByTestId("watermark-overlay-empty")).not.toBeInTheDocument();
  });
});
