import { render, screen } from "@testing-library/react";
import { describe, expect, it } from "vitest";
import { WorkspaceRootShell } from "./WorkspaceRootShell";

describe("WorkspaceRootShell", () => {
  it("renders the dedicated workspace chrome and nests children inside the content surface", () => {
    render(
      <WorkspaceRootShell>
        <div data-testid="content-slot">content</div>
      </WorkspaceRootShell>
    );

    const shell = screen.getByTestId("workspace-root-shell");
    const backdrop = shell.querySelector(".workspace__backdrop");
    const content = shell.querySelector(".workspace__content");

    expect(shell.tagName).toBe("MAIN");
    expect(backdrop).not.toBeNull();
    expect(content).not.toBeNull();
    expect(shell.firstChild).toBe(backdrop);
    expect(shell.lastChild).toBe(content);
    expect(content?.firstChild).toBe(screen.getByTestId("content-slot"));
  });
});
