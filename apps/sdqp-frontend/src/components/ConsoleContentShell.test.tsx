import { render, screen } from "@testing-library/react";
import { describe, expect, it } from "vitest";
import { ConsoleContentShell } from "./ConsoleContentShell";

describe("ConsoleContentShell", () => {
  it("renders the dedicated console content shell and preserves hero/banner/mfa/workspace ordering", () => {
    render(
      <ConsoleContentShell
        heroPanel={<div data-testid="hero-slot">hero</div>}
        securityNoticeBanner={<div data-testid="banner-slot">banner</div>}
        mfaChallengePanel={<div data-testid="mfa-slot">mfa</div>}
        authenticatedWorkspace={<div data-testid="workspace-slot">workspace</div>}
      />
    );

    const shell = screen.getByTestId("console-content-shell");
    expect(shell).toBeInTheDocument();
    expect(screen.getByTestId("hero-slot")).toBeInTheDocument();
    expect(screen.getByTestId("banner-slot")).toBeInTheDocument();
    expect(screen.getByTestId("mfa-slot")).toBeInTheDocument();
    expect(screen.getByTestId("workspace-slot")).toBeInTheDocument();
    expect(shell.firstChild).toBe(screen.getByTestId("hero-slot"));
    expect(shell.lastChild).toBe(screen.getByTestId("workspace-slot"));
  });

  it("omits the workspace when the authenticated shell is absent", () => {
    render(
      <ConsoleContentShell
        heroPanel={<div data-testid="hero-slot">hero</div>}
        securityNoticeBanner={<div data-testid="banner-slot">banner</div>}
        mfaChallengePanel={<div data-testid="mfa-slot">mfa</div>}
        authenticatedWorkspace={null}
      />
    );

    expect(screen.getByTestId("console-content-shell")).toBeInTheDocument();
    expect(screen.queryByTestId("workspace-slot")).not.toBeInTheDocument();
  });
});
