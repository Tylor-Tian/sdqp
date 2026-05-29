import { render, screen } from "@testing-library/react";
import type { ComponentProps } from "react";
import { describe, expect, it, vi } from "vitest";
import {
  ConsoleContentComposition,
  type ConsoleContentCompositionProps
} from "./ConsoleContentComposition";
import { ConsoleHeroPanel } from "./ConsoleHeroPanel";
import { MfaChallengePanel } from "./MfaChallengePanel";
import { SecurityNoticeBanner } from "./SecurityNoticeBanner";

vi.mock("./ConsoleHeroPanel", () => ({
  ConsoleHeroPanel: () => <div data-testid="console-hero-panel">hero</div>
}));

vi.mock("./SecurityNoticeBanner", () => ({
  SecurityNoticeBanner: () => <div data-testid="security-notice-banner">banner</div>
}));

vi.mock("./MfaChallengePanel", () => ({
  MfaChallengePanel: () => <div data-testid="mfa-challenge-panel">mfa</div>
}));

vi.mock("./AuthenticatedWorkspaceComposition", () => ({
  AuthenticatedWorkspaceComposition: ({ showWorkspace }: { showWorkspace: boolean }) =>
    showWorkspace ? <div data-testid="authenticated-workspace-composition">workspace</div> : null
}));

function buildProps(): ConsoleContentCompositionProps {
  return {
    heroPanelProps: {} as ComponentProps<typeof ConsoleHeroPanel>,
    securityNoticeBannerProps: {} as ComponentProps<typeof SecurityNoticeBanner>,
    mfaChallengePanelProps: {} as ComponentProps<typeof MfaChallengePanel>,
    showWorkspace: true,
    projectControlPanelProps: {} as ConsoleContentCompositionProps["projectControlPanelProps"],
    permissionsPanelProps: {} as ConsoleContentCompositionProps["permissionsPanelProps"],
    securityPanelProps: {} as ConsoleContentCompositionProps["securityPanelProps"],
    approvalQueuePanelProps: {} as ConsoleContentCompositionProps["approvalQueuePanelProps"],
    queryWorkbenchPanelProps: {} as ConsoleContentCompositionProps["queryWorkbenchPanelProps"],
    uebaAuditPanelProps: {} as ConsoleContentCompositionProps["uebaAuditPanelProps"],
    detailPagePanelProps: {} as ConsoleContentCompositionProps["detailPagePanelProps"],
    analysisTemplatesPanelProps: {} as ConsoleContentCompositionProps["analysisTemplatesPanelProps"],
    evidenceExportPanelProps: {} as ConsoleContentCompositionProps["evidenceExportPanelProps"]
  };
}

describe("ConsoleContentComposition", () => {
  it("renders the dedicated console-content composition through the existing shell surface", () => {
    render(<ConsoleContentComposition {...buildProps()} />);

    expect(screen.getByTestId("console-content-shell")).toBeInTheDocument();
    expect(screen.getByTestId("console-hero-panel")).toBeInTheDocument();
    expect(screen.getByTestId("security-notice-banner")).toBeInTheDocument();
    expect(screen.getByTestId("mfa-challenge-panel")).toBeInTheDocument();
    expect(screen.getByTestId("authenticated-workspace-composition")).toBeInTheDocument();
  });

  it("omits the authenticated workspace when the composition is still pre-workspace", () => {
    render(<ConsoleContentComposition {...buildProps()} showWorkspace={false} />);

    expect(screen.getByTestId("console-content-shell")).toBeInTheDocument();
    expect(screen.getByTestId("console-hero-panel")).toBeInTheDocument();
    expect(screen.getByTestId("security-notice-banner")).toBeInTheDocument();
    expect(screen.getByTestId("mfa-challenge-panel")).toBeInTheDocument();
    expect(screen.queryByTestId("authenticated-workspace-composition")).not.toBeInTheDocument();
  });
});
