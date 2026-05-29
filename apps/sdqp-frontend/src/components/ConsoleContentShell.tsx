import type { ReactNode } from "react";

export function ConsoleContentShell({
  heroPanel,
  securityNoticeBanner,
  mfaChallengePanel,
  authenticatedWorkspace
}: {
  heroPanel: ReactNode;
  securityNoticeBanner: ReactNode;
  mfaChallengePanel: ReactNode;
  authenticatedWorkspace: ReactNode;
}) {
  return (
    <div data-testid="console-content-shell">
      {heroPanel}
      {securityNoticeBanner}
      {mfaChallengePanel}
      {authenticatedWorkspace}
    </div>
  );
}
