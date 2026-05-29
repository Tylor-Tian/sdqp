import type { ComponentProps } from "react";
import {
  AuthenticatedWorkspaceComposition,
  type AuthenticatedWorkspaceCompositionProps
} from "./AuthenticatedWorkspaceComposition";
import { ConsoleContentShell } from "./ConsoleContentShell";
import { ConsoleHeroPanel } from "./ConsoleHeroPanel";
import { MfaChallengePanel } from "./MfaChallengePanel";
import { SecurityNoticeBanner } from "./SecurityNoticeBanner";

export type ConsoleContentCompositionProps = {
  heroPanelProps: ComponentProps<typeof ConsoleHeroPanel>;
  securityNoticeBannerProps: ComponentProps<typeof SecurityNoticeBanner>;
  mfaChallengePanelProps: ComponentProps<typeof MfaChallengePanel>;
} & AuthenticatedWorkspaceCompositionProps;

export function ConsoleContentComposition({
  heroPanelProps,
  securityNoticeBannerProps,
  mfaChallengePanelProps,
  ...authenticatedWorkspaceCompositionProps
}: ConsoleContentCompositionProps) {
  return (
    <ConsoleContentShell
      heroPanel={<ConsoleHeroPanel {...heroPanelProps} />}
      securityNoticeBanner={<SecurityNoticeBanner {...securityNoticeBannerProps} />}
      mfaChallengePanel={<MfaChallengePanel {...mfaChallengePanelProps} />}
      authenticatedWorkspace={
        <AuthenticatedWorkspaceComposition {...authenticatedWorkspaceCompositionProps} />
      }
    />
  );
}
