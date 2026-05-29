import type { MfaChallengeDetails } from "../api";

export function MfaChallengePanel({
  challenge
}: {
  challenge:
    | {
        pendingSessionId: string;
        method: string;
        details?: MfaChallengeDetails | null;
        kind?: "login" | "step-up";
      }
    | null;
}) {
  if (!challenge) {
    return null;
  }
  const title = challenge.kind === "step-up" ? "Step-Up Challenge" : "MFA Challenge";

  return (
    <section className="surfacePanel">
      <h2 className="surfacePanel__title">{title}</h2>
      <p className="surfacePanel__body">{`${challenge.pendingSessionId} / ${challenge.method}`}</p>
      {challenge.details?.reason ? (
        <p className="inlineNotice">{challenge.details.reason}</p>
      ) : null}
      {challenge.details?.webauthnRequest ? (
        <p className="surfacePanel__body">Security key verification will run in the browser.</p>
      ) : null}
    </section>
  );
}
