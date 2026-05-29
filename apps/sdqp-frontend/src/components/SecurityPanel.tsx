export function SecurityPanel({
  isHydrating,
  riskResult,
  onEvaluateDevicePosture,
  onCompleteStepUp
}: {
  isHydrating: boolean;
  riskResult: { required: boolean; action: string; challenge?: { method: string } | null } | null;
  onEvaluateDevicePosture: () => void;
  onCompleteStepUp: () => void;
}) {
  return (
    <section className="surfacePanel">
      <h2 className="surfacePanel__title">Security</h2>
      <div className="toolbar">
        <button
          className="button button--primary"
          type="button"
          disabled={isHydrating}
          onClick={onEvaluateDevicePosture}
        >
          Evaluate Device Posture
        </button>
        {riskResult?.required ? (
          <button
            className="button button--secondary"
            type="button"
            disabled={isHydrating}
            onClick={onCompleteStepUp}
          >
            Complete Step-Up
          </button>
        ) : null}
      </div>
      {riskResult ? (
        <p className="inlineNotice">
          {riskResult.required
            ? `Step-Up Required${riskResult.challenge?.method ? ` (${riskResult.challenge.method})` : ""}`
            : riskResult.action}
        </p>
      ) : null}
    </section>
  );
}
