export function ConsoleHeroPanel({
  personaKey,
  personas,
  challengePending,
  hasSession,
  statusMessage,
  isHydrating,
  onPersonaKeyChange,
  onStartLogin,
  onCompleteMfa,
  onRefreshSession
}: {
  personaKey: string;
  personas: Array<{
    key: string;
    username: string;
    label: string;
    mfaCode: string;
  }>;
  challengePending: boolean;
  hasSession: boolean;
  statusMessage: string;
  isHydrating: boolean;
  onPersonaKeyChange: (value: string) => void;
  onStartLogin: () => void;
  onCompleteMfa: () => void;
  onRefreshSession: () => void;
}) {
  return (
    <section className="heroPanel">
      <p className="heroPanel__eyebrow">Prod Stage 12</p>
      <h1 className="heroPanel__title">SDQP Operations Console</h1>
      <p className="heroPanel__body">
        Operate access, projects, permissions, approvals, queries, audit, UEBA, and evidence export from one console.
      </p>
      <div className="formGrid">
        <label className="formField">
          <span>Persona</span>
          <select
            className="textInput"
            aria-label="Persona"
            value={personaKey}
            onChange={(event) => onPersonaKeyChange(event.target.value)}
          >
            {personas.map((item) => (
              <option key={item.key} value={item.key}>
                {item.key}
              </option>
            ))}
          </select>
        </label>
      </div>
      <div className="toolbar">
        <button
          className="button button--primary"
          type="button"
          disabled={isHydrating}
          onClick={onStartLogin}
        >
          Start Login
        </button>
        {challengePending ? (
          <button
            className="button button--secondary"
            type="button"
            disabled={isHydrating}
            onClick={onCompleteMfa}
          >
            Complete MFA
          </button>
        ) : null}
        {hasSession ? (
          <button
            className="button button--ghost"
            type="button"
            disabled={isHydrating}
            onClick={onRefreshSession}
          >
            Refresh Session
          </button>
        ) : null}
      </div>
      <p className="inlineNotice" role="status">
        {statusMessage}
      </p>
    </section>
  );
}
