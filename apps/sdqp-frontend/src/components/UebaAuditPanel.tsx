import type { UebaAlerts, UebaBaselines } from "../api";
import type { AuditViewSummary } from "../analysisEvidenceController";

export function UebaAuditPanel({
  isHydrating,
  alerts,
  baselines,
  auditAction,
  auditActionOptions,
  auditLimit,
  auditLimitOptions,
  auditView,
  onAuditActionChange,
  onAuditLimitChange,
  onLoadAuditView
}: {
  isHydrating: boolean;
  alerts: UebaAlerts | null;
  baselines: UebaBaselines | null;
  auditAction: string;
  auditActionOptions: Array<{
    value: string;
    label: string;
  }>;
  auditLimit: number;
  auditLimitOptions: number[];
  auditView: AuditViewSummary | null;
  onAuditActionChange: (value: string) => void;
  onAuditLimitChange: (value: number) => void;
  onLoadAuditView: () => void;
}) {
  return (
    <section className="surfacePanel">
      <h2 className="surfacePanel__title">UEBA</h2>
      <div className="sessionSummary">
        <article className="metricPanel">
          <p className="metricPanel__label">Alerts</p>
          <p className="metricPanel__value">{alerts?.alerts.length ?? 0}</p>
        </article>
        <article className="metricPanel">
          <p className="metricPanel__label">Baselines</p>
          <p className="metricPanel__value">{baselines?.entity_baselines.length ?? 0}</p>
        </article>
      </div>
      <div className="formGrid">
        <label className="formField">
          <span>Audit Action</span>
          <select
            className="textInput"
            aria-label="Audit Action"
            value={auditAction}
            disabled={isHydrating}
            onChange={(event) => onAuditActionChange(event.target.value)}
          >
            {auditActionOptions.map((option) => (
              <option key={option.label} value={option.value}>
                {option.label}
              </option>
            ))}
          </select>
        </label>
        <label className="formField">
          <span>Audit Limit</span>
          <select
            className="textInput"
            aria-label="Audit Limit"
            value={String(auditLimit)}
            disabled={isHydrating}
            onChange={(event) => onAuditLimitChange(Number(event.target.value))}
          >
            {auditLimitOptions.map((option) => (
              <option key={option} value={option}>
                {option}
              </option>
            ))}
          </select>
        </label>
      </div>
      <button
        className="button button--ghost"
        type="button"
        disabled={isHydrating}
        onClick={onLoadAuditView}
      >
        Load Audit View
      </button>
      {auditView ? (
        <>
          <div className="sessionSummary">
            <article className="metricPanel">
              <p className="metricPanel__label">Matches</p>
              <p className="metricPanel__value">{auditView.totalMatches}</p>
            </article>
            <article className="metricPanel">
              <p className="metricPanel__label">Chain</p>
              <p className="metricPanel__value">{auditView.chainValid ? "Valid" : "Invalid"}</p>
            </article>
          </div>
          <div className="stackList">
            <article className="listCard">
              <strong>Audit Match Summary</strong>
              <p>{`${auditView.totalMatches} matches / ${auditView.actionLabel} / limit ${auditView.limit}`}</p>
            </article>
            {auditView.events.map((event) => (
              <article className="listCard" key={event.eventId}>
                <strong>{`${event.action} / ${event.result}`}</strong>
                <p>{`${event.actorUserId} / ${event.resourceId}`}</p>
                <p>{event.context}</p>
              </article>
            ))}
          </div>
        </>
      ) : null}
    </section>
  );
}
