import type { ApprovalTask } from "../api";

export function ApprovalQueuePanel({
  isHydrating,
  approvalTasks,
  approvalMessage,
  onLoadApprovalQueue,
  onDelegateApproval
}: {
  isHydrating: boolean;
  approvalTasks: ApprovalTask[];
  approvalMessage: string;
  onLoadApprovalQueue: () => void;
  onDelegateApproval: (instanceId: string) => void;
}) {
  return (
    <section className="surfacePanel">
      <h2 className="surfacePanel__title">Approvals</h2>
      <div className="toolbar">
        <button
          className="button button--primary"
          type="button"
          disabled={isHydrating}
          onClick={onLoadApprovalQueue}
        >
          Load Approval Queue
        </button>
      </div>
      <div className="stackList">
        {approvalTasks.map((item) => (
          <article className="listCard" key={item.instance_id}>
            <strong>{item.instance_id}</strong>
            <p>{item.data_source_id}</p>
            <button
              className="button button--ghost"
              type="button"
              disabled={isHydrating}
              onClick={() => onDelegateApproval(item.instance_id)}
            >
              Delegate
            </button>
          </article>
        ))}
      </div>
      {approvalMessage ? <p className="inlineNotice">{approvalMessage}</p> : null}
    </section>
  );
}
