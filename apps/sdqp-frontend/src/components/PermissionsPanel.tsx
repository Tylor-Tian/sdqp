import type { PermissionApplication, PermissionGrantsResponse } from "../api";

export function PermissionsPanel({
  isHydrating,
  permissionApplication,
  permissionGrants,
  onSubmitPermissionRequest
}: {
  isHydrating: boolean;
  permissionApplication: PermissionApplication | null;
  permissionGrants: PermissionGrantsResponse["grants"];
  onSubmitPermissionRequest: () => void;
}) {
  return (
    <section className="surfacePanel">
      <h2 className="surfacePanel__title">Permissions</h2>
      <div className="toolbar">
        <button
          className="button button--primary"
          type="button"
          disabled={isHydrating}
          onClick={onSubmitPermissionRequest}
        >
          Submit Permission Request
        </button>
      </div>
      {permissionApplication ? <p className="inlineNotice">{permissionApplication.application_id}</p> : null}
      <div className="stackList">
        {permissionGrants.map((grant) => (
          <article className="listCard" key={grant.grant_id}>
            <strong>{grant.grant_id}</strong>
            <p>{grant.fields.join(", ")}</p>
          </article>
        ))}
      </div>
    </section>
  );
}
