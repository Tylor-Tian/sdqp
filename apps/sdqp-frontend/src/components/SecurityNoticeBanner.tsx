export function SecurityNoticeBanner({
  notice
}: {
  notice:
    | {
        kind: "timeout" | "step-up" | "failure";
        title: string;
        body: string;
      }
    | null;
}) {
  if (!notice) {
    return null;
  }

  return (
    <section
      className={
        notice.kind === "timeout"
          ? "securityBanner securityBanner--timeout"
          : "securityBanner securityBanner--warning"
      }
      role="alert"
    >
      <div>
        <p className="securityBanner__title">{notice.title}</p>
        <p className="securityBanner__body">{notice.body}</p>
      </div>
    </section>
  );
}
