import type { ReactNode } from "react";

export function WorkspaceRootShell({ children }: { children: ReactNode }) {
  return (
    <main className="workspace" data-testid="workspace-root-shell">
      <div className="workspace__backdrop" />
      <div className="workspace__content">{children}</div>
    </main>
  );
}
