import type { ProjectsResponse } from "../api";

export function ProjectControlPanel({
  isHydrating,
  projectId,
  projects,
  projectStateMessage,
  onSwitchProject,
  onFreezeProject
}: {
  isHydrating: boolean;
  projectId: string;
  projects: ProjectsResponse["projects"];
  projectStateMessage: string;
  onSwitchProject: (projectId: string) => void;
  onFreezeProject: (projectId: string) => void;
}) {
  return (
    <section className="surfacePanel">
      <h2 className="surfacePanel__title">Project Control</h2>
      <p className="surfacePanel__body">{`current project ${projectId || "-"}`}</p>
      <div className="projectCatalog">
        {projects.map((project) => (
          <article
            className={
              project.project_id === projectId ? "projectCard projectCard--active" : "projectCard"
            }
            key={project.project_id}
          >
            <strong>{project.project_id}</strong>
            <p className="helperText">{project.state}</p>
            <div className="toolbar">
              <button
                className="button button--ghost"
                type="button"
                disabled={isHydrating}
                onClick={() => onSwitchProject(project.project_id)}
              >
                Switch Project
              </button>
              <button
                className="button button--ghost"
                type="button"
                disabled={isHydrating}
                onClick={() => onFreezeProject(project.project_id)}
              >
                Freeze Project
              </button>
            </div>
          </article>
        ))}
      </div>
      {projectStateMessage ? <p className="inlineNotice">{projectStateMessage}</p> : null}
    </section>
  );
}
