import { useEffect, useEffectEvent, useRef } from "react";
import type { SnapshotPage } from "../api";

function CanvasTextCell({
  fieldName,
  value,
  masked
}: {
  fieldName: string;
  value: string;
  masked: boolean;
}) {
  const ref = useRef<HTMLCanvasElement | null>(null);
  const paintCanvas = useEffectEvent(() => {
    const canvas = ref.current;
    if (!canvas) {
      return;
    }

    const context = canvas.getContext("2d");
    if (!context) {
      return;
    }

    const width = 196;
    const height = 30;
    const ratio = window.devicePixelRatio || 1;
    canvas.width = width * ratio;
    canvas.height = height * ratio;
    canvas.style.width = `${width}px`;
    canvas.style.height = `${height}px`;
    context.setTransform(ratio, 0, 0, ratio, 0, 0);
    context.clearRect(0, 0, width, height);
    context.fillStyle = masked ? "#8b5c13" : "#18222d";
    context.font = masked ? "700 13px Aptos" : "600 13px Aptos";
    context.fillText(value, 4, 19);
  });

  useEffect(() => {
    paintCanvas();
  }, [paintCanvas, value]);

  return <canvas ref={ref} className="canvasCell" aria-label={`${fieldName} canvas cell`} />;
}

export function DetailView({ snapshotPage }: { snapshotPage: SnapshotPage }) {
  return (
    <div className="tableFrame" data-testid="detail-view">
      <table>
        <thead>
          <tr>
            {snapshotPage.columns.map((column) => (
              <th key={column}>{column}</th>
            ))}
          </tr>
        </thead>
        <tbody>
          {snapshotPage.rows.map((row, rowIndex) => (
            <tr key={`row-${rowIndex}`}>
              {snapshotPage.columns.map((column) => {
                const policy = snapshotPage.field_policies.find(
                  (candidate) => candidate.field_name === column
                );
                return (
                  <td key={`${rowIndex}-${column}`}>
                    <CanvasTextCell
                      fieldName={column}
                      value={row[column] ?? "-"}
                      masked={Boolean(policy?.masked)}
                    />
                  </td>
                );
              })}
            </tr>
          ))}
        </tbody>
      </table>
    </div>
  );
}
