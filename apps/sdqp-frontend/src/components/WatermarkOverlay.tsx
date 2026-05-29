import { useEffect, useId, useRef, type ReactNode } from "react";

type WatermarkTile = {
  id: string;
  label: string;
  x: number;
  y: number;
  rotation: number;
  opacity: number;
};

function hashText(value: string) {
  let hash = 2166136261;
  for (let index = 0; index < value.length; index += 1) {
    hash ^= value.charCodeAt(index);
    hash = Math.imul(hash, 16777619);
  }
  return hash >>> 0;
}

function compactLabel(text: string, index: number, seed: number) {
  const normalized = text.replace(/\s+/g, " ").trim();
  const head = normalized.slice(0, 12);
  const tail = normalized.slice(-6);
  const fragment = (seed + Math.imul(index + 1, 2654435761))
    .toString(36)
    .slice(-6)
    .toUpperCase();

  return `${head} ${fragment} ${tail}`;
}

function buildTiles(text: string, tileCount: number): WatermarkTile[] {
  const seed = hashText(text);
  const columns = Math.max(2, Math.round(Math.sqrt(tileCount * 1.5)));
  const rows = Math.max(1, Math.ceil(tileCount / columns));

  return Array.from({ length: tileCount }, (_, index) => {
    const column = index % columns;
    const row = Math.floor(index / columns);
    const jitterX = ((seed + index * 17) % 18) - 9;
    const jitterY = ((seed + index * 31) % 14) - 7;
    const x = ((column + 0.46) / columns) * 1000 + jitterX;
    const y = ((row + 0.54) / rows) * 1000 + jitterY;

    return {
      id: `${seed}-${index}`,
      label: compactLabel(text, index, seed),
      x,
      y,
      rotation: -32 + ((seed + index * 29) % 21),
      opacity: 0.038 + ((seed + index * 13) % 7) * 0.008
    };
  });
}

function drawCanvasLayer(
  canvas: HTMLCanvasElement,
  text: string,
  tileCount: number
) {
  const context = canvas.getContext("2d");
  if (
    !context ||
    typeof context.setTransform !== "function" ||
    typeof context.clearRect !== "function" ||
    typeof context.beginPath !== "function" ||
    typeof context.moveTo !== "function" ||
    typeof context.lineTo !== "function" ||
    typeof context.stroke !== "function" ||
    typeof context.fillRect !== "function" ||
    typeof context.fillText !== "function" ||
    typeof context.save !== "function" ||
    typeof context.restore !== "function" ||
    typeof context.translate !== "function" ||
    typeof context.rotate !== "function"
  ) {
    return;
  }

  const seed = hashText(text);
  const tiles = buildTiles(text, tileCount * 2);
  const rect = canvas.getBoundingClientRect();
  const width = Math.max(640, Math.round(rect.width || 1200));
  const height = Math.max(360, Math.round(rect.height || 780));
  const devicePixelRatio =
    typeof window === "undefined" ? 1 : window.devicePixelRatio || 1;

  canvas.width = Math.round(width * devicePixelRatio);
  canvas.height = Math.round(height * devicePixelRatio);
  context.setTransform(devicePixelRatio, 0, 0, devicePixelRatio, 0, 0);
  context.clearRect(0, 0, width, height);
  context.globalCompositeOperation = "multiply";

  context.strokeStyle = "rgba(164, 64, 48, 0.085)";
  context.lineWidth = 1;
  for (let index = -1; index < 8; index += 1) {
    const offset = ((index + 1) * width) / 7;
    context.beginPath();
    context.moveTo(offset - width * 0.2, 0);
    context.lineTo(offset + width * 0.25, height);
    context.stroke();
  }

  context.fillStyle = "rgba(164, 64, 48, 0.045)";
  for (let index = 0; index < 96; index += 1) {
    const x = ((seed + index * 97) % width) + 0.5;
    const y = ((seed + index * 53) % height) + 0.5;
    context.fillRect(x, y, 1.1, 1.1);
  }

  context.font =
    "600 14px \"IBM Plex Sans\", \"Segoe UI\", sans-serif";
  context.textAlign = "center";
  context.textBaseline = "middle";
  tiles.forEach((tile, index) => {
    context.save();
    context.translate((tile.x / 1000) * width, (tile.y / 1000) * height);
    context.rotate((tile.rotation * Math.PI) / 180);
    context.fillStyle =
      index % 2 === 0
        ? "rgba(164, 64, 48, 0.075)"
        : "rgba(92, 48, 42, 0.055)";
    context.fillText(tile.label, 0, 0);
    context.restore();
  });
}

export function WatermarkOverlay({
  text,
  tileCount = 12,
  testId
}: {
  text: string | null | undefined;
  tileCount?: number;
  testId?: string;
}) {
  const normalizedText = text?.trim() ?? "";
  const canvasRef = useRef<HTMLCanvasElement | null>(null);
  const patternId = useId().replace(/:/g, "-");

  const seed = hashText(normalizedText);
  const tiles = buildTiles(normalizedText, tileCount);

  useEffect(() => {
    if (!normalizedText) {
      return;
    }
    const canvas = canvasRef.current;
    if (!canvas) {
      return;
    }

    drawCanvasLayer(canvas, normalizedText, tileCount);
  }, [normalizedText, tileCount]);

  if (!normalizedText) {
    return null;
  }

  return (
    <div
      className="watermarkOverlay"
      aria-hidden="true"
      data-testid={testId}
      data-seed={seed}
    >
      <canvas
        ref={canvasRef}
        className="watermarkOverlay__canvas"
        data-seed={seed}
      />
      <svg
        className="watermarkOverlay__vector"
        viewBox="0 0 1000 1000"
        preserveAspectRatio="none"
      >
        <desc>{normalizedText}</desc>
        <defs>
          <pattern
            id={`${patternId}-pattern`}
            width="280"
            height="220"
            patternUnits="userSpaceOnUse"
            patternTransform={`rotate(${(seed % 9) - 18})`}
          >
            <text
              className="watermarkOverlay__band"
              x="36"
              y="112"
              opacity="0.12"
            >
              {compactLabel(normalizedText, 0, seed)}
            </text>
            <text
              className="watermarkOverlay__band"
              x="148"
              y="180"
              opacity="0.08"
            >
              {compactLabel(normalizedText, 1, seed)}
            </text>
          </pattern>
          <radialGradient id={`${patternId}-fade`} cx="50%" cy="50%" r="72%">
            <stop offset="0%" stopColor="rgba(255,255,255,0)" />
            <stop offset="82%" stopColor="rgba(255,255,255,0.02)" />
            <stop offset="100%" stopColor="rgba(255,255,255,0.1)" />
          </radialGradient>
        </defs>

        <rect
          x="0"
          y="0"
          width="1000"
          height="1000"
          fill={`url(#${patternId}-pattern)`}
          opacity="0.58"
        />

        {tiles.map((tile) => (
          <g
            key={tile.id}
            transform={`rotate(${tile.rotation} ${tile.x} ${tile.y})`}
          >
            <text
              className="watermarkOverlay__glyph"
              x={tile.x}
              y={tile.y}
              opacity={tile.opacity}
            >
              {tile.label}
            </text>
            <circle
              className="watermarkOverlay__microdot"
              cx={tile.x + 68}
              cy={tile.y - 14}
              r="1.4"
              opacity={Math.min(tile.opacity + 0.05, 0.16)}
            />
          </g>
        ))}

        <rect
          x="0"
          y="0"
          width="1000"
          height="1000"
          fill={`url(#${patternId}-fade)`}
          opacity="0.62"
        />
      </svg>
    </div>
  );
}

export function WatermarkFrame({
  text,
  children,
  tileCount,
  testId
}: {
  text: string | null | undefined;
  children: ReactNode;
  tileCount?: number;
  testId?: string;
}) {
  return (
    <div className="watermarkFrame">
      <div className="watermarkFrame__content">{children}</div>
      <WatermarkOverlay text={text} tileCount={tileCount} testId={testId} />
    </div>
  );
}
