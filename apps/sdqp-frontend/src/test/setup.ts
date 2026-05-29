import "@testing-library/jest-dom/vitest";
import { cleanup } from "@testing-library/react";
import { afterEach, vi } from "vitest";

Object.defineProperty(HTMLCanvasElement.prototype, "getContext", {
  configurable: true,
  value: vi.fn(() => ({
    setTransform: vi.fn(),
    clearRect: vi.fn(),
    fillText: vi.fn(),
    fillStyle: "",
    font: ""
  }))
});

afterEach(() => {
  cleanup();
});
