import { describe, expect, it } from "vitest";
import { resolveApiBaseUrl } from "./api";

describe("frontend api configuration", () => {
  it("uses same-origin requests when no api base url is configured", () => {
    expect(resolveApiBaseUrl({})).toBe("");
  });

  it("normalizes an explicitly configured api base url", () => {
    expect(resolveApiBaseUrl({ VITE_SDQP_API_BASE_URL: "http://localhost:8080/" })).toBe(
      "http://localhost:8080"
    );
  });
});
