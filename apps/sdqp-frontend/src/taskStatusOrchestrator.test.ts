import { afterEach, describe, expect, it, vi } from "vitest";
import type { FrontendClient, QueryTaskStatus } from "./api";
import { observeTaskStatus } from "./taskStatusOrchestrator";

function createTaskStatus(status: Partial<QueryTaskStatus> & Pick<QueryTaskStatus, "state">): QueryTaskStatus {
  return {
    task_id: "task-a",
    state: status.state,
    snapshot_id: status.snapshot_id ?? null,
    cache_hit: status.cache_hit ?? false,
    error: status.error ?? null
  };
}

function createClient(overrides?: Partial<Pick<FrontendClient, "getTaskStatus" | "streamTaskStatus">>) {
  return {
    getTaskStatus: vi.fn(),
    streamTaskStatus: vi.fn().mockReturnValue({
      close: vi.fn()
    }),
    ...overrides
  };
}

describe("taskStatusOrchestrator", () => {
  afterEach(() => {
    vi.useRealTimers();
  });

  it("subscribes to the task stream and forwards streamed status updates", async () => {
    const close = vi.fn();
    let streamOptions:
      | Parameters<FrontendClient["streamTaskStatus"]>[1]
      | undefined;
    const client = createClient({
      streamTaskStatus: vi.fn().mockImplementation((_taskId, options) => {
        streamOptions = options;
        return { close };
      })
    });
    const onStatus = vi.fn();

    const subscription = observeTaskStatus({
      client,
      taskId: "task-a",
      streamPath: "/v1/tasks/task-a/ws",
      pollIntervalMs: 50,
      onStatus
    });

    expect(client.streamTaskStatus).toHaveBeenCalledWith(
      "task-a",
      expect.objectContaining({ path: "/v1/tasks/task-a/ws", replayLast: true })
    );

    const running = createTaskStatus({ state: "running" });
    const completed = createTaskStatus({ state: "completed", snapshot_id: "snapshot-a" });

    streamOptions?.onStatus(running);
    streamOptions?.onStatus(completed);
    await Promise.resolve();

    expect(onStatus).toHaveBeenNthCalledWith(1, running);
    expect(onStatus).toHaveBeenNthCalledWith(2, completed);

    streamOptions?.onError?.(new Error("socket closed after completion"));
    expect(client.getTaskStatus).not.toHaveBeenCalled();

    subscription.close();
    expect(close).toHaveBeenCalledTimes(1);
  });

  it("falls back to polling when the websocket stream reports an error", async () => {
    vi.useFakeTimers();

    const onStatus = vi.fn();
    const onPollingFallback = vi.fn();
    const onPollingError = vi.fn();
    const client = createClient({
      streamTaskStatus: vi.fn().mockImplementation((_taskId, options) => {
        options.onError?.(new Error("socket unavailable"));
        return {
          close: vi.fn()
        };
      }),
      getTaskStatus: vi
        .fn()
        .mockResolvedValueOnce(createTaskStatus({ state: "running" }))
        .mockResolvedValueOnce(createTaskStatus({ state: "completed", snapshot_id: "snapshot-a" }))
    });

    observeTaskStatus({
      client,
      taskId: "task-a",
      pollIntervalMs: 10,
      onStatus,
      onPollingFallback,
      onPollingError
    });

    await Promise.resolve();
    await Promise.resolve();

    expect(onPollingFallback).toHaveBeenCalledTimes(1);
    expect(onPollingError).not.toHaveBeenCalled();
    expect(client.getTaskStatus).toHaveBeenCalledTimes(1);
    expect(onStatus).toHaveBeenNthCalledWith(1, createTaskStatus({ state: "running" }));

    await vi.advanceTimersByTimeAsync(10);

    expect(client.getTaskStatus).toHaveBeenCalledTimes(2);
    expect(onStatus).toHaveBeenNthCalledWith(
      2,
      createTaskStatus({ state: "completed", snapshot_id: "snapshot-a" })
    );

    await vi.advanceTimersByTimeAsync(20);
    expect(client.getTaskStatus).toHaveBeenCalledTimes(2);
  });

  it("cancels the polling loop when the controller is closed", async () => {
    vi.useFakeTimers();

    const close = vi.fn();
    const client = createClient({
      streamTaskStatus: vi.fn().mockImplementation((_taskId, options) => {
        options.onError?.(new Error("socket unavailable"));
        return { close };
      }),
      getTaskStatus: vi.fn().mockResolvedValue(createTaskStatus({ state: "running" }))
    });
    const onStatus = vi.fn();

    const subscription = observeTaskStatus({
      client,
      taskId: "task-a",
      pollIntervalMs: 10,
      onStatus
    });

    await Promise.resolve();
    await Promise.resolve();
    expect(client.getTaskStatus).toHaveBeenCalledTimes(1);

    subscription.close();
    await vi.advanceTimersByTimeAsync(20);

    expect(client.getTaskStatus).toHaveBeenCalledTimes(1);
    expect(close).toHaveBeenCalledTimes(1);
  });
});
