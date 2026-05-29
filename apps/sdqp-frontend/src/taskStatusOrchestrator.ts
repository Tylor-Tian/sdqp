import type {
  FrontendClient,
  QueryTaskStatus,
  TaskStatusStreamSubscription
} from "./api";

type TaskStatusClient = Pick<FrontendClient, "getTaskStatus" | "streamTaskStatus">;

export type ObserveTaskStatusOptions = {
  client: TaskStatusClient;
  taskId: string;
  streamPath?: string;
  pollIntervalMs: number;
  onStatus: (status: QueryTaskStatus) => void | Promise<void>;
  onPollingFallback?: () => void;
  onPollingError?: (error: unknown) => void;
};

export function isTerminalTaskState(status: string) {
  return status === "completed" || status === "failed" || status === "cancelled";
}

export function observeTaskStatus({
  client,
  taskId,
  streamPath,
  pollIntervalMs,
  onStatus,
  onPollingFallback,
  onPollingError
}: ObserveTaskStatusOptions): TaskStatusStreamSubscription {
  let disposed = false;
  let timer = 0;
  let terminal = false;
  let polling = false;

  const applyNextTask = async (nextTask: QueryTaskStatus) => {
    terminal = isTerminalTaskState(nextTask.state);
    await onStatus(nextTask);
  };

  const loop = async () => {
    if (disposed || terminal) {
      return;
    }

    try {
      const nextTask = await client.getTaskStatus(taskId);
      if (disposed) {
        return;
      }
      await applyNextTask(nextTask);
      if (!disposed && !terminal) {
        timer = window.setTimeout(() => {
          void loop();
        }, pollIntervalMs);
      }
    } catch (error) {
      if (!disposed) {
        onPollingError?.(error);
      }
    }
  };

  const startPollingFallback = () => {
    if (disposed || terminal || polling) {
      return;
    }
    polling = true;
    onPollingFallback?.();
    void loop();
  };

  let subscription: TaskStatusStreamSubscription | null = null;
  try {
    subscription = client.streamTaskStatus(taskId, {
      path: streamPath,
      replayLast: true,
      onStatus: (nextTask) => {
        void applyNextTask(nextTask);
      },
      onError: () => {
        startPollingFallback();
      }
    });
  } catch {
    startPollingFallback();
  }

  return {
    close() {
      disposed = true;
      window.clearTimeout(timer);
      subscription?.close();
    }
  };
}
