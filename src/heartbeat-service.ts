import fs from "node:fs/promises";
import type { AuditLedger } from "./audit-ledger";

interface HeartbeatTask {
  id: string;
  enabled: boolean;
  interval_seconds: number;
  description?: string;
}

interface HeartbeatTaskFile {
  tasks: HeartbeatTask[];
}

interface RuntimeTask extends HeartbeatTask {
  nextRunAtMs: number;
}

export interface HeartbeatOptions {
  intervalSeconds: number;
  tasksPath: string;
}

export class HeartbeatService {
  private options: HeartbeatOptions;
  private ledger: AuditLedger;
  private timer: NodeJS.Timeout | null = null;
  private tasks = new Map<string, RuntimeTask>();

  constructor(options: HeartbeatOptions, ledger: AuditLedger) {
    this.options = options;
    this.ledger = ledger;
  }

  async start(): Promise<void> {
    await this.loadTasks();
    const intervalMs = Math.max(5, this.options.intervalSeconds) * 1000;
    this.timer = setInterval(() => {
      void this.tick();
    }, intervalMs);
    await this.tick();
  }

  async stop(): Promise<void> {
    if (this.timer) {
      clearInterval(this.timer);
      this.timer = null;
    }
  }

  private async loadTasks(): Promise<void> {
    try {
      const raw = await fs.readFile(this.options.tasksPath, "utf8");
      const parsed = JSON.parse(raw) as HeartbeatTaskFile;
      const now = Date.now();
      this.tasks.clear();
      for (const task of parsed.tasks || []) {
        if (!task.id || task.interval_seconds <= 0) {
          continue;
        }
        this.tasks.set(task.id, {
          ...task,
          nextRunAtMs: now + task.interval_seconds * 1000,
        });
      }
    } catch {
      // Missing/invalid file is non-fatal; heartbeat still runs.
      this.tasks.clear();
    }
  }

  private async tick(): Promise<void> {
    const now = Date.now();
    this.ledger.logAndSignAction("HEARTBEAT_TICK", {
      timestamp: new Date(now).toISOString(),
      task_count: this.tasks.size,
    });

    for (const task of this.tasks.values()) {
      if (!task.enabled) {
        continue;
      }
      if (now < task.nextRunAtMs) {
        continue;
      }

      this.ledger.logAndSignAction("HEARTBEAT_TASK_DUE", {
        task_id: task.id,
        description: task.description || "",
        due_at: new Date(now).toISOString(),
      });
      task.nextRunAtMs = now + task.interval_seconds * 1000;
    }
  }
}
