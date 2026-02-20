export interface AlertPayload {
  event: string;
  severity: "info" | "warning" | "critical";
  message: string;
  details?: Record<string, unknown>;
}

export interface AlertNotifierOptions {
  webhookUrl?: string;
  minIntervalMs?: number;
}

export class AlertNotifier {
  private webhookUrl: string | null;
  private minIntervalMs: number;
  private lastSentByEvent = new Map<string, number>();

  constructor(options: AlertNotifierOptions) {
    this.webhookUrl = options.webhookUrl?.trim() || null;
    this.minIntervalMs = Math.max(1000, options.minIntervalMs ?? 60_000);
  }

  async send(payload: AlertPayload): Promise<void> {
    if (!this.webhookUrl) {
      return;
    }

    const now = Date.now();
    const last = this.lastSentByEvent.get(payload.event) ?? 0;
    if (now - last < this.minIntervalMs) {
      return;
    }
    this.lastSentByEvent.set(payload.event, now);

    const body = {
      timestamp: new Date().toISOString(),
      ...payload,
    };

    const response = await fetch(this.webhookUrl, {
      method: "POST",
      headers: {
        "content-type": "application/json",
      },
      body: JSON.stringify(body),
    });

    if (!response.ok) {
      throw new Error(`Alert webhook failed: ${response.status} ${response.statusText}`);
    }
  }
}
