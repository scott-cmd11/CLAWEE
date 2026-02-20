import { InteractionStore } from "./interaction-store";

export type ReplayStoreMode = "sqlite" | "redis";

export interface ReplayStore {
  mode(): ReplayStoreMode;
  warmup(): Promise<void>;
  registerNonce(nonceHash: string, ttlSeconds: number): Promise<boolean>;
  registerEventKey(eventKeyHash: string, ttlSeconds: number): Promise<boolean>;
  getState(): Record<string, unknown>;
  close(): Promise<void>;
}

export interface ReplayStoreConfig {
  mode: ReplayStoreMode;
  redisUrl: string;
  redisPrefix: string;
}

class SqliteReplayStore implements ReplayStore {
  private interactionStore: InteractionStore;

  constructor(interactionStore: InteractionStore) {
    this.interactionStore = interactionStore;
  }

  mode(): ReplayStoreMode {
    return "sqlite";
  }

  async warmup(): Promise<void> {
    return;
  }

  async registerNonce(nonceHash: string, ttlSeconds: number): Promise<boolean> {
    return this.interactionStore.registerIngressNonce(nonceHash, ttlSeconds);
  }

  async registerEventKey(eventKeyHash: string, ttlSeconds: number): Promise<boolean> {
    return this.interactionStore.registerIngressEventKey(eventKeyHash, ttlSeconds);
  }

  getState(): Record<string, unknown> {
    return { mode: "sqlite" };
  }

  async close(): Promise<void> {
    return;
  }
}

class RedisReplayStore implements ReplayStore {
  private redisUrl: string;
  private redisPrefix: string;
  private client: any | null = null;

  constructor(redisUrl: string, redisPrefix: string) {
    this.redisUrl = redisUrl.trim();
    this.redisPrefix = redisPrefix.trim() || "clawee";
  }

  mode(): ReplayStoreMode {
    return "redis";
  }

  async connect(): Promise<void> {
    if (this.client) {
      return;
    }
    let redisModule: any;
    try {
      redisModule = await import("redis");
    } catch {
      throw new Error(
        "Replay store mode is redis, but package 'redis' is not installed. Run npm install redis.",
      );
    }
    const client = redisModule.createClient({
      url: this.redisUrl,
    });
    client.on("error", () => {
      // Errors are surfaced by command failures where relevant.
    });
    await client.connect();
    this.client = client;
  }

  async warmup(): Promise<void> {
    await this.connect();
    await this.client.ping();
  }

  async registerNonce(nonceHash: string, ttlSeconds: number): Promise<boolean> {
    await this.connect();
    const key = `${this.redisPrefix}:replay:nonce:${nonceHash}`;
    const result = await this.client.set(key, "1", {
      NX: true,
      EX: Math.max(1, Math.floor(ttlSeconds)),
    });
    return result === "OK";
  }

  async registerEventKey(eventKeyHash: string, ttlSeconds: number): Promise<boolean> {
    await this.connect();
    const key = `${this.redisPrefix}:replay:event:${eventKeyHash}`;
    const result = await this.client.set(key, "1", {
      NX: true,
      EX: Math.max(60, Math.floor(ttlSeconds)),
    });
    return result === "OK";
  }

  getState(): Record<string, unknown> {
    return {
      mode: "redis",
      redis_prefix: this.redisPrefix,
      redis_url_configured: this.redisUrl.length > 0,
    };
  }

  async close(): Promise<void> {
    if (this.client) {
      await this.client.quit();
      this.client = null;
    }
  }
}

export function createReplayStore(
  config: ReplayStoreConfig,
  interactionStore: InteractionStore,
): ReplayStore {
  if (config.mode === "redis") {
    if (!config.redisUrl.trim()) {
      throw new Error("Replay store mode is redis but REPLAY_REDIS_URL is not configured.");
    }
    return new RedisReplayStore(config.redisUrl, config.redisPrefix);
  }
  return new SqliteReplayStore(interactionStore);
}
