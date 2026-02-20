import { InteractionStore } from "./interaction-store";

export type ReplayStoreMode = "sqlite" | "redis" | "postgres";

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
  postgresUrl: string;
  postgresSchema: string;
  postgresTablePrefix: string;
  postgresConnectTimeoutMs: number;
  postgresSslMode: "disable" | "require" | "verify-full";
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

class PostgresReplayStore implements ReplayStore {
  private postgresUrl: string;
  private postgresSchema: string;
  private postgresTablePrefix: string;
  private connectTimeoutMs: number;
  private sslMode: "disable" | "require" | "verify-full";
  private pool: any | null = null;
  private lastError: string | null = null;
  private cleanupCounter = 0;

  constructor(config: {
    postgresUrl: string;
    postgresSchema: string;
    postgresTablePrefix: string;
    postgresConnectTimeoutMs: number;
    postgresSslMode: "disable" | "require" | "verify-full";
  }) {
    this.postgresUrl = config.postgresUrl.trim();
    this.postgresSchema = normalizeIdentifier(config.postgresSchema || "clawee", "schema");
    this.postgresTablePrefix = normalizeIdentifier(
      config.postgresTablePrefix || "replay_",
      "table prefix",
    );
    this.connectTimeoutMs = Math.max(1000, Math.floor(config.postgresConnectTimeoutMs));
    this.sslMode = config.postgresSslMode;
  }

  mode(): ReplayStoreMode {
    return "postgres";
  }

  async warmup(): Promise<void> {
    const pool = await this.connect();
    await pool.query("SELECT 1");
    await this.ensureSchemaAndTables(pool);
  }

  async registerNonce(nonceHash: string, ttlSeconds: number): Promise<boolean> {
    const pool = await this.connect();
    await this.maybeCleanup(pool);
    const ttl = Math.max(1, Math.floor(ttlSeconds));
    const table = this.qualifiedTable("channel_ingress_replay");
    const sql = `
      INSERT INTO ${table} (nonce_hash, seen_at, expires_at)
      VALUES ($1, NOW(), NOW() + ($2::text || ' seconds')::interval)
      ON CONFLICT (nonce_hash) DO NOTHING
      RETURNING nonce_hash
    `;
    const result = await pool.query(sql, [nonceHash, ttl]);
    return Number(result.rowCount || 0) > 0;
  }

  async registerEventKey(eventKeyHash: string, ttlSeconds: number): Promise<boolean> {
    const pool = await this.connect();
    await this.maybeCleanup(pool);
    const ttl = Math.max(60, Math.floor(ttlSeconds));
    const table = this.qualifiedTable("channel_ingress_event_replay");
    const sql = `
      INSERT INTO ${table} (event_key_hash, seen_at, expires_at)
      VALUES ($1, NOW(), NOW() + ($2::text || ' seconds')::interval)
      ON CONFLICT (event_key_hash) DO NOTHING
      RETURNING event_key_hash
    `;
    const result = await pool.query(sql, [eventKeyHash, ttl]);
    return Number(result.rowCount || 0) > 0;
  }

  getState(): Record<string, unknown> {
    return {
      mode: "postgres",
      postgres_url_configured: this.postgresUrl.length > 0,
      postgres_schema: this.postgresSchema,
      postgres_table_prefix: this.postgresTablePrefix,
      postgres_ssl_mode: this.sslMode,
      postgres_connected: this.pool !== null,
      last_error: this.lastError,
    };
  }

  async close(): Promise<void> {
    if (this.pool) {
      await this.pool.end();
      this.pool = null;
    }
  }

  private async connect(): Promise<any> {
    if (this.pool) {
      return this.pool;
    }
    let pgModule: any;
    try {
      pgModule = await import("pg");
    } catch {
      throw new Error("Replay store mode is postgres, but package 'pg' is not installed.");
    }
    const ssl =
      this.sslMode === "disable"
        ? false
        : this.sslMode === "require"
          ? { rejectUnauthorized: false }
          : { rejectUnauthorized: true };
    const pool = new pgModule.Pool({
      connectionString: this.postgresUrl,
      connectionTimeoutMillis: this.connectTimeoutMs,
      ssl,
      max: 5,
    });
    pool.on("error", (error: unknown) => {
      this.lastError = error instanceof Error ? error.message : String(error);
    });
    try {
      await pool.query("SELECT 1");
      this.pool = pool;
      this.lastError = null;
      return pool;
    } catch (error) {
      this.lastError = error instanceof Error ? error.message : String(error);
      await pool.end();
      throw new Error(`Failed to connect to Postgres replay store: ${this.lastError}`);
    }
  }

  private async ensureSchemaAndTables(pool: any): Promise<void> {
    const schema = this.quotedIdentifier(this.postgresSchema);
    const nonceTable = this.quotedIdentifier(`${this.postgresTablePrefix}channel_ingress_replay`);
    const nonceExpiryIndex = this.quotedIdentifier(`${this.postgresTablePrefix}nonce_expires_idx`);
    const eventTable = this.quotedIdentifier(
      `${this.postgresTablePrefix}channel_ingress_event_replay`,
    );
    const eventExpiryIndex = this.quotedIdentifier(`${this.postgresTablePrefix}event_expires_idx`);
    await pool.query(`CREATE SCHEMA IF NOT EXISTS ${schema}`);
    await pool.query(`
      CREATE TABLE IF NOT EXISTS ${schema}.${nonceTable} (
        nonce_hash TEXT PRIMARY KEY,
        seen_at TIMESTAMPTZ NOT NULL,
        expires_at TIMESTAMPTZ NOT NULL
      )
    `);
    await pool.query(`
      CREATE INDEX IF NOT EXISTS ${nonceExpiryIndex}
      ON ${schema}.${nonceTable} (expires_at)
    `);
    await pool.query(`
      CREATE TABLE IF NOT EXISTS ${schema}.${eventTable} (
        event_key_hash TEXT PRIMARY KEY,
        seen_at TIMESTAMPTZ NOT NULL,
        expires_at TIMESTAMPTZ NOT NULL
      )
    `);
    await pool.query(`
      CREATE INDEX IF NOT EXISTS ${eventExpiryIndex}
      ON ${schema}.${eventTable} (expires_at)
    `);
  }

  private quotedIdentifier(value: string): string {
    return `"${value.replace(/"/g, "\"\"")}"`;
  }

  private qualifiedTable(suffix: "channel_ingress_replay" | "channel_ingress_event_replay"): string {
    const table = `${this.postgresTablePrefix}${suffix}`;
    return `${this.quotedIdentifier(this.postgresSchema)}.${this.quotedIdentifier(table)}`;
  }

  private async maybeCleanup(pool: any): Promise<void> {
    this.cleanupCounter += 1;
    if (this.cleanupCounter % 100 !== 0) {
      return;
    }
    await pool.query(`DELETE FROM ${this.qualifiedTable("channel_ingress_replay")} WHERE expires_at < NOW()`);
    await pool.query(
      `DELETE FROM ${this.qualifiedTable("channel_ingress_event_replay")} WHERE expires_at < NOW()`,
    );
  }
}

function normalizeIdentifier(raw: string, label: string): string {
  const normalized = String(raw || "")
    .trim()
    .toLowerCase()
    .replace(/[^a-z0-9_]/g, "_");
  if (!normalized || !/^[a-z_][a-z0-9_]*$/.test(normalized)) {
    throw new Error(`Invalid Postgres ${label}: ${raw}`);
  }
  return normalized;
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
  if (config.mode === "postgres") {
    if (!config.postgresUrl.trim()) {
      throw new Error("Replay store mode is postgres but REPLAY_POSTGRES_URL is not configured.");
    }
    return new PostgresReplayStore({
      postgresUrl: config.postgresUrl,
      postgresSchema: config.postgresSchema,
      postgresTablePrefix: config.postgresTablePrefix,
      postgresConnectTimeoutMs: config.postgresConnectTimeoutMs,
      postgresSslMode: config.postgresSslMode,
    });
  }
  return new SqliteReplayStore(interactionStore);
}
