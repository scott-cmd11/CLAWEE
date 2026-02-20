import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import Database from "better-sqlite3";

export type BudgetDecision = "allow" | "suspend";

export interface BudgetPolicy {
  hourlyUsdCap: number;
  dailyUsdCap: number;
}

export interface PricingEntry {
  model: string;
  input_usd_per_1k: number;
  output_usd_per_1k: number;
}

interface PricingCatalogFile {
  version: string;
  models: PricingEntry[];
}

export interface CostEstimate {
  model: string;
  inputTokens: number;
  outputTokens: number;
  estimatedUsd: number;
}

export interface CostRecord extends CostEstimate {
  requestPath: string;
  timestamp?: string;
}

export interface BudgetStatus {
  suspended: boolean;
  reason: string | null;
  triggeredAt: string | null;
  hourlyUsd: number;
  dailyUsd: number;
  hourlyUsdCap: number;
  dailyUsdCap: number;
}

export class BudgetController {
  private dbPath: string;
  private pricingByModel = new Map<string, PricingEntry>();
  private policy: BudgetPolicy;
  private db: Database.Database | null = null;

  constructor(policy: BudgetPolicy, pricingCatalogPath: string, dbPath?: string) {
    this.policy = policy;
    this.dbPath = dbPath || path.join(os.homedir(), ".openclaw", "enterprise_budget.db");
    this.loadPricingCatalog(pricingCatalogPath);
  }

  init(): void {
    fs.mkdirSync(path.dirname(this.dbPath), { recursive: true });
    this.db = new Database(this.dbPath);
    this.db.pragma("journal_mode = WAL");
    this.db.exec(`
      CREATE TABLE IF NOT EXISTS cost_events (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        timestamp TEXT NOT NULL,
        model TEXT NOT NULL,
        input_tokens INTEGER NOT NULL,
        output_tokens INTEGER NOT NULL,
        usd_cost REAL NOT NULL,
        request_path TEXT NOT NULL
      );

      CREATE TABLE IF NOT EXISTS budget_state (
        id INTEGER PRIMARY KEY CHECK (id = 1),
        suspended INTEGER NOT NULL,
        reason TEXT,
        triggered_at TEXT,
        resumed_at TEXT,
        resumed_by TEXT,
        updated_at TEXT NOT NULL
      );

      INSERT OR IGNORE INTO budget_state (id, suspended, reason, triggered_at, resumed_at, resumed_by, updated_at)
      VALUES (1, 0, NULL, NULL, NULL, NULL, datetime('now'));
    `);
  }

  close(): void {
    if (this.db) {
      this.db.close();
      this.db = null;
    }
  }

  estimateCost(model: string, inputTokens: number, outputTokens: number): CostEstimate {
    const pricing = this.pricingByModel.get(model) || this.pricingByModel.get("*");
    if (!pricing) {
      throw new Error(`No pricing entry found for model "${model}" and no "*" fallback.`);
    }
    const estimatedUsd =
      (inputTokens / 1000) * pricing.input_usd_per_1k +
      (outputTokens / 1000) * pricing.output_usd_per_1k;

    return {
      model,
      inputTokens,
      outputTokens,
      estimatedUsd,
    };
  }

  evaluateProjected(estimate: CostEstimate): { decision: BudgetDecision; reason: string | null } {
    const db = this.assertDb();
    const state = this.readState();
    if (state.suspended) {
      return {
        decision: "suspend",
        reason: state.reason || "Budget controller is currently suspended.",
      };
    }

    const usage = this.readUsage();
    const projectedHourly = usage.hourlyUsd + estimate.estimatedUsd;
    const projectedDaily = usage.dailyUsd + estimate.estimatedUsd;

    if (projectedHourly > this.policy.hourlyUsdCap) {
      const reason = `Hourly compute budget exceeded (${projectedHourly.toFixed(4)} > ${this.policy.hourlyUsdCap.toFixed(4)} USD).`;
      this.suspend(reason);
      return { decision: "suspend", reason };
    }

    if (projectedDaily > this.policy.dailyUsdCap) {
      const reason = `Daily compute budget exceeded (${projectedDaily.toFixed(4)} > ${this.policy.dailyUsdCap.toFixed(4)} USD).`;
      this.suspend(reason);
      return { decision: "suspend", reason };
    }

    void db; // reserved for future deterministic transaction wrapping.
    return { decision: "allow", reason: null };
  }

  recordActual(cost: CostRecord): void {
    const db = this.assertDb();
    const timestamp = cost.timestamp || new Date().toISOString();
    db.prepare(
      `
        INSERT INTO cost_events (timestamp, model, input_tokens, output_tokens, usd_cost, request_path)
        VALUES (?, ?, ?, ?, ?, ?)
      `,
    ).run(
      timestamp,
      cost.model,
      cost.inputTokens,
      cost.outputTokens,
      cost.estimatedUsd,
      cost.requestPath,
    );

    const usage = this.readUsage();
    if (usage.hourlyUsd > this.policy.hourlyUsdCap) {
      this.suspend(
        `Hourly compute budget exceeded after actual accounting (${usage.hourlyUsd.toFixed(4)} > ${this.policy.hourlyUsdCap.toFixed(4)} USD).`,
      );
    } else if (usage.dailyUsd > this.policy.dailyUsdCap) {
      this.suspend(
        `Daily compute budget exceeded after actual accounting (${usage.dailyUsd.toFixed(4)} > ${this.policy.dailyUsdCap.toFixed(4)} USD).`,
      );
    }
  }

  suspend(reason: string): void {
    const db = this.assertDb();
    db.prepare(
      `
        UPDATE budget_state
        SET suspended = 1,
            reason = ?,
            triggered_at = ?,
            updated_at = ?
        WHERE id = 1
      `,
    ).run(reason, new Date().toISOString(), new Date().toISOString());
  }

  resume(resumedBy: string): void {
    const db = this.assertDb();
    db.prepare(
      `
        UPDATE budget_state
        SET suspended = 0,
            reason = NULL,
            resumed_at = ?,
            resumed_by = ?,
            updated_at = ?
        WHERE id = 1
      `,
    ).run(new Date().toISOString(), resumedBy, new Date().toISOString());
  }

  getStatus(): BudgetStatus {
    const state = this.readState();
    const usage = this.readUsage();
    return {
      suspended: state.suspended,
      reason: state.reason,
      triggeredAt: state.triggeredAt,
      hourlyUsd: usage.hourlyUsd,
      dailyUsd: usage.dailyUsd,
      hourlyUsdCap: this.policy.hourlyUsdCap,
      dailyUsdCap: this.policy.dailyUsdCap,
    };
  }

  private readState(): { suspended: boolean; reason: string | null; triggeredAt: string | null } {
    const db = this.assertDb();
    const row = db
      .prepare(
        `
          SELECT suspended, reason, triggered_at
          FROM budget_state
          WHERE id = 1
        `,
      )
      .get() as { suspended: number; reason: string | null; triggered_at: string | null };

    return {
      suspended: row.suspended === 1,
      reason: row.reason,
      triggeredAt: row.triggered_at,
    };
  }

  private readUsage(): { hourlyUsd: number; dailyUsd: number } {
    const db = this.assertDb();
    const hourly = db
      .prepare(
        `
          SELECT COALESCE(SUM(usd_cost), 0) AS total
          FROM cost_events
          WHERE timestamp >= ?
        `,
      )
      .get(new Date(Date.now() - 60 * 60 * 1000).toISOString()) as { total: number };

    const dayStart = new Date();
    dayStart.setUTCHours(0, 0, 0, 0);
    const daily = db
      .prepare(
        `
          SELECT COALESCE(SUM(usd_cost), 0) AS total
          FROM cost_events
          WHERE timestamp >= ?
        `,
      )
      .get(dayStart.toISOString()) as { total: number };

    return {
      hourlyUsd: Number(hourly.total || 0),
      dailyUsd: Number(daily.total || 0),
    };
  }

  private loadPricingCatalog(filePath: string): void {
    const raw = fs.readFileSync(filePath, "utf8");
    const parsed = JSON.parse(raw) as PricingCatalogFile;

    if (!parsed.models || !Array.isArray(parsed.models) || parsed.models.length === 0) {
      throw new Error("Pricing catalog has no model entries.");
    }

    for (const entry of parsed.models) {
      if (!entry.model) {
        throw new Error("Pricing catalog entry missing model.");
      }
      this.pricingByModel.set(entry.model, entry);
    }
  }

  private assertDb(): Database.Database {
    if (!this.db) {
      throw new Error("Budget controller is not initialized.");
    }
    return this.db;
  }
}
