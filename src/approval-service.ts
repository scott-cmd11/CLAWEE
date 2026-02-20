import crypto from "node:crypto";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import Database from "better-sqlite3";

export type ApprovalStatus = "pending" | "approved" | "denied" | "expired";

export interface ApprovalRecord {
  id: string;
  created_at: string;
  expires_at: string;
  status: ApprovalStatus;
  required_approvals: number;
  required_roles: string;
  max_uses: number;
  use_count: number;
  last_used_at: string | null;
  approval_actors: string;
  approval_actor_roles: string;
  request_fingerprint: string;
  reason: string;
  metadata: string;
  resolved_by: string | null;
  resolved_at: string | null;
}

export interface ApprovalCreateInput {
  requestFingerprint: string;
  reason: string;
  metadata: unknown;
  ttlSeconds: number;
  requiredApprovals?: number;
  requiredRoles?: string[];
  maxUses?: number;
}

export interface ApprovalCreateResult {
  record: ApprovalRecord;
  created: boolean;
}

export class ApprovalService {
  private dbPath: string;
  private db: Database.Database | null = null;

  constructor(dbPath = path.join(os.homedir(), ".openclaw", "enterprise_approvals.db")) {
    this.dbPath = dbPath;
  }

  init(): void {
    fs.mkdirSync(path.dirname(this.dbPath), { recursive: true });
    this.db = new Database(this.dbPath);
    this.db.pragma("journal_mode = WAL");
    this.db.exec(`
      CREATE TABLE IF NOT EXISTS approvals (
        id TEXT PRIMARY KEY,
        created_at TEXT NOT NULL,
        expires_at TEXT NOT NULL,
        status TEXT NOT NULL,
        required_approvals INTEGER NOT NULL DEFAULT 1,
        approval_actors TEXT NOT NULL DEFAULT '[]',
        max_uses INTEGER NOT NULL DEFAULT 1,
        use_count INTEGER NOT NULL DEFAULT 0,
        last_used_at TEXT,
        request_fingerprint TEXT NOT NULL,
        reason TEXT NOT NULL,
        metadata TEXT NOT NULL,
        resolved_by TEXT,
        resolved_at TEXT
      );
    `);
    this.ensureColumns();
  }

  close(): void {
    if (this.db) {
      this.db.close();
      this.db = null;
    }
  }

  cleanupExpired(nowIso = new Date().toISOString()): number {
    const db = this.assertDb();
    const result = db
      .prepare(
        `
          UPDATE approvals
          SET status = 'expired'
          WHERE status = 'pending' AND expires_at < ?
        `,
      )
      .run(nowIso);
    return result.changes;
  }

  getOrCreatePending(input: ApprovalCreateInput): ApprovalCreateResult {
    const db = this.assertDb();
    this.cleanupExpired();
    const requiredApprovals = this.normalizeRequiredApprovals(input.requiredApprovals);
    const requiredRoles = this.normalizeRoles(input.requiredRoles);
    const maxUses = this.normalizeMaxUses(input.maxUses);
    const existing = db
      .prepare(
        `
          SELECT *
          FROM approvals
          WHERE request_fingerprint = ?
            AND status = 'pending'
          ORDER BY created_at DESC
          LIMIT 1
        `,
      )
      .get(input.requestFingerprint) as ApprovalRecord | undefined;

    if (existing) {
      const existingRequiredRoles = this.parseRoleArray(existing.required_roles);
      const mergedRoles = this.mergeRoles(existingRequiredRoles, requiredRoles);
      if (existing.max_uses < maxUses) {
        db.prepare(
          `
            UPDATE approvals
            SET max_uses = ?
            WHERE id = ?
          `,
        ).run(maxUses, existing.id);
      }
      if (existing.required_approvals < requiredApprovals) {
        db.prepare(
          `
            UPDATE approvals
            SET required_approvals = ?,
                required_roles = ?
            WHERE id = ?
          `,
        ).run(requiredApprovals, JSON.stringify(mergedRoles), existing.id);
        const upgraded = this.getById(existing.id);
        if (!upgraded) {
          throw new Error(`Approval not found after quorum upgrade: ${existing.id}`);
        }
        return {
          record: upgraded,
          created: false,
        };
      }
      if (JSON.stringify(existingRequiredRoles) !== JSON.stringify(mergedRoles)) {
        db.prepare(
          `
            UPDATE approvals
            SET required_roles = ?
            WHERE id = ?
          `,
        ).run(JSON.stringify(mergedRoles), existing.id);
        const upgraded = this.getById(existing.id);
        if (!upgraded) {
          throw new Error(`Approval not found after role upgrade: ${existing.id}`);
        }
        return {
          record: upgraded,
          created: false,
        };
      }
      return {
        record: existing,
        created: false,
      };
    }

    const createdAt = new Date();
    const expiresAt = new Date(createdAt.getTime() + Math.max(60, input.ttlSeconds) * 1000);
    const id = crypto.randomUUID();
    const metadata = JSON.stringify(input.metadata || {});

    db.prepare(
      `
        INSERT INTO approvals (
          id,
          created_at,
          expires_at,
          status,
          required_approvals,
          required_roles,
          approval_actors,
          approval_actor_roles,
          max_uses,
          use_count,
          last_used_at,
          request_fingerprint,
          reason,
          metadata,
          resolved_by,
          resolved_at
        )
        VALUES (?, ?, ?, 'pending', ?, ?, '[]', '{}', ?, 0, NULL, ?, ?, ?, NULL, NULL)
      `,
    ).run(
      id,
      createdAt.toISOString(),
      expiresAt.toISOString(),
      requiredApprovals,
      JSON.stringify(requiredRoles),
      maxUses,
      input.requestFingerprint,
      input.reason,
      metadata,
    );

    const createdRecord = db
      .prepare(
        `
          SELECT *
          FROM approvals
          WHERE id = ?
        `,
      )
      .get(id) as ApprovalRecord;

    return {
      record: createdRecord,
      created: true,
    };
  }

  approve(id: string, actor: string, actorRole = "unknown"): ApprovalRecord {
    const db = this.assertDb();
    this.cleanupExpired();
    const normalizedActor = actor.trim();
    if (!normalizedActor) {
      throw new Error("Approval actor is required.");
    }
    const row = this.getById(id);
    if (!row) {
      throw new Error(`Approval not found: ${id}`);
    }
    if (row.status !== "pending") {
      return row;
    }

    const actors = new Set<string>(this.parseApprovalActors(row.approval_actors));
    actors.add(normalizedActor);
    const actorList = [...actors].sort();
    const roleMap = this.parseApprovalActorRoles(row.approval_actor_roles);
    roleMap[normalizedActor] = String(actorRole || "unknown").trim().toLowerCase() || "unknown";
    const requiredApprovals = this.normalizeRequiredApprovals(row.required_approvals);
    const requiredRoles = this.parseRoleArray(row.required_roles);
    const roleCoverage = new Set<string>(Object.values(roleMap));
    const rolesSatisfied = requiredRoles.every((requiredRole) => roleCoverage.has(requiredRole));
    const nowIso = new Date().toISOString();

    if (actorList.length >= requiredApprovals && rolesSatisfied) {
      db.prepare(
        `
          UPDATE approvals
          SET status = 'approved',
              approval_actors = ?,
              approval_actor_roles = ?,
              resolved_by = ?,
              resolved_at = ?
          WHERE id = ?
            AND status = 'pending'
        `,
      ).run(JSON.stringify(actorList), JSON.stringify(roleMap), normalizedActor, nowIso, id);
    } else {
      db.prepare(
        `
          UPDATE approvals
          SET approval_actors = ?,
              approval_actor_roles = ?
          WHERE id = ?
            AND status = 'pending'
        `,
      ).run(JSON.stringify(actorList), JSON.stringify(roleMap), id);
    }

    const updated = this.getById(id);
    if (!updated) {
      throw new Error(`Approval not found: ${id}`);
    }
    return updated;
  }

  deny(id: string, actor: string): ApprovalRecord {
    return this.resolve(id, "denied", actor);
  }

  getPending(limit = 50): ApprovalRecord[] {
    const db = this.assertDb();
    this.cleanupExpired();
    return db
      .prepare(
        `
          SELECT *
          FROM approvals
          WHERE status = 'pending'
          ORDER BY created_at DESC
          LIMIT ?
        `,
      )
      .all(limit) as ApprovalRecord[];
  }

  getById(id: string): ApprovalRecord | null {
    const db = this.assertDb();
    const row = db
      .prepare(
        `
          SELECT *
          FROM approvals
          WHERE id = ?
          LIMIT 1
        `,
      )
      .get(id) as ApprovalRecord | undefined;
    return row || null;
  }

  getStats(): {
    pending: number;
    approved: number;
    denied: number;
    expired: number;
  } {
    const db = this.assertDb();
    this.cleanupExpired();
    const rows = db
      .prepare(
        `
          SELECT status, COUNT(*) AS count
          FROM approvals
          GROUP BY status
        `,
      )
      .all() as Array<{ status: ApprovalStatus; count: number }>;

    const stats = {
      pending: 0,
      approved: 0,
      denied: 0,
      expired: 0,
    };
    for (const row of rows) {
      if (row.status in stats) {
        (stats as Record<string, number>)[row.status] = row.count;
      }
    }
    return stats;
  }

  listForAttestation(limit = 1000, sinceIso = ""): ApprovalRecord[] {
    const db = this.assertDb();
    this.cleanupExpired();
    const safeLimit = Math.min(Math.max(1, Math.floor(limit)), 10000);
    const since = sinceIso.trim();
    if (since) {
      return db
        .prepare(
          `
            SELECT *
            FROM approvals
            WHERE created_at >= ?
              AND status != 'pending'
            ORDER BY created_at ASC, id ASC
            LIMIT ?
          `,
        )
        .all(since, safeLimit) as ApprovalRecord[];
    }
    return db
      .prepare(
        `
          SELECT *
          FROM approvals
          WHERE status != 'pending'
          ORDER BY created_at ASC, id ASC
          LIMIT ?
        `,
      )
      .all(safeLimit) as ApprovalRecord[];
  }

  validateApproved(id: string, requestFingerprint: string): boolean {
    const db = this.assertDb();
    this.cleanupExpired();
    const row = db
      .prepare(
        `
          SELECT status, request_fingerprint, expires_at, max_uses, use_count
          FROM approvals
          WHERE id = ?
        `,
      )
      .get(id) as
      | {
          status: ApprovalStatus;
          request_fingerprint: string;
          expires_at: string;
          max_uses: number;
          use_count: number;
        }
      | undefined;

    if (!row) {
      return false;
    }
    if (row.status !== "approved") {
      return false;
    }
    if (row.request_fingerprint !== requestFingerprint) {
      return false;
    }
    if (new Date(row.expires_at).getTime() < Date.now()) {
      return false;
    }
    if (Number(row.use_count || 0) >= this.normalizeMaxUses(row.max_uses)) {
      return false;
    }
    return true;
  }

  consumeApproved(id: string, requestFingerprint: string): boolean {
    const db = this.assertDb();
    this.cleanupExpired();
    const nowIso = new Date().toISOString();
    const result = db
      .prepare(
        `
          UPDATE approvals
          SET use_count = use_count + 1,
              last_used_at = ?
          WHERE id = ?
            AND status = 'approved'
            AND request_fingerprint = ?
            AND expires_at >= ?
            AND use_count < max_uses
        `,
      )
      .run(nowIso, id, requestFingerprint, nowIso);
    return result.changes > 0;
  }

  private resolve(id: string, status: "approved" | "denied", actor: string): ApprovalRecord {
    const db = this.assertDb();
    this.cleanupExpired();
    db.prepare(
      `
        UPDATE approvals
        SET status = ?,
            resolved_by = ?,
            resolved_at = ?
        WHERE id = ?
          AND status = 'pending'
      `,
    ).run(status, actor, new Date().toISOString(), id);

    const row = db
      .prepare(
        `
          SELECT *
          FROM approvals
          WHERE id = ?
        `,
      )
      .get(id) as ApprovalRecord | undefined;

    if (!row) {
      throw new Error(`Approval not found: ${id}`);
    }
    return row;
  }

  private assertDb(): Database.Database {
    if (!this.db) {
      throw new Error("Approval service is not initialized.");
    }
    return this.db;
  }

  private normalizeRequiredApprovals(value: number | undefined): number {
    const fallback = 1;
    const numeric = Number(value ?? fallback);
    if (!Number.isFinite(numeric)) {
      return fallback;
    }
    return Math.min(5, Math.max(1, Math.floor(numeric)));
  }

  private normalizeMaxUses(value: number | undefined): number {
    const fallback = 1;
    const numeric = Number(value ?? fallback);
    if (!Number.isFinite(numeric)) {
      return fallback;
    }
    return Math.min(100, Math.max(1, Math.floor(numeric)));
  }

  private parseApprovalActors(raw: string): string[] {
    try {
      const parsed = JSON.parse(raw);
      if (!Array.isArray(parsed)) {
        return [];
      }
      return parsed
        .map((value) => String(value || "").trim())
        .filter(Boolean);
    } catch {
      return [];
    }
  }

  private ensureColumns(): void {
    const db = this.assertDb();
    const columns = db
      .prepare("PRAGMA table_info(approvals)")
      .all() as Array<{ name: string }>;
    const names = new Set(columns.map((column) => String(column.name || "")));
    if (!names.has("required_approvals")) {
      db.exec("ALTER TABLE approvals ADD COLUMN required_approvals INTEGER NOT NULL DEFAULT 1");
    }
    if (!names.has("required_roles")) {
      db.exec("ALTER TABLE approvals ADD COLUMN required_roles TEXT NOT NULL DEFAULT '[]'");
    }
    if (!names.has("max_uses")) {
      db.exec("ALTER TABLE approvals ADD COLUMN max_uses INTEGER NOT NULL DEFAULT 1");
    }
    if (!names.has("use_count")) {
      db.exec("ALTER TABLE approvals ADD COLUMN use_count INTEGER NOT NULL DEFAULT 0");
    }
    if (!names.has("last_used_at")) {
      db.exec("ALTER TABLE approvals ADD COLUMN last_used_at TEXT");
    }
    if (!names.has("approval_actors")) {
      db.exec("ALTER TABLE approvals ADD COLUMN approval_actors TEXT NOT NULL DEFAULT '[]'");
    }
    if (!names.has("approval_actor_roles")) {
      db.exec("ALTER TABLE approvals ADD COLUMN approval_actor_roles TEXT NOT NULL DEFAULT '{}'");
    }
    db.exec(`
      UPDATE approvals
      SET required_approvals = 1
      WHERE required_approvals IS NULL OR required_approvals < 1;
      UPDATE approvals
      SET required_roles = '[]'
      WHERE required_roles IS NULL OR TRIM(required_roles) = '';
      UPDATE approvals
      SET max_uses = 1
      WHERE max_uses IS NULL OR max_uses < 1;
      UPDATE approvals
      SET use_count = 0
      WHERE use_count IS NULL OR use_count < 0;
      UPDATE approvals
      SET approval_actors = '[]'
      WHERE approval_actors IS NULL OR TRIM(approval_actors) = '';
      UPDATE approvals
      SET approval_actor_roles = '{}'
      WHERE approval_actor_roles IS NULL OR TRIM(approval_actor_roles) = '';
    `);
  }

  private normalizeRoles(values: string[] | undefined): string[] {
    const normalized = (values || [])
      .map((value) => String(value || "").trim().toLowerCase())
      .filter(Boolean);
    return [...new Set(normalized)].sort();
  }

  private mergeRoles(a: string[], b: string[]): string[] {
    return [...new Set([...a, ...b])].sort();
  }

  private parseRoleArray(raw: string): string[] {
    try {
      const parsed = JSON.parse(raw);
      if (!Array.isArray(parsed)) {
        return [];
      }
      return parsed
        .map((value) => String(value || "").trim().toLowerCase())
        .filter(Boolean)
        .sort();
    } catch {
      return [];
    }
  }

  private parseApprovalActorRoles(raw: string): Record<string, string> {
    try {
      const parsed = JSON.parse(raw);
      if (!parsed || typeof parsed !== "object" || Array.isArray(parsed)) {
        return {};
      }
      const out: Record<string, string> = {};
      for (const [actor, role] of Object.entries(parsed as Record<string, unknown>)) {
        const actorKey = String(actor || "").trim();
        const roleValue = String(role || "").trim().toLowerCase();
        if (!actorKey || !roleValue) {
          continue;
        }
        out[actorKey] = roleValue;
      }
      return out;
    } catch {
      return {};
    }
  }
}
