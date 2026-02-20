import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import Database from "better-sqlite3";
import type { ChannelInboundEvent, ChannelOutboundMessage } from "./channel-hub";
import type { ModalityObservation } from "./modality-hub";

export class InteractionStore {
  private dbPath: string;
  private db: Database.Database | null = null;

  constructor(dbPath = path.join(os.homedir(), ".openclaw", "enterprise_interactions.db")) {
    this.dbPath = dbPath;
  }

  init(): void {
    fs.mkdirSync(path.dirname(this.dbPath), { recursive: true });
    this.db = new Database(this.dbPath);
    this.db.pragma("journal_mode = WAL");
    this.db.exec(`
      CREATE TABLE IF NOT EXISTS modality_observations (
        id TEXT PRIMARY KEY,
        session_id TEXT NOT NULL,
        modality TEXT NOT NULL,
        source TEXT NOT NULL,
        timestamp TEXT NOT NULL,
        payload TEXT NOT NULL
      );

      CREATE TABLE IF NOT EXISTS channel_inbound (
        id TEXT PRIMARY KEY,
        channel TEXT NOT NULL,
        source TEXT NOT NULL,
        sender TEXT NOT NULL,
        text TEXT NOT NULL,
        timestamp TEXT NOT NULL,
        metadata TEXT NOT NULL
      );

      CREATE TABLE IF NOT EXISTS channel_outbound (
        id TEXT PRIMARY KEY,
        channel TEXT NOT NULL,
        destination TEXT NOT NULL,
        text TEXT NOT NULL,
        timestamp TEXT NOT NULL,
        metadata TEXT NOT NULL
      );

      CREATE TABLE IF NOT EXISTS channel_delivery (
        message_id TEXT PRIMARY KEY,
        status TEXT NOT NULL,
        attempts INTEGER NOT NULL,
        last_error TEXT,
        next_attempt_at TEXT NOT NULL,
        sent_at TEXT,
        updated_at TEXT NOT NULL
      );

      CREATE TABLE IF NOT EXISTS channel_ingress_replay (
        nonce_hash TEXT PRIMARY KEY,
        seen_at TEXT NOT NULL,
        expires_at TEXT NOT NULL
      );

      CREATE TABLE IF NOT EXISTS channel_ingress_event_replay (
        event_key_hash TEXT PRIMARY KEY,
        seen_at TEXT NOT NULL,
        expires_at TEXT NOT NULL
      );
    `);
  }

  close(): void {
    if (this.db) {
      this.db.close();
      this.db = null;
    }
  }

  recordModality(observation: ModalityObservation): void {
    const db = this.assertDb();
    db.prepare(
      `
        INSERT OR REPLACE INTO modality_observations (id, session_id, modality, source, timestamp, payload)
        VALUES (?, ?, ?, ?, ?, ?)
      `,
    ).run(
      observation.id,
      observation.session_id,
      observation.modality,
      observation.source,
      observation.timestamp,
      JSON.stringify(observation.payload ?? {}),
    );
  }

  recordChannelInbound(event: ChannelInboundEvent): void {
    const db = this.assertDb();
    db.prepare(
      `
        INSERT OR REPLACE INTO channel_inbound (id, channel, source, sender, text, timestamp, metadata)
        VALUES (?, ?, ?, ?, ?, ?, ?)
      `,
    ).run(
      event.id,
      event.channel,
      event.source,
      event.sender,
      event.text,
      event.timestamp,
      JSON.stringify(event.metadata ?? {}),
    );
  }

  recordChannelOutbound(message: ChannelOutboundMessage): void {
    const db = this.assertDb();
    const now = new Date().toISOString();
    db.prepare(
      `
        INSERT OR REPLACE INTO channel_outbound (id, channel, destination, text, timestamp, metadata)
        VALUES (?, ?, ?, ?, ?, ?)
      `,
    ).run(
      message.id,
      message.channel,
      message.destination,
      message.text,
      message.timestamp,
      JSON.stringify(message.metadata ?? {}),
    );

    db.prepare(
      `
        INSERT OR IGNORE INTO channel_delivery (message_id, status, attempts, last_error, next_attempt_at, sent_at, updated_at)
        VALUES (?, 'queued', 0, NULL, ?, NULL, ?)
      `,
    ).run(message.id, now, now);
  }

  getPendingOutbound(limit = 20): Array<
    ChannelOutboundMessage & {
      attempts: number;
      status: string;
    }
  > {
    const db = this.assertDb();
    const safeLimit = Math.min(Math.max(1, Math.floor(limit)), 200);
    const now = new Date().toISOString();
    return db
      .prepare(
        `
          SELECT
            o.id,
            o.channel,
            o.destination,
            o.text,
            o.timestamp,
            o.metadata,
            d.attempts,
            d.status
          FROM channel_outbound o
          JOIN channel_delivery d ON d.message_id = o.id
          WHERE d.status IN ('queued', 'retry')
            AND d.next_attempt_at <= ?
          ORDER BY d.next_attempt_at ASC
          LIMIT ?
        `,
      )
      .all(now, safeLimit)
      .map((row) => ({
        id: String((row as Record<string, unknown>).id),
        channel: String((row as Record<string, unknown>).channel) as ChannelOutboundMessage["channel"],
        destination: String((row as Record<string, unknown>).destination),
        text: String((row as Record<string, unknown>).text),
        timestamp: String((row as Record<string, unknown>).timestamp),
        metadata: JSON.parse(String((row as Record<string, unknown>).metadata || "{}")) as Record<string, unknown>,
        attempts: Number((row as Record<string, unknown>).attempts || 0),
        status: String((row as Record<string, unknown>).status),
      }));
  }

  markOutboundSent(messageId: string): void {
    const db = this.assertDb();
    const now = new Date().toISOString();
    db.prepare(
      `
        UPDATE channel_delivery
        SET status = 'sent',
            sent_at = ?,
            updated_at = ?,
            last_error = NULL
        WHERE message_id = ?
      `,
    ).run(now, now, messageId);
  }

  markOutboundFailed(messageId: string, attempts: number, nextAttemptAt: string, errorMessage: string): void {
    const db = this.assertDb();
    const now = new Date().toISOString();
    db.prepare(
      `
        UPDATE channel_delivery
        SET status = 'retry',
            attempts = ?,
            next_attempt_at = ?,
            last_error = ?,
            updated_at = ?
        WHERE message_id = ?
      `,
    ).run(attempts, nextAttemptAt, errorMessage, now, messageId);
  }

  markOutboundExhausted(messageId: string, attempts: number, errorMessage: string): void {
    const db = this.assertDb();
    const now = new Date().toISOString();
    db.prepare(
      `
        UPDATE channel_delivery
        SET status = 'failed',
            attempts = ?,
            last_error = ?,
            updated_at = ?
        WHERE message_id = ?
      `,
    ).run(attempts, errorMessage, now, messageId);
  }

  forceRetry(messageId: string): boolean {
    const db = this.assertDb();
    const now = new Date().toISOString();
    const result = db
      .prepare(
        `
          UPDATE channel_delivery
          SET status = 'retry',
              next_attempt_at = ?,
              updated_at = ?
          WHERE message_id = ?
        `,
      )
      .run(now, now, messageId);
    return result.changes > 0;
  }

  listDeliveries(limit = 100): Array<{
    message_id: string;
    channel: string;
    destination: string;
    status: string;
    attempts: number;
    last_error: string | null;
    next_attempt_at: string;
    sent_at: string | null;
    updated_at: string;
    }> {
    const db = this.assertDb();
    const safeLimit = Math.min(Math.max(1, Math.floor(limit)), 1000);
    return db
      .prepare(
        `
          SELECT
            d.message_id,
            o.channel,
            o.destination,
            d.status,
            d.attempts,
            d.last_error,
            d.next_attempt_at,
            d.sent_at,
            d.updated_at
          FROM channel_delivery d
          JOIN channel_outbound o ON o.id = d.message_id
          ORDER BY d.updated_at DESC
          LIMIT ?
        `,
      )
      .all(safeLimit) as Array<{
      message_id: string;
      channel: string;
      destination: string;
      status: string;
      attempts: number;
      last_error: string | null;
      next_attempt_at: string;
      sent_at: string | null;
      updated_at: string;
    }>;
  }

  registerIngressNonce(nonceHash: string, ttlSeconds: number): boolean {
    const db = this.assertDb();
    const now = new Date();
    const expiresAt = new Date(now.getTime() + Math.max(1, Math.floor(ttlSeconds)) * 1000).toISOString();
    db.prepare(
      `
        DELETE FROM channel_ingress_replay
        WHERE expires_at < ?
      `,
    ).run(now.toISOString());
    const result = db
      .prepare(
        `
          INSERT OR IGNORE INTO channel_ingress_replay (nonce_hash, seen_at, expires_at)
          VALUES (?, ?, ?)
        `,
      )
      .run(nonceHash, now.toISOString(), expiresAt);
    return result.changes > 0;
  }

  registerIngressEventKey(eventKeyHash: string, ttlSeconds: number): boolean {
    const db = this.assertDb();
    const now = new Date();
    const expiresAt = new Date(now.getTime() + Math.max(60, Math.floor(ttlSeconds)) * 1000).toISOString();
    db.prepare(
      `
        DELETE FROM channel_ingress_event_replay
        WHERE expires_at < ?
      `,
    ).run(now.toISOString());
    const result = db
      .prepare(
        `
          INSERT OR IGNORE INTO channel_ingress_event_replay (event_key_hash, seen_at, expires_at)
          VALUES (?, ?, ?)
        `,
      )
      .run(eventKeyHash, now.toISOString(), expiresAt);
    return result.changes > 0;
  }

  counts(): {
    modality_total: number;
    channel_inbound_total: number;
    channel_outbound_total: number;
    channel_delivery_queued: number;
    channel_delivery_retry: number;
    channel_delivery_sent: number;
    channel_delivery_failed: number;
    channel_ingress_nonce_total: number;
    channel_ingress_event_nonce_total: number;
  } {
    const db = this.assertDb();
    const modality = db
      .prepare("SELECT COUNT(*) AS count FROM modality_observations")
      .get() as { count: number };
    const inbound = db
      .prepare("SELECT COUNT(*) AS count FROM channel_inbound")
      .get() as { count: number };
    const outbound = db
      .prepare("SELECT COUNT(*) AS count FROM channel_outbound")
      .get() as { count: number };
    const deliveryRows = db
      .prepare(
        `
          SELECT status, COUNT(*) AS count
          FROM channel_delivery
          GROUP BY status
        `,
      )
      .all() as Array<{ status: string; count: number }>;
    const ingressNonce = db
      .prepare("SELECT COUNT(*) AS count FROM channel_ingress_replay")
      .get() as { count: number };
    const ingressEventNonce = db
      .prepare("SELECT COUNT(*) AS count FROM channel_ingress_event_replay")
      .get() as { count: number };

    const delivery = {
      queued: 0,
      retry: 0,
      sent: 0,
      failed: 0,
    };
    for (const row of deliveryRows) {
      if (row.status in delivery) {
        (delivery as Record<string, number>)[row.status] = Number(row.count || 0);
      }
    }
    return {
      modality_total: Number(modality.count || 0),
      channel_inbound_total: Number(inbound.count || 0),
      channel_outbound_total: Number(outbound.count || 0),
      channel_delivery_queued: delivery.queued,
      channel_delivery_retry: delivery.retry,
      channel_delivery_sent: delivery.sent,
      channel_delivery_failed: delivery.failed,
      channel_ingress_nonce_total: Number(ingressNonce.count || 0),
      channel_ingress_event_nonce_total: Number(ingressEventNonce.count || 0),
    };
  }

  private assertDb(): Database.Database {
    if (!this.db) {
      throw new Error("Interaction store is not initialized.");
    }
    return this.db;
  }
}
