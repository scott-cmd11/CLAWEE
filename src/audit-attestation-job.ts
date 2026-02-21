import fs from "node:fs";
import path from "node:path";
import type { AuditLedger } from "./audit-ledger";
import { AuditAttestationService } from "./audit-attestation";

export interface AuditAttestationJobOptions {
  enabled: boolean;
  intervalSeconds: number;
  snapshotDirectory: string;
  chainPath: string;
  maxRecordsPerExport: number;
  incremental: boolean;
  retentionMaxFiles: number;
}

export class AuditAttestationJobService {
  private options: AuditAttestationJobOptions;
  private attestationService: AuditAttestationService;
  private ledger: AuditLedger;
  private timer: NodeJS.Timeout | null = null;
  private running = false;
  private sinceCursor = "";

  constructor(
    options: AuditAttestationJobOptions,
    attestationService: AuditAttestationService,
    ledger: AuditLedger,
  ) {
    this.options = options;
    this.attestationService = attestationService;
    this.ledger = ledger;
  }

  start(): void {
    if (!this.options.enabled) {
      return;
    }
    const intervalMs = Math.max(10, this.options.intervalSeconds) * 1000;
    this.timer = setInterval(() => {
      void this.runNow();
    }, intervalMs);
    void this.runNow();
  }

  stop(): void {
    if (this.timer) {
      clearInterval(this.timer);
      this.timer = null;
    }
  }

  async runNow(): Promise<void> {
    if (!this.options.enabled || this.running) {
      return;
    }
    this.running = true;
    try {
      const stamp = new Date().toISOString().replace(/[:.]/g, "-");
      const snapshotPath = path.join(this.options.snapshotDirectory, `audit-attestation-${stamp}.json`);
      const result = this.attestationService.exportSealedSnapshot({
        snapshotPath,
        chainPath: this.options.chainPath,
        limit: this.options.maxRecordsPerExport,
        since: this.options.incremental ? this.sinceCursor : "",
      });
      if (this.options.incremental) {
        this.sinceCursor = result.generated_at;
      }
      this.ledger.logAndSignAction("AUDIT_ATTESTATION_PERIODIC_EXPORTED", {
        snapshot_path: result.snapshot_path,
        chain_path: result.chain_path,
        count: result.count,
        current_snapshot_hash: result.current_snapshot_hash,
        previous_snapshot_hash: result.previous_snapshot_hash,
        incremental: this.options.incremental,
        since_cursor: this.sinceCursor || null,
      });
      this.pruneSnapshots();
    } catch (error) {
      this.ledger.logAndSignAction("SYSTEM_ERROR", {
        module: "audit-attestation-job",
        stage: "run",
        message: error instanceof Error ? error.message : String(error),
      });
    } finally {
      this.running = false;
    }
  }

  private pruneSnapshots(): void {
    const keepRaw = Number(this.options.retentionMaxFiles);
    const keep = Number.isFinite(keepRaw) ? Math.max(0, Math.floor(keepRaw)) : 0;
    if (keep <= 0) {
      return;
    }

    let files: Array<{ path: string; mtimeMs: number }> = [];
    try {
      files = fs
        .readdirSync(this.options.snapshotDirectory)
        .filter((name) => name.toLowerCase().endsWith(".json"))
        .map((name) => {
          const fullPath = path.join(this.options.snapshotDirectory, name);
          const stat = fs.statSync(fullPath);
          return { path: fullPath, mtimeMs: stat.mtimeMs };
        })
        .sort((a, b) => b.mtimeMs - a.mtimeMs);
    } catch {
      return;
    }

    if (files.length <= keep) {
      return;
    }

    const remove = files.slice(keep);
    for (const file of remove) {
      try {
        fs.rmSync(file.path, { force: true });
      } catch {
        // ignore individual prune failures
      }
    }
    this.ledger.logAndSignAction("AUDIT_ATTESTATION_SNAPSHOTS_PRUNED", {
      removed_count: remove.length,
      kept_count: keep,
      snapshot_directory: this.options.snapshotDirectory,
    });
  }
}
