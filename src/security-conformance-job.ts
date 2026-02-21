import fs from "node:fs";
import path from "node:path";
import type { AuditLedger } from "./audit-ledger";
import { SecurityConformanceService } from "./security-conformance";
import { SecurityInvariantRegistry } from "./security-invariants";

export interface SecurityConformanceJobOptions {
  enabled: boolean;
  intervalSeconds: number;
  snapshotDirectory: string;
  chainPath: string;
  retentionMaxFiles: number;
}

export class SecurityConformanceJobService {
  private options: SecurityConformanceJobOptions;
  private conformanceService: SecurityConformanceService;
  private invariantRegistry: SecurityInvariantRegistry;
  private ledger: AuditLedger;
  private timer: NodeJS.Timeout | null = null;
  private running = false;

  constructor(
    options: SecurityConformanceJobOptions,
    conformanceService: SecurityConformanceService,
    invariantRegistry: SecurityInvariantRegistry,
    ledger: AuditLedger,
  ) {
    this.options = options;
    this.conformanceService = conformanceService;
    this.invariantRegistry = invariantRegistry;
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
      const reportPath = path.join(this.options.snapshotDirectory, `security-conformance-${stamp}.json`);
      const summary = this.invariantRegistry.summary();
      const invariants = this.invariantRegistry.list();
      const payload = this.conformanceService.generate({
        invariantCatalogHash: this.invariantRegistry.definitionHash(),
        summary,
        invariants,
      });
      const result = this.conformanceService.exportSealedSnapshot(payload, {
        reportPath,
        chainPath: this.options.chainPath,
      });
      this.ledger.logAndSignAction("SECURITY_CONFORMANCE_PERIODIC_EXPORTED", {
        report_path: result.report_path,
        chain_path: result.chain_path,
        report_hash: result.report_hash,
        current_hash: result.current_hash,
        previous_hash: result.previous_hash,
        summary,
        invariant_count: invariants.length,
      });
      this.pruneSnapshots();
    } catch (error) {
      this.ledger.logAndSignAction("SYSTEM_ERROR", {
        module: "security-conformance-job",
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
    this.ledger.logAndSignAction("SECURITY_CONFORMANCE_SNAPSHOTS_PRUNED", {
      removed_count: remove.length,
      kept_count: keep,
      snapshot_directory: this.options.snapshotDirectory,
    });
  }
}
