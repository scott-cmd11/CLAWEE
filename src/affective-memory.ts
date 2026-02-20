import fs from "node:fs/promises";
import path from "node:path";
import chokidar, { type FSWatcher } from "chokidar";
import type { AuditLedger } from "./audit-ledger";

export type AffectiveState = "Frustrated" | "Neutral" | "Happy";

export interface AffectiveMemoryOptions {
  agentsRootPath: string;
  soulFilePath: string;
}

const OVERRIDE_START = "<!-- CLAWGUARD_OVERRIDE_START -->";
const OVERRIDE_END = "<!-- CLAWGUARD_OVERRIDE_END -->";
const FRUSTRATED_OVERRIDE = `${OVERRIDE_START}
> [SYSTEM OVERRIDE: USER IS FRUSTRATED. BE HIGHLY CONCISE, APOLOGETIC, AND SOLUTION-ORIENTED.]
${OVERRIDE_END}
`;

function inferSentiment(text: string): AffectiveState {
  const value = text.toLowerCase();
  const frustratedSignals = [
    "frustrated",
    "annoyed",
    "angry",
    "upset",
    "broken",
    "not working",
    "this fails",
    "waste of time",
    "error",
    "wtf",
  ];
  const happySignals = ["thanks", "great", "awesome", "perfect", "love this", "nice", "excellent"];

  if (frustratedSignals.some((signal) => value.includes(signal))) {
    return "Frustrated";
  }

  if (happySignals.some((signal) => value.includes(signal))) {
    return "Happy";
  }

  return "Neutral";
}

function extractUserText(jsonLine: string): string | null {
  try {
    const parsed = JSON.parse(jsonLine) as Record<string, unknown>;
    if (parsed.role !== "user") {
      return null;
    }

    const content = parsed.content;
    if (typeof content === "string") {
      return content;
    }

    if (Array.isArray(content)) {
      const textParts = content
        .map((entry) => {
          if (!entry || typeof entry !== "object") {
            return "";
          }
          const item = entry as Record<string, unknown>;
          return typeof item.text === "string" ? item.text : "";
        })
        .filter(Boolean);
      return textParts.length > 0 ? textParts.join(" ") : null;
    }
  } catch {
    return null;
  }

  return null;
}

async function readLastNonEmptyLine(filePath: string): Promise<string | null> {
  const content = await fs.readFile(filePath, "utf8");
  const lines = content.split(/\r?\n/).map((line) => line.trim());
  for (let i = lines.length - 1; i >= 0; i -= 1) {
    if (lines[i]) {
      return lines[i];
    }
  }
  return null;
}

async function ensureDirectory(filePath: string): Promise<void> {
  await fs.mkdir(path.dirname(filePath), { recursive: true });
}

function removeManagedOverride(content: string): string {
  const escapedStart = OVERRIDE_START.replace(/[.*+?^${}()|[\]\\]/g, "\\$&");
  const escapedEnd = OVERRIDE_END.replace(/[.*+?^${}()|[\]\\]/g, "\\$&");
  const pattern = new RegExp(`${escapedStart}[\\s\\S]*?${escapedEnd}\\s*`, "g");
  return content.replace(pattern, "").trimStart();
}

export class AffectiveMemoryService {
  private options: AffectiveMemoryOptions;
  private ledger: AuditLedger;
  private watcher: FSWatcher | null = null;
  private currentState: AffectiveState = "Neutral";
  private writeQueue: Promise<void> = Promise.resolve();

  constructor(options: AffectiveMemoryOptions, ledger: AuditLedger) {
    this.options = options;
    this.ledger = ledger;
  }

  async start(): Promise<void> {
    const watchPath = path.join(this.options.agentsRootPath, "**", "sessions", "*.jsonl");
    this.watcher = chokidar.watch(watchPath, {
      ignoreInitial: true,
      awaitWriteFinish: {
        stabilityThreshold: 250,
        pollInterval: 100,
      },
    });

    const onChange = async (filePath: string) => {
      try {
        const line = await readLastNonEmptyLine(filePath);
        if (!line) {
          return;
        }
        const userText = extractUserText(line);
        if (!userText) {
          return;
        }
        const sentiment = inferSentiment(userText);
        await this.applyState(sentiment);
      } catch (error) {
        this.ledger.logAndSignAction("SYSTEM_ERROR", {
          module: "affective-memory",
          stage: "watcher",
          file_path: filePath,
          message: error instanceof Error ? error.message : String(error),
        });
      }
    };

    this.watcher.on("add", onChange);
    this.watcher.on("change", onChange);
  }

  async stop(): Promise<void> {
    if (this.watcher) {
      await this.watcher.close();
      this.watcher = null;
    }
  }

  private applyState(nextState: AffectiveState): Promise<void> {
    this.writeQueue = this.writeQueue.then(async () => {
      if (nextState === this.currentState) {
        return;
      }

      if (nextState === "Frustrated") {
        await this.setOverride();
        this.currentState = nextState;
        this.ledger.logAndSignAction("AFFECTIVE_OVERRIDE_SET", { state: nextState });
        return;
      }

      if (this.currentState === "Frustrated") {
        await this.clearOverride();
        this.ledger.logAndSignAction("AFFECTIVE_OVERRIDE_CLEARED", { state: nextState });
      }

      this.currentState = nextState;
    });

    return this.writeQueue;
  }

  private async setOverride(): Promise<void> {
    await ensureDirectory(this.options.soulFilePath);
    let content = "";
    try {
      content = await fs.readFile(this.options.soulFilePath, "utf8");
    } catch {
      content = "";
    }

    const cleaned = removeManagedOverride(content);
    const next = `${FRUSTRATED_OVERRIDE}\n${cleaned}`.trimEnd() + "\n";
    await fs.writeFile(this.options.soulFilePath, next, "utf8");
  }

  private async clearOverride(): Promise<void> {
    await ensureDirectory(this.options.soulFilePath);
    let content = "";
    try {
      content = await fs.readFile(this.options.soulFilePath, "utf8");
    } catch {
      content = "";
    }

    const cleaned = removeManagedOverride(content).trimEnd() + "\n";
    await fs.writeFile(this.options.soulFilePath, cleaned, "utf8");
  }
}
