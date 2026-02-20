import assert from "node:assert/strict";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";

import { InteractionStore } from "../dist/interaction-store.js";
import { createReplayStore } from "../dist/replay-store.js";

function strictModeEnabled() {
  const raw = String(process.env.REPLAY_SMOKE_STRICT || "").trim().toLowerCase();
  return raw === "1" || raw === "true" || raw === "yes" || raw === "on";
}

async function main() {
  const postgresUrl = String(process.env.REPLAY_POSTGRES_URL || "").trim();
  const strictMode = strictModeEnabled();
  if (!postgresUrl) {
    if (strictMode) {
      throw new Error(
        "replay-postgres-smoke: REPLAY_POSTGRES_URL is required when REPLAY_SMOKE_STRICT=true",
      );
    }
    console.log("replay-postgres-smoke: skipped (REPLAY_POSTGRES_URL not set)");
    return;
  }

  const tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), "claw-ee-postgres-smoke-"));
  const dbPath = path.join(tmpDir, "interactions.db");
  const interactionStore = new InteractionStore(dbPath);
  interactionStore.init();

  const replayStore = createReplayStore(
    {
      mode: "postgres",
      redisUrl: "",
      redisPrefix: "clawee",
      postgresUrl,
      postgresSchema: String(process.env.REPLAY_POSTGRES_SCHEMA || "clawee"),
      postgresTablePrefix: String(process.env.REPLAY_POSTGRES_TABLE_PREFIX || "replay_"),
      postgresConnectTimeoutMs: Number(process.env.REPLAY_POSTGRES_CONNECT_TIMEOUT_MS || 10000),
      postgresSslMode: String(process.env.REPLAY_POSTGRES_SSL_MODE || "disable"),
    },
    interactionStore,
  );

  try {
    await replayStore.warmup();
    const keySuffix = `${Date.now()}`;
    const nonceKey = `nonce-${keySuffix}`;
    const eventKey = `event-${keySuffix}`;
    const nonceA = await replayStore.registerNonce(nonceKey, 60);
    const nonceAReplay = await replayStore.registerNonce(nonceKey, 60);
    const eventA = await replayStore.registerEventKey(eventKey, 3600);
    const eventAReplay = await replayStore.registerEventKey(eventKey, 3600);

    assert.equal(nonceA, true);
    assert.equal(nonceAReplay, false);
    assert.equal(eventA, true);
    assert.equal(eventAReplay, false);

    console.log("replay-postgres-smoke: ok", replayStore.getState());
  } finally {
    await replayStore.close();
    interactionStore.close();
    fs.rmSync(tmpDir, { recursive: true, force: true });
  }
}

main().catch((error) => {
  console.error("replay-postgres-smoke: failed", error);
  process.exit(1);
});
