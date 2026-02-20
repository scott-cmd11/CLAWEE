import assert from "node:assert/strict";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";

import { InteractionStore } from "../dist/interaction-store.js";
import { createReplayStore } from "../dist/replay-store.js";

async function main() {
  const redisUrl = String(process.env.REPLAY_REDIS_URL || "").trim();
  if (!redisUrl) {
    console.log("replay-redis-smoke: skipped (REPLAY_REDIS_URL not set)");
    return;
  }

  const tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), "claw-ee-redis-smoke-"));
  const dbPath = path.join(tmpDir, "interactions.db");
  const interactionStore = new InteractionStore(dbPath);
  interactionStore.init();

  const replayStore = createReplayStore(
    {
      mode: "redis",
      redisUrl,
      redisPrefix: `clawee-smoke-${Date.now()}`,
      postgresUrl: "",
      postgresSchema: "clawee",
      postgresTablePrefix: "replay_",
      postgresConnectTimeoutMs: 10000,
      postgresSslMode: "disable",
    },
    interactionStore,
  );

  try {
    await replayStore.warmup();
    const nonceA = await replayStore.registerNonce("nonce-a", 60);
    const nonceAReplay = await replayStore.registerNonce("nonce-a", 60);
    const eventA = await replayStore.registerEventKey("event-a", 3600);
    const eventAReplay = await replayStore.registerEventKey("event-a", 3600);

    assert.equal(nonceA, true);
    assert.equal(nonceAReplay, false);
    assert.equal(eventA, true);
    assert.equal(eventAReplay, false);

    console.log("replay-redis-smoke: ok", replayStore.getState());
  } finally {
    await replayStore.close();
    interactionStore.close();
    fs.rmSync(tmpDir, { recursive: true, force: true });
  }
}

main().catch((error) => {
  console.error("replay-redis-smoke: failed", error);
  process.exit(1);
});
