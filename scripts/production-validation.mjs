import { spawnSync } from "node:child_process";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";

function nowIso() {
  return new Date().toISOString();
}

function parseArgs(argv) {
  const out = {
    profile: "staging",
    iterations: null,
  };
  for (const raw of argv) {
    if (raw.startsWith("--profile=")) {
      out.profile = String(raw.slice("--profile=".length) || "").trim().toLowerCase();
      continue;
    }
    if (raw.startsWith("--iterations=")) {
      const value = Number(raw.slice("--iterations=".length));
      if (Number.isFinite(value) && value > 0) {
        out.iterations = Math.floor(value);
      }
    }
  }
  return out;
}

function profileConfig(profile, iterationsOverride) {
  if (profile === "quick") {
    return {
      profile: "quick",
      iterations: iterationsOverride ?? 1,
      runStrictSmoke: true,
      includeGateLoop: false,
    };
  }
  if (profile === "soak") {
    return {
      profile: "soak",
      iterations: iterationsOverride ?? 10,
      runStrictSmoke: true,
      includeGateLoop: true,
    };
  }
  return {
    profile: "staging",
    iterations: iterationsOverride ?? 3,
    runStrictSmoke: true,
    includeGateLoop: true,
  };
}

function commandPrefix() {
  return process.platform === "win32" ? "npm.cmd" : "npm";
}

function runStep(step, command, args = []) {
  const startedAt = Date.now();
  const child = spawnSync(command, args, {
    stdio: "pipe",
    encoding: "utf8",
    shell: false,
    env: process.env,
  });
  const durationMs = Date.now() - startedAt;
  return {
    step,
    command: [command, ...args].join(" "),
    exitCode: child.status ?? -1,
    durationMs,
    ok: child.status === 0,
    stdout: String(child.stdout || ""),
    stderr: String(child.stderr || ""),
  };
}

function requireStrictReplayEnv() {
  const redis = String(process.env.REPLAY_REDIS_URL || "").trim();
  const postgres = String(process.env.REPLAY_POSTGRES_URL || "").trim();
  const missing = [];
  if (!redis) {
    missing.push("REPLAY_REDIS_URL");
  }
  if (!postgres) {
    missing.push("REPLAY_POSTGRES_URL");
  }
  return {
    ok: missing.length === 0,
    missing,
  };
}

function ensureArtifactsDir() {
  const dir = path.join(process.cwd(), "artifacts", "production-validation");
  fs.mkdirSync(dir, { recursive: true });
  return dir;
}

function printStep(result) {
  const status = result.ok ? "PASS" : "FAIL";
  // eslint-disable-next-line no-console
  console.log(`[${status}] ${result.step} (${result.durationMs}ms): ${result.command}`);
  if (!result.ok) {
    if (result.stdout.trim()) {
      // eslint-disable-next-line no-console
      console.log(result.stdout.trim());
    }
    if (result.stderr.trim()) {
      // eslint-disable-next-line no-console
      console.error(result.stderr.trim());
    }
  }
}

function summarize(results) {
  const total = results.length;
  const failed = results.filter((item) => !item.ok).length;
  const passed = total - failed;
  return {
    total,
    passed,
    failed,
    success: failed === 0,
  };
}

function main() {
  const parsed = parseArgs(process.argv.slice(2));
  const config = profileConfig(parsed.profile, parsed.iterations);
  const npm = commandPrefix();
  const startedAt = nowIso();
  const runId = new Date().toISOString().replace(/[:.]/g, "-");
  const results = [];

  const strictEnv = requireStrictReplayEnv();
  if (config.runStrictSmoke && !strictEnv.ok) {
    const report = {
      run_id: runId,
      started_at: startedAt,
      finished_at: nowIso(),
      host: os.hostname(),
      node: process.version,
      profile: config.profile,
      iterations: config.iterations,
      strict_replay_env: strictEnv,
      summary: {
        total: 0,
        passed: 0,
        failed: 1,
        success: false,
      },
      results: [],
      error: `Missing required strict replay env vars: ${strictEnv.missing.join(", ")}`,
    };
    const outDir = ensureArtifactsDir();
    const reportPath = path.join(outDir, `report-${runId}.json`);
    fs.writeFileSync(reportPath, `${JSON.stringify(report, null, 2)}\n`, "utf8");
    // eslint-disable-next-line no-console
    console.error(report.error);
    // eslint-disable-next-line no-console
    console.error(`report: ${reportPath}`);
    process.exit(1);
  }

  const baselineSteps = [
    { step: "build", command: npm, args: ["run", "build"] },
    { step: "repo-check", command: npm, args: ["run", "repo:check"] },
  ];
  for (const item of baselineSteps) {
    const result = runStep(item.step, item.command, item.args);
    results.push(result);
    printStep(result);
    if (!result.ok) {
      break;
    }
  }

  if (results.every((item) => item.ok) && config.runStrictSmoke) {
    const strictSmoke = runStep("smoke-security-strict", npm, ["run", "smoke:security:strict"]);
    results.push(strictSmoke);
    printStep(strictSmoke);
  }

  if (results.every((item) => item.ok) && config.includeGateLoop) {
    for (let i = 1; i <= config.iterations; i += 1) {
      const gate = runStep(`gate-integration-loop-${i}`, "node", ["tests/gate-integration-smoke.mjs"]);
      results.push(gate);
      printStep(gate);
      if (!gate.ok) {
        break;
      }
      const initiative = runStep(`initiative-loop-${i}`, "node", ["tests/initiative-smoke.mjs"]);
      results.push(initiative);
      printStep(initiative);
      if (!initiative.ok) {
        break;
      }
    }
  }

  const summary = summarize(results);
  const report = {
    run_id: runId,
    started_at: startedAt,
    finished_at: nowIso(),
    host: os.hostname(),
    node: process.version,
    profile: config.profile,
    iterations: config.iterations,
    strict_replay_env: strictEnv,
    summary,
    results: results.map((item) => ({
      step: item.step,
      command: item.command,
      exit_code: item.exitCode,
      ok: item.ok,
      duration_ms: item.durationMs,
    })),
  };

  const outDir = ensureArtifactsDir();
  const reportPath = path.join(outDir, `report-${runId}.json`);
  fs.writeFileSync(reportPath, `${JSON.stringify(report, null, 2)}\n`, "utf8");

  // eslint-disable-next-line no-console
  console.log(`report: ${reportPath}`);
  // eslint-disable-next-line no-console
  console.log(`summary: ${summary.passed}/${summary.total} steps passed`);

  process.exit(summary.success ? 0 : 1);
}

main();
