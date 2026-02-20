import { spawnSync } from "node:child_process";

const npmCommand = process.platform === "win32" ? "npm.cmd" : "npm";
const result = spawnSync(npmCommand, ["run", "smoke:security"], {
  stdio: "inherit",
  shell: true,
  env: {
    ...process.env,
    REPLAY_SMOKE_STRICT: "true",
  },
});

if (result.error) {
  console.error("smoke-security-strict: failed to invoke smoke:security", result.error);
  process.exit(1);
}

if (typeof result.status === "number") {
  process.exit(result.status);
}

process.exit(1);
