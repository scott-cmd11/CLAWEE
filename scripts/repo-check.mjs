import fs from "node:fs";
import path from "node:path";

const root = process.cwd();

const requiredFiles = [
  "README.md",
  "CHANGELOG.md",
  "RELEASE.md",
  "openapi/claw-ee.openapi.yaml",
  "Dockerfile",
  "docker-compose.yml",
  "LICENSE",
  "SECURITY.md",
  "CONTRIBUTING.md",
  ".env.example",
  ".github/workflows/security-smoke.yml",
  ".github/workflows/release.yml",
  ".github/pull_request_template.md",
  ".github/ISSUE_TEMPLATE/bug_report.yml",
  ".github/ISSUE_TEMPLATE/feature_request.yml",
  "config/policy-catalog.v1.json",
  "config/model-registry.v1.json",
  "config/capability-catalog.v1.json",
  "config/approval-policy-catalog.v1.json",
  "release-notes/v0.1.0.md",
];

const signatureFiles = [
  "config/policy-catalog.v1.json",
  "config/capability-catalog.v1.json",
  "config/approval-policy-catalog.v1.json",
];

let failures = 0;

for (const rel of requiredFiles) {
  const full = path.join(root, rel);
  if (!fs.existsSync(full)) {
    failures += 1;
    console.error(`missing: ${rel}`);
  }
}

for (const rel of signatureFiles) {
  const full = path.join(root, rel);
  if (!fs.existsSync(full)) {
    continue;
  }
  try {
    const parsed = JSON.parse(fs.readFileSync(full, "utf8"));
    const sig = String(parsed.signature || "").trim();
    const hasV2 =
      parsed.signature_v2 &&
      typeof parsed.signature_v2 === "object" &&
      String(parsed.signature_v2.kid || "").trim() &&
      String(parsed.signature_v2.sig || "").trim();
    if (!sig && !hasV2) {
      failures += 1;
      console.error(`unsigned catalog: ${rel}`);
    }
  } catch (error) {
    failures += 1;
    console.error(`invalid json: ${rel}: ${error instanceof Error ? error.message : String(error)}`);
  }
}

if (failures > 0) {
  console.error(`repo-check: failed (${failures} issues)`);
  process.exit(1);
}

console.log("repo-check: ok");
