import fs from "node:fs";
import path from "node:path";

function normalizeVersion(raw) {
  const trimmed = String(raw || "").trim();
  if (!trimmed) {
    return "";
  }
  return trimmed.startsWith("v") ? trimmed.slice(1) : trimmed;
}

function extractSection(changelog, version) {
  const lines = changelog.split(/\r?\n/);
  const heading = `## ${version}`;
  const start = lines.findIndex((line) => line.trim() === heading);
  if (start < 0) {
    return "";
  }
  let end = lines.length;
  for (let i = start + 1; i < lines.length; i += 1) {
    if (lines[i].startsWith("## ")) {
      end = i;
      break;
    }
  }
  return lines.slice(start + 1, end).join("\n").trim();
}

function main() {
  const versionInput = process.argv[2];
  if (!versionInput) {
    console.error("Usage: node scripts/generate-release-notes.mjs <tag-or-version>");
    process.exit(1);
  }
  const normalizedVersion = normalizeVersion(versionInput);
  const tagName = `v${normalizedVersion}`;
  const changelogPath = path.join(process.cwd(), "CHANGELOG.md");
  const outputDir = path.join(process.cwd(), "release-notes");
  const outputPath = path.join(outputDir, `${tagName}.md`);
  const changelog = fs.readFileSync(changelogPath, "utf8");
  const section = extractSection(changelog, normalizedVersion);
  if (!section) {
    console.error(`Version section not found in CHANGELOG.md: ${normalizedVersion}`);
    process.exit(2);
  }

  const body = `# ${tagName}\n\n${section}\n`;
  fs.mkdirSync(outputDir, { recursive: true });
  fs.writeFileSync(outputPath, body, "utf8");
  console.log(outputPath);
}

main();
