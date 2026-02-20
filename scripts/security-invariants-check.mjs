import fs from "node:fs";
import path from "node:path";

const projectRoot = process.cwd();
const gatePath = path.join(projectRoot, "src", "uncertainty-gate.ts");
const deliveryPath = path.join(projectRoot, "src", "channel-delivery-service.ts");

let failures = 0;

function fail(message) {
  failures += 1;
  console.error(`security-invariants-check: ${message}`);
}

if (!fs.existsSync(gatePath)) {
  fail("missing src/uncertainty-gate.ts");
} else {
  const gate = fs.readFileSync(gatePath, "utf8");
  const requiredMarkers = [
    'runtimeEgressGuard.assertAllowed("upstream_base_url")',
    "capabilityPolicy.evaluateToolExecution(",
    "modelRegistry.evaluate(",
    "policyEngine.evaluate(",
    "approvalService.getOrCreatePending(",
    "budgetController.evaluateProjected(",
    "app.get(\"/_clawee/control/security/invariants\"",
    "app.post(\"/_clawee/control/security/conformance/export\"",
    "app.post(\"/_clawee/control/security/conformance/verify\"",
    "__claweeSecurityDecisionId",
    "invariantCheck({",
  ];
  for (const marker of requiredMarkers) {
    if (!gate.includes(marker)) {
      fail(`uncertainty-gate missing marker: ${marker}`);
    }
  }
  const guardIndex = gate.indexOf("app.use(guardMiddleware);");
  const proxyIndex = gate.indexOf("app.use(\"/\", proxy);");
  if (guardIndex === -1 || proxyIndex === -1) {
    fail("could not locate guard/proxy middleware ordering markers");
  } else if (guardIndex > proxyIndex) {
    fail("proxy middleware is registered before guard middleware");
  }
}

if (!fs.existsSync(deliveryPath)) {
  fail("missing src/channel-delivery-service.ts");
} else {
  const delivery = fs.readFileSync(deliveryPath, "utf8");
  if (!delivery.includes("destinationPolicy.evaluate(")) {
    fail("channel-delivery-service missing destination policy check");
  }
}

if (failures > 0) {
  console.error(`security-invariants-check: failed (${failures} issue(s))`);
  process.exit(1);
}

console.log("security-invariants-check: ok");
