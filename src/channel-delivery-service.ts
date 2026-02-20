import crypto from "node:crypto";
import type { AuditLedger } from "./audit-ledger";
import { AlertNotifier } from "./alert-notifier";
import {
  loadChannelConnectorCatalog,
  type ChannelConnectorCatalog,
} from "./channel-connector-catalog";
import { ChannelDestinationPolicy } from "./channel-destination-policy";
import { InteractionStore } from "./interaction-store";
import { RuntimeEgressGuard, RuntimeEgressPolicyError } from "./runtime-egress-guard";

export interface ChannelDeliveryOptions {
  pollSeconds: number;
  batchSize: number;
  maxAttempts: number;
  retryBaseSeconds: number;
  connectorConfigPath: string;
  connectorSigningKey: string;
}

export class ChannelDeliveryService {
  private options: ChannelDeliveryOptions;
  private store: InteractionStore;
  private ledger: AuditLedger;
  private alertNotifier: AlertNotifier;
  private timer: NodeJS.Timeout | null = null;
  private connectors: ChannelConnectorCatalog = { channels: {} };
  private connectorFingerprint = "";
  private connectorSigned = false;
  private running = false;
  private runtimeEgressGuard?: RuntimeEgressGuard;
  private destinationPolicy?: ChannelDestinationPolicy;

  constructor(
    options: ChannelDeliveryOptions,
    store: InteractionStore,
    ledger: AuditLedger,
    alertNotifier: AlertNotifier,
    runtimeEgressGuard?: RuntimeEgressGuard,
    destinationPolicy?: ChannelDestinationPolicy,
  ) {
    this.options = options;
    this.store = store;
    this.ledger = ledger;
    this.alertNotifier = alertNotifier;
    this.runtimeEgressGuard = runtimeEgressGuard;
    this.destinationPolicy = destinationPolicy;
  }

  start(): void {
    this.reloadConnectors();
    const intervalMs = Math.max(1, this.options.pollSeconds) * 1000;
    this.timer = setInterval(() => {
      void this.tick();
    }, intervalMs);
  }

  stop(): void {
    if (this.timer) {
      clearInterval(this.timer);
      this.timer = null;
    }
  }

  reloadConnectors(): void {
    const loaded = loadChannelConnectorCatalog(
      this.options.connectorConfigPath,
      this.options.connectorSigningKey,
    );
    this.connectors = loaded.catalog;
    this.connectorFingerprint = loaded.fingerprint;
    this.connectorSigned = loaded.signed;
  }

  getConnectorState(): { fingerprint: string; signed: boolean } {
    return {
      fingerprint: this.connectorFingerprint,
      signed: this.connectorSigned,
    };
  }

  private async tick(): Promise<void> {
    if (this.running) {
      return;
    }
    this.running = true;
    try {
      const pending = this.store.getPendingOutbound(this.options.batchSize);
      for (const item of pending) {
        await this.deliver(item);
      }
    } finally {
      this.running = false;
    }
  }

  private async deliver(
    item: {
      id: string;
      channel: string;
      destination: string;
      text: string;
      metadata: Record<string, unknown>;
      attempts: number;
    },
  ): Promise<void> {
    if (this.destinationPolicy) {
      const destinationDecision = this.destinationPolicy.evaluate(item.channel, item.destination);
      if (!destinationDecision.allowed) {
        this.store.markOutboundExhausted(
          item.id,
          item.attempts + 1,
          `Destination policy blocked: ${destinationDecision.reason}`,
        );
        this.ledger.logAndSignAction("CHANNEL_DESTINATION_BLOCKED", {
          stage: "delivery",
          message_id: item.id,
          channel: item.channel,
          destination: item.destination,
          reason: destinationDecision.reason,
          matched_pattern: destinationDecision.matched_pattern,
          source: destinationDecision.source,
        });
        return;
      }
    }

    const connector = this.connectors.channels[item.channel];
    if (!connector || !connector.webhook_url) {
      this.store.markOutboundExhausted(
        item.id,
        item.attempts + 1,
        `No connector configured for channel: ${item.channel}`,
      );
      this.ledger.logAndSignAction("CHANNEL_DELIVERY_FAILED", {
        message_id: item.id,
        channel: item.channel,
        reason: "missing-connector",
      });
      return;
    }

    const timeoutMs = Number(connector.timeout_ms || this.connectors.default_timeout_ms || 10000);
    const payload = {
      message_id: item.id,
      channel: item.channel,
      destination: item.destination,
      text: item.text,
      metadata: item.metadata,
      timestamp: new Date().toISOString(),
    };
    const body = JSON.stringify(payload);
    const headers: Record<string, string> = {
      "content-type": "application/json",
      ...(connector.auth_header ? { authorization: connector.auth_header } : {}),
    };
    if (connector.hmac_secret && connector.hmac_secret.trim()) {
      headers["x-clawee-signature"] = `sha256=${crypto
        .createHmac("sha256", connector.hmac_secret.trim())
        .update(body)
        .digest("hex")}`;
    }
    const controller = new AbortController();
    const timeout = setTimeout(() => controller.abort(), timeoutMs);

    try {
      if (this.runtimeEgressGuard) {
        await this.runtimeEgressGuard.assertUrlAllowed(
          `channel_connector:${item.channel}`,
          connector.webhook_url,
        );
      }
      const response = await fetch(connector.webhook_url, {
        method: "POST",
        headers,
        body,
        signal: controller.signal,
      });

      if (!response.ok) {
        throw new Error(`Delivery webhook returned ${response.status}`);
      }

      this.store.markOutboundSent(item.id);
      this.ledger.logAndSignAction("CHANNEL_DELIVERY_SENT", {
        message_id: item.id,
        channel: item.channel,
        destination: item.destination,
      });
    } catch (error) {
      const attempts = item.attempts + 1;
      const message =
        error instanceof RuntimeEgressPolicyError
          ? `Runtime egress denied: ${error.result.reason}`
          : error instanceof Error
            ? error.message
            : String(error);
      const runtimePolicyError = error instanceof RuntimeEgressPolicyError ? error : null;
      const isPolicyDeny = runtimePolicyError !== null;
      if (isPolicyDeny || attempts >= this.options.maxAttempts) {
        this.store.markOutboundExhausted(item.id, attempts, message);
      } else {
        const delaySeconds = Math.max(1, this.options.retryBaseSeconds) * Math.pow(2, attempts - 1);
        const nextAttemptAt = new Date(Date.now() + delaySeconds * 1000).toISOString();
        this.store.markOutboundFailed(item.id, attempts, nextAttemptAt, message);
      }

      this.ledger.logAndSignAction("CHANNEL_DELIVERY_FAILED", {
        message_id: item.id,
        channel: item.channel,
        attempts,
        error: message,
      });
      if (isPolicyDeny) {
        this.ledger.logAndSignAction("RUNTIME_EGRESS_BLOCKED", {
          path: connector.webhook_url,
          method: "POST",
          target: `channel_connector:${item.channel}`,
          details: runtimePolicyError.result,
        });
      }

      try {
        await this.alertNotifier.send({
          event: "channel_delivery_failed",
          severity: isPolicyDeny || attempts >= this.options.maxAttempts ? "critical" : "warning",
          message: "Claw-EE channel delivery failed.",
          details: {
            message_id: item.id,
            channel: item.channel,
            attempts,
            error: message,
          },
        });
      } catch {
        // Alerting failure should not break delivery loop.
      }
    } finally {
      clearTimeout(timeout);
    }
  }
}
