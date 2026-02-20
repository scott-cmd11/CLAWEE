import { sha256Hex, stableStringify } from "./utils";

export type ChannelKind = "slack" | "teams" | "discord" | "email" | "webhook";

export interface ChannelInboundEvent {
  id: string;
  channel: ChannelKind;
  source: string;
  sender: string;
  text: string;
  timestamp: string;
  metadata: Record<string, unknown>;
}

export interface ChannelOutboundMessage {
  id: string;
  channel: ChannelKind;
  destination: string;
  text: string;
  timestamp: string;
  metadata: Record<string, unknown>;
}

export class ChannelHub {
  private inbound: ChannelInboundEvent[] = [];
  private outbound: ChannelOutboundMessage[] = [];
  private maxSize: number;

  constructor(maxSize = 2000) {
    this.maxSize = Math.max(100, maxSize);
  }

  ingestInbound(input: Omit<ChannelInboundEvent, "id" | "timestamp"> & { timestamp?: string }): ChannelInboundEvent {
    const timestamp = input.timestamp || new Date().toISOString();
    const id = sha256Hex(
      `${input.channel}|${input.source}|${input.sender}|${timestamp}|${stableStringify(input.metadata)}|${input.text}`,
    );
    const event: ChannelInboundEvent = {
      id,
      channel: input.channel,
      source: input.source,
      sender: input.sender,
      text: input.text,
      timestamp,
      metadata: input.metadata,
    };
    this.inbound.unshift(event);
    if (this.inbound.length > this.maxSize) {
      this.inbound.length = this.maxSize;
    }
    return event;
  }

  queueOutbound(input: Omit<ChannelOutboundMessage, "id" | "timestamp"> & { timestamp?: string }): ChannelOutboundMessage {
    const timestamp = input.timestamp || new Date().toISOString();
    const id = sha256Hex(
      `${input.channel}|${input.destination}|${timestamp}|${stableStringify(input.metadata)}|${input.text}`,
    );
    const message: ChannelOutboundMessage = {
      id,
      channel: input.channel,
      destination: input.destination,
      text: input.text,
      timestamp,
      metadata: input.metadata,
    };
    this.outbound.unshift(message);
    if (this.outbound.length > this.maxSize) {
      this.outbound.length = this.maxSize;
    }
    return message;
  }

  listInbound(limit = 100): ChannelInboundEvent[] {
    const safe = Math.min(Math.max(1, Math.floor(limit)), this.maxSize);
    return this.inbound.slice(0, safe);
  }

  listOutbound(limit = 100): ChannelOutboundMessage[] {
    const safe = Math.min(Math.max(1, Math.floor(limit)), this.maxSize);
    return this.outbound.slice(0, safe);
  }

  stats(): {
    inbound_total: number;
    outbound_total: number;
    inbound_by_channel: Record<string, number>;
    outbound_by_channel: Record<string, number>;
  } {
    const inboundByChannel: Record<string, number> = {};
    const outboundByChannel: Record<string, number> = {};
    for (const event of this.inbound) {
      inboundByChannel[event.channel] = (inboundByChannel[event.channel] || 0) + 1;
    }
    for (const message of this.outbound) {
      outboundByChannel[message.channel] = (outboundByChannel[message.channel] || 0) + 1;
    }
    return {
      inbound_total: this.inbound.length,
      outbound_total: this.outbound.length,
      inbound_by_channel: inboundByChannel,
      outbound_by_channel: outboundByChannel,
    };
  }
}
