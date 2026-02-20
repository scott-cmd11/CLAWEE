import { sha256Hex, stableStringify } from "./utils";

export type ModalityType = "text" | "vision" | "audio" | "action";

export interface ModalityObservation {
  id: string;
  session_id: string;
  modality: ModalityType;
  source: string;
  timestamp: string;
  payload: unknown;
}

export class ModalityHub {
  private recent: ModalityObservation[] = [];
  private maxSize: number;

  constructor(maxSize = 1000) {
    this.maxSize = Math.max(100, maxSize);
  }

  ingest(observation: Omit<ModalityObservation, "id" | "timestamp"> & { timestamp?: string }): ModalityObservation {
    const timestamp = observation.timestamp || new Date().toISOString();
    const id = sha256Hex(
      `${observation.session_id}|${observation.modality}|${observation.source}|${timestamp}|${stableStringify(observation.payload)}`,
    );
    const normalized: ModalityObservation = {
      id,
      session_id: observation.session_id,
      modality: observation.modality,
      source: observation.source,
      timestamp,
      payload: observation.payload,
    };
    this.recent.unshift(normalized);
    if (this.recent.length > this.maxSize) {
      this.recent.length = this.maxSize;
    }
    return normalized;
  }

  listRecent(limit = 100): ModalityObservation[] {
    const safe = Math.min(Math.max(1, Math.floor(limit)), this.maxSize);
    return this.recent.slice(0, safe);
  }

  stats(): { total: number; by_modality: Record<string, number> } {
    const byModality: Record<string, number> = {
      text: 0,
      vision: 0,
      audio: 0,
      action: 0,
    };
    for (const item of this.recent) {
      byModality[item.modality] = (byModality[item.modality] || 0) + 1;
    }
    return {
      total: this.recent.length,
      by_modality: byModality,
    };
  }
}
