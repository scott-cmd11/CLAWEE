import type { ModalityType } from "./modality-hub";
import { stableStringify } from "./utils";

export interface ModalityPayloadValidationOptions {
  maxPayloadBytes: Record<ModalityType, number>;
  textMaxChars: number;
}

export interface ModalityPayloadValidationResult {
  ok: boolean;
  statusCode: 400 | 413;
  reason: string | null;
  payloadBytes: number;
  maxPayloadBytes: number;
  normalizedPayload: Record<string, unknown> | null;
}

const TEXT_KEYS = new Set(["text", "language", "sender", "metadata"]);
const VISION_KEYS = new Set([
  "image_url",
  "image_b64",
  "mime_type",
  "width",
  "height",
  "ocr_text",
  "metadata",
]);
const AUDIO_KEYS = new Set([
  "transcript",
  "audio_url",
  "audio_b64",
  "mime_type",
  "duration_ms",
  "speaker",
  "metadata",
]);
const ACTION_KEYS = new Set([
  "action",
  "status",
  "target",
  "arguments",
  "result",
  "error",
  "metadata",
]);

const VISION_MIME_TYPES = new Set([
  "image/jpeg",
  "image/png",
  "image/webp",
  "image/gif",
  "image/bmp",
  "image/tiff",
]);

const AUDIO_MIME_TYPES = new Set([
  "audio/wav",
  "audio/mpeg",
  "audio/mp4",
  "audio/webm",
  "audio/flac",
]);

const ACTION_STATUSES = new Set(["queued", "running", "succeeded", "failed"]);

function payloadBytes(value: unknown): number {
  return Buffer.byteLength(stableStringify(value), "utf8");
}

function okResult(
  normalizedPayload: Record<string, unknown>,
  bytes: number,
  maxBytes: number,
): ModalityPayloadValidationResult {
  return {
    ok: true,
    statusCode: 400,
    reason: null,
    payloadBytes: bytes,
    maxPayloadBytes: maxBytes,
    normalizedPayload,
  };
}

function errorResult(
  reason: string,
  statusCode: 400 | 413,
  bytes: number,
  maxBytes: number,
): ModalityPayloadValidationResult {
  return {
    ok: false,
    statusCode,
    reason,
    payloadBytes: bytes,
    maxPayloadBytes: maxBytes,
    normalizedPayload: null,
  };
}

function isPlainObject(value: unknown): value is Record<string, unknown> {
  if (!value || typeof value !== "object" || Array.isArray(value)) {
    return false;
  }
  const proto = Object.getPrototypeOf(value);
  return proto === Object.prototype || proto === null;
}

function rejectUnknownKeys(
  payload: Record<string, unknown>,
  allowed: Set<string>,
): string | null {
  for (const key of Object.keys(payload)) {
    if (!allowed.has(key)) {
      return `Unexpected payload field "${key}".`;
    }
  }
  return null;
}

function requireString(
  payload: Record<string, unknown>,
  key: string,
  maxChars: number,
): string | null {
  const value = payload[key];
  if (typeof value !== "string" || !value.trim()) {
    return null;
  }
  if (value.length > maxChars) {
    return null;
  }
  return value;
}

function optionalString(
  payload: Record<string, unknown>,
  key: string,
  maxChars: number,
): string | undefined {
  const value = payload[key];
  if (value === undefined) {
    return undefined;
  }
  if (typeof value !== "string" || !value.trim() || value.length > maxChars) {
    return undefined;
  }
  return value;
}

function optionalObject(
  payload: Record<string, unknown>,
  key: string,
): Record<string, unknown> | undefined {
  const value = payload[key];
  if (value === undefined) {
    return undefined;
  }
  if (!isPlainObject(value)) {
    return undefined;
  }
  return value;
}

function optionalInteger(
  payload: Record<string, unknown>,
  key: string,
  min: number,
  max: number,
): number | undefined {
  const value = payload[key];
  if (value === undefined) {
    return undefined;
  }
  if (typeof value !== "number" || !Number.isInteger(value) || value < min || value > max) {
    return undefined;
  }
  return value;
}

function validateTextPayload(
  payload: Record<string, unknown>,
  options: ModalityPayloadValidationOptions,
): ModalityPayloadValidationResult {
  const unknown = rejectUnknownKeys(payload, TEXT_KEYS);
  if (unknown) {
    return errorResult(unknown, 400, 0, options.maxPayloadBytes.text);
  }
  const text = requireString(payload, "text", options.textMaxChars);
  if (!text) {
    return errorResult(
      `Field "text" is required and must be <= ${options.textMaxChars} characters.`,
      400,
      0,
      options.maxPayloadBytes.text,
    );
  }
  const language = payload.language;
  if (language !== undefined && (typeof language !== "string" || !language.trim() || language.length > 32)) {
    return errorResult('Field "language" must be a non-empty string <= 32 characters.', 400, 0, options.maxPayloadBytes.text);
  }
  const sender = payload.sender;
  if (sender !== undefined && (typeof sender !== "string" || !sender.trim() || sender.length > 256)) {
    return errorResult('Field "sender" must be a non-empty string <= 256 characters.', 400, 0, options.maxPayloadBytes.text);
  }
  const metadata = payload.metadata;
  if (metadata !== undefined && !isPlainObject(metadata)) {
    return errorResult('Field "metadata" must be an object.', 400, 0, options.maxPayloadBytes.text);
  }
  const normalized: Record<string, unknown> = {
    text,
  };
  if (typeof language === "string") {
    normalized.language = language;
  }
  if (typeof sender === "string") {
    normalized.sender = sender;
  }
  if (metadata && isPlainObject(metadata)) {
    normalized.metadata = metadata;
  }
  const bytes = payloadBytes(normalized);
  if (bytes > options.maxPayloadBytes.text) {
    return errorResult(
      "Text modality payload exceeds max allowed size.",
      413,
      bytes,
      options.maxPayloadBytes.text,
    );
  }
  return okResult(normalized, bytes, options.maxPayloadBytes.text);
}

function validateVisionPayload(
  payload: Record<string, unknown>,
  options: ModalityPayloadValidationOptions,
): ModalityPayloadValidationResult {
  const unknown = rejectUnknownKeys(payload, VISION_KEYS);
  if (unknown) {
    return errorResult(unknown, 400, 0, options.maxPayloadBytes.vision);
  }
  const imageUrl = optionalString(payload, "image_url", 4096);
  const imageB64 = optionalString(payload, "image_b64", 2_000_000);
  const ocrText = optionalString(payload, "ocr_text", options.textMaxChars * 4);
  if (!imageUrl && !imageB64 && !ocrText) {
    return errorResult(
      'Vision payload requires at least one of: "image_url", "image_b64", or "ocr_text".',
      400,
      0,
      options.maxPayloadBytes.vision,
    );
  }
  const mimeType = optionalString(payload, "mime_type", 64);
  if (mimeType && !VISION_MIME_TYPES.has(mimeType.toLowerCase())) {
    return errorResult('Field "mime_type" is not an allowed vision MIME type.', 400, 0, options.maxPayloadBytes.vision);
  }
  const width = optionalInteger(payload, "width", 1, 20_000);
  if (payload.width !== undefined && width === undefined) {
    return errorResult('Field "width" must be an integer between 1 and 20000.', 400, 0, options.maxPayloadBytes.vision);
  }
  const height = optionalInteger(payload, "height", 1, 20_000);
  if (payload.height !== undefined && height === undefined) {
    return errorResult('Field "height" must be an integer between 1 and 20000.', 400, 0, options.maxPayloadBytes.vision);
  }
  const metadata = optionalObject(payload, "metadata");
  if (payload.metadata !== undefined && !metadata) {
    return errorResult('Field "metadata" must be an object.', 400, 0, options.maxPayloadBytes.vision);
  }

  const normalized: Record<string, unknown> = {};
  if (imageUrl) {
    normalized.image_url = imageUrl;
  }
  if (imageB64) {
    normalized.image_b64 = imageB64;
  }
  if (ocrText) {
    normalized.ocr_text = ocrText;
  }
  if (mimeType) {
    normalized.mime_type = mimeType.toLowerCase();
  }
  if (width !== undefined) {
    normalized.width = width;
  }
  if (height !== undefined) {
    normalized.height = height;
  }
  if (metadata) {
    normalized.metadata = metadata;
  }
  const bytes = payloadBytes(normalized);
  if (bytes > options.maxPayloadBytes.vision) {
    return errorResult(
      "Vision modality payload exceeds max allowed size.",
      413,
      bytes,
      options.maxPayloadBytes.vision,
    );
  }
  return okResult(normalized, bytes, options.maxPayloadBytes.vision);
}

function validateAudioPayload(
  payload: Record<string, unknown>,
  options: ModalityPayloadValidationOptions,
): ModalityPayloadValidationResult {
  const unknown = rejectUnknownKeys(payload, AUDIO_KEYS);
  if (unknown) {
    return errorResult(unknown, 400, 0, options.maxPayloadBytes.audio);
  }
  const transcript = optionalString(payload, "transcript", options.textMaxChars * 4);
  const audioUrl = optionalString(payload, "audio_url", 4096);
  const audioB64 = optionalString(payload, "audio_b64", 2_000_000);
  if (!transcript && !audioUrl && !audioB64) {
    return errorResult(
      'Audio payload requires at least one of: "transcript", "audio_url", or "audio_b64".',
      400,
      0,
      options.maxPayloadBytes.audio,
    );
  }
  const mimeType = optionalString(payload, "mime_type", 64);
  if (mimeType && !AUDIO_MIME_TYPES.has(mimeType.toLowerCase())) {
    return errorResult('Field "mime_type" is not an allowed audio MIME type.', 400, 0, options.maxPayloadBytes.audio);
  }
  const durationMs = optionalInteger(payload, "duration_ms", 0, 86_400_000);
  if (payload.duration_ms !== undefined && durationMs === undefined) {
    return errorResult('Field "duration_ms" must be an integer between 0 and 86400000.', 400, 0, options.maxPayloadBytes.audio);
  }
  const speaker = optionalString(payload, "speaker", 256);
  if (payload.speaker !== undefined && !speaker) {
    return errorResult('Field "speaker" must be a non-empty string <= 256 characters.', 400, 0, options.maxPayloadBytes.audio);
  }
  const metadata = optionalObject(payload, "metadata");
  if (payload.metadata !== undefined && !metadata) {
    return errorResult('Field "metadata" must be an object.', 400, 0, options.maxPayloadBytes.audio);
  }

  const normalized: Record<string, unknown> = {};
  if (transcript) {
    normalized.transcript = transcript;
  }
  if (audioUrl) {
    normalized.audio_url = audioUrl;
  }
  if (audioB64) {
    normalized.audio_b64 = audioB64;
  }
  if (mimeType) {
    normalized.mime_type = mimeType.toLowerCase();
  }
  if (durationMs !== undefined) {
    normalized.duration_ms = durationMs;
  }
  if (speaker) {
    normalized.speaker = speaker;
  }
  if (metadata) {
    normalized.metadata = metadata;
  }
  const bytes = payloadBytes(normalized);
  if (bytes > options.maxPayloadBytes.audio) {
    return errorResult(
      "Audio modality payload exceeds max allowed size.",
      413,
      bytes,
      options.maxPayloadBytes.audio,
    );
  }
  return okResult(normalized, bytes, options.maxPayloadBytes.audio);
}

function validateActionPayload(
  payload: Record<string, unknown>,
  options: ModalityPayloadValidationOptions,
): ModalityPayloadValidationResult {
  const unknown = rejectUnknownKeys(payload, ACTION_KEYS);
  if (unknown) {
    return errorResult(unknown, 400, 0, options.maxPayloadBytes.action);
  }
  const action = requireString(payload, "action", 128);
  if (!action) {
    return errorResult(
      'Field "action" is required and must be <= 128 characters.',
      400,
      0,
      options.maxPayloadBytes.action,
    );
  }
  const status = optionalString(payload, "status", 32);
  if (status && !ACTION_STATUSES.has(status.toLowerCase())) {
    return errorResult('Field "status" must be one of: queued, running, succeeded, failed.', 400, 0, options.maxPayloadBytes.action);
  }
  const target = optionalString(payload, "target", 512);
  if (payload.target !== undefined && !target) {
    return errorResult('Field "target" must be a non-empty string <= 512 characters.', 400, 0, options.maxPayloadBytes.action);
  }
  if (payload.arguments !== undefined && !isPlainObject(payload.arguments)) {
    return errorResult('Field "arguments" must be an object.', 400, 0, options.maxPayloadBytes.action);
  }
  if (payload.metadata !== undefined && !isPlainObject(payload.metadata)) {
    return errorResult('Field "metadata" must be an object.', 400, 0, options.maxPayloadBytes.action);
  }
  const errorText = optionalString(payload, "error", 4000);
  if (payload.error !== undefined && !errorText) {
    return errorResult('Field "error" must be a non-empty string <= 4000 characters.', 400, 0, options.maxPayloadBytes.action);
  }

  const normalized: Record<string, unknown> = {
    action,
  };
  if (status) {
    normalized.status = status.toLowerCase();
  }
  if (target) {
    normalized.target = target;
  }
  if (payload.arguments && isPlainObject(payload.arguments)) {
    normalized.arguments = payload.arguments;
  }
  if (payload.result !== undefined) {
    normalized.result = payload.result;
  }
  if (errorText) {
    normalized.error = errorText;
  }
  if (payload.metadata && isPlainObject(payload.metadata)) {
    normalized.metadata = payload.metadata;
  }
  const bytes = payloadBytes(normalized);
  if (bytes > options.maxPayloadBytes.action) {
    return errorResult(
      "Action modality payload exceeds max allowed size.",
      413,
      bytes,
      options.maxPayloadBytes.action,
    );
  }
  return okResult(normalized, bytes, options.maxPayloadBytes.action);
}

export function validateModalityPayload(
  modality: ModalityType,
  payload: unknown,
  options: ModalityPayloadValidationOptions,
): ModalityPayloadValidationResult {
  const maxPayloadByModality: Record<ModalityType, number> = {
    text: Math.max(256, Math.floor(options.maxPayloadBytes.text)),
    vision: Math.max(1024, Math.floor(options.maxPayloadBytes.vision)),
    audio: Math.max(1024, Math.floor(options.maxPayloadBytes.audio)),
    action: Math.max(256, Math.floor(options.maxPayloadBytes.action)),
  };
  const normalizedTextMaxChars = Math.max(32, Math.floor(options.textMaxChars));
  const normalizedOptions: ModalityPayloadValidationOptions = {
    maxPayloadBytes: maxPayloadByModality,
    textMaxChars: normalizedTextMaxChars,
  };
  if (!isPlainObject(payload)) {
    return errorResult(
      "Payload must be a JSON object.",
      400,
      0,
      normalizedOptions.maxPayloadBytes[modality],
    );
  }

  switch (modality) {
    case "text":
      return validateTextPayload(payload, normalizedOptions);
    case "vision":
      return validateVisionPayload(payload, normalizedOptions);
    case "audio":
      return validateAudioPayload(payload, normalizedOptions);
    case "action":
      return validateActionPayload(payload, normalizedOptions);
    default:
      return errorResult(
        "Unsupported modality type.",
        400,
        0,
        normalizedOptions.maxPayloadBytes.text,
      );
  }
}
