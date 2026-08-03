const TOKEN_VERSION = "v1";
const TOKEN_AAD = new TextEncoder().encode("safesub:v1");
const UUID_PATTERN = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i;

export interface MappingPayload {
  v: 1;
  kind: "mapping";
  fakeId: string;
  realId: string;
  realQuery: string;
}

export interface SubscriptionPayload {
  v: 1;
  kind: "subscription";
  fakeId: string;
  realId: string;
  realQuery: string;
  upstreamUrl: string;
}

export type TokenPayload = MappingPayload | SubscriptionPayload;

function encodeBase64Url(bytes: Uint8Array): string {
  let binary = "";
  for (const byte of bytes) {
    binary += String.fromCharCode(byte);
  }
  return btoa(binary).replaceAll("+", "-").replaceAll("/", "_").replace(/=+$/u, "");
}

function decodeBase64Url(value: string): Uint8Array {
  if (!/^[A-Za-z0-9_-]+$/u.test(value)) {
    throw new Error("Base64URL 格式无效");
  }

  const padded = value.replaceAll("-", "+").replaceAll("_", "/").padEnd(Math.ceil(value.length / 4) * 4, "=");
  let binary: string;
  try {
    binary = atob(padded);
  } catch {
    throw new Error("Base64URL 格式无效");
  }

  const bytes = Uint8Array.from(binary, (character) => character.charCodeAt(0));
  if (encodeBase64Url(bytes) !== value) {
    throw new Error("Base64URL 格式无效");
  }
  return bytes;
}

export function decodeSecret(secret: string): Uint8Array {
  let bytes: Uint8Array;
  try {
    bytes = decodeBase64Url(secret.trim());
  } catch {
    throw new Error("TOKEN_KEY 必须是 32 字节的 Base64URL 密钥");
  }

  if (bytes.byteLength !== 32) {
    throw new Error("TOKEN_KEY 必须是 32 字节的 Base64URL 密钥");
  }
  return bytes;
}

function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === "object" && value !== null && !Array.isArray(value);
}

function isPayload(value: unknown): value is TokenPayload {
  if (!isRecord(value)) {
    return false;
  }

  const commonFieldsAreValid =
    value.v === 1 &&
    UUID_PATTERN.test(typeof value.fakeId === "string" ? value.fakeId : "") &&
    UUID_PATTERN.test(typeof value.realId === "string" ? value.realId : "") &&
    typeof value.realQuery === "string";

  if (!commonFieldsAreValid) {
    return false;
  }
  if (value.kind === "mapping") {
    return true;
  }
  return value.kind === "subscription" && typeof value.upstreamUrl === "string";
}

async function importKey(secret: string): Promise<CryptoKey> {
  return crypto.subtle.importKey("raw", decodeSecret(secret), "AES-GCM", false, ["encrypt", "decrypt"]);
}

export async function sealToken(payload: TokenPayload, secret: string): Promise<string> {
  const nonce = crypto.getRandomValues(new Uint8Array(12));
  const plaintext = new TextEncoder().encode(JSON.stringify(payload));
  const key = await importKey(secret);
  const encrypted = await crypto.subtle.encrypt(
    { name: "AES-GCM", iv: nonce, additionalData: TOKEN_AAD },
    key,
    plaintext,
  );

  return `${TOKEN_VERSION}.${encodeBase64Url(nonce)}.${encodeBase64Url(new Uint8Array(encrypted))}`;
}

export async function openToken(token: string, secret: string): Promise<TokenPayload> {
  try {
    const parts = token.split(".");
    if (parts.length !== 3 || parts[0] !== TOKEN_VERSION || parts[1] === undefined || parts[2] === undefined) {
      throw new Error("令牌格式无效");
    }

    const nonce = decodeBase64Url(parts[1]);
    const ciphertext = decodeBase64Url(parts[2]);
    if (nonce.byteLength !== 12) {
      throw new Error("令牌 nonce 无效");
    }

    const key = await importKey(secret);
    const decrypted = await crypto.subtle.decrypt(
      { name: "AES-GCM", iv: nonce, additionalData: TOKEN_AAD },
      key,
      ciphertext,
    );
    const parsed: unknown = JSON.parse(
      new TextDecoder("utf-8", { fatal: true, ignoreBOM: false }).decode(decrypted),
    );
    if (!isPayload(parsed)) {
      throw new Error("令牌负载无效");
    }
    return parsed;
  } catch (error: unknown) {
    if (error instanceof Error && error.message === "令牌负载无效") {
      throw error;
    }
    throw new Error("令牌无效");
  }
}
