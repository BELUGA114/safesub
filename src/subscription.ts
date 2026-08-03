import { AppError } from "./errors";
import type { MappingPayload } from "./token";
import { restoreVlessLine } from "./vless";

const MAX_UPSTREAM_URL_LENGTH = 2048;
const MAX_SUBSCRIPTION_BYTES = 2 * 1024 * 1024;
const DEFAULT_TIMEOUT_MS = 15_000;
const MAX_REDIRECTS = 3;

export interface RestoreResult {
  text: string;
  matchCount: number;
}

export interface FetchOptions {
  timeoutMs?: number;
}

function rejectUrl(): never {
  throw new AppError("invalid_upstream_url", "上游 URL 必须是公开的 HTTPS 地址", 400);
}

function isBlockedIpv4(hostname: string): boolean {
  const parts = hostname.split(".");
  if (parts.length !== 4 || parts.some((part) => !/^\d{1,3}$/u.test(part))) {
    return false;
  }
  const octets = parts.map(Number);
  if (octets.some((octet) => octet < 0 || octet > 255)) {
    return true;
  }

  const first = octets[0] ?? 0;
  const second = octets[1] ?? 0;
  return (
    first === 0 ||
    first === 10 ||
    first === 127 ||
    (first === 100 && second >= 64 && second <= 127) ||
    (first === 169 && second === 254) ||
    (first === 172 && second >= 16 && second <= 31) ||
    (first === 192 && (second === 0 || second === 168)) ||
    (first === 198 && (second === 18 || second === 19 || second === 51)) ||
    (first === 203 && second === 0) ||
    first >= 224
  );
}

function isBlockedIpv6(hostname: string): boolean {
  const normalized = hostname.replace(/^\[|\]$/gu, "").toLowerCase();
  if (!normalized.includes(":")) {
    return false;
  }
  return (
    normalized === "::" ||
    normalized === "::1" ||
    normalized.startsWith("fc") ||
    normalized.startsWith("fd") ||
    /^fe[89ab]/u.test(normalized) ||
    normalized.startsWith("ff") ||
    normalized.startsWith("2001:db8") ||
    normalized.startsWith("::ffff:")
  );
}

export function validateUpstreamUrl(input: string): URL {
  if (input.length === 0 || input.length > MAX_UPSTREAM_URL_LENGTH) {
    return rejectUrl();
  }

  let url: URL;
  try {
    url = new URL(input);
  } catch {
    return rejectUrl();
  }

  const hostname = url.hostname.toLowerCase().replace(/\.$/u, "");
  if (
    url.protocol !== "https:" ||
    url.username !== "" ||
    url.password !== "" ||
    hostname === "localhost" ||
    hostname.endsWith(".localhost") ||
    hostname.endsWith(".local") ||
    isBlockedIpv4(hostname) ||
    isBlockedIpv6(hostname)
  ) {
    return rejectUrl();
  }
  return url;
}

function decodeBase64Bytes(input: string): Uint8Array {
  const compact = input.replace(/[\t\n\f\r ]/gu, "");
  if (compact.length === 0 || !/^[A-Za-z0-9+/_-]*={0,2}$/u.test(compact) || compact.length % 4 === 1) {
    throw new AppError("invalid_base64", "上游订阅不是有效的 Base64", 502);
  }

  const firstPadding = compact.indexOf("=");
  if (firstPadding >= 0 && firstPadding < compact.length - 2) {
    throw new AppError("invalid_base64", "上游订阅不是有效的 Base64", 502);
  }

  const normalized = compact.replaceAll("-", "+").replaceAll("_", "/");
  const padded = normalized.padEnd(Math.ceil(normalized.length / 4) * 4, "=");
  try {
    const binary = atob(padded);
    return Uint8Array.from(binary, (character) => character.charCodeAt(0));
  } catch {
    throw new AppError("invalid_base64", "上游订阅不是有效的 Base64", 502);
  }
}

export function decodeSubscription(body: string): string {
  const bytes = decodeBase64Bytes(body);
  try {
    return new TextDecoder("utf-8", { fatal: true, ignoreBOM: false }).decode(bytes);
  } catch {
    throw new AppError("invalid_utf8", "上游订阅不是有效的 UTF-8 文本", 502);
  }
}

export function encodeSubscription(text: string): string {
  const bytes = new TextEncoder().encode(text);
  let binary = "";
  for (let offset = 0; offset < bytes.length; offset += 32_768) {
    binary += String.fromCharCode(...bytes.subarray(offset, offset + 32_768));
  }
  return btoa(binary);
}

export function restoreSubscription(text: string, mapping: MappingPayload): RestoreResult {
  let matchCount = 0;
  const lines = text.split(/\r?\n/u).map((line) => {
    const restored = restoreVlessLine(line, mapping);
    if (restored.matched) {
      matchCount += 1;
    }
    return restored.line;
  });

  if (matchCount === 0) {
    throw new AppError("node_not_found", "上游订阅中未找到伪装节点", 422);
  }
  return { text: lines.join("\n"), matchCount };
}

async function readLimitedBody(response: Response): Promise<string> {
  const declaredLength = Number(response.headers.get("content-length"));
  if (Number.isFinite(declaredLength) && declaredLength > MAX_SUBSCRIPTION_BYTES) {
    throw new AppError("upstream_too_large", "上游订阅过大", 502);
  }
  if (response.body === null) {
    return "";
  }

  const reader = response.body.getReader();
  const chunks: Uint8Array[] = [];
  let total = 0;
  while (true) {
    const result = await reader.read();
    if (result.done) {
      break;
    }
    total += result.value.byteLength;
    if (total > MAX_SUBSCRIPTION_BYTES) {
      await reader.cancel();
      throw new AppError("upstream_too_large", "上游订阅过大", 502);
    }
    chunks.push(result.value);
  }

  const body = new Uint8Array(total);
  let offset = 0;
  for (const chunk of chunks) {
    body.set(chunk, offset);
    offset += chunk.byteLength;
  }
  return new TextDecoder().decode(body);
}

export async function fetchAndRestore(
  upstreamUrl: string,
  mapping: MappingPayload,
  fetcher: typeof fetch = fetch,
  options: FetchOptions = {},
): Promise<string> {
  let currentUrl = validateUpstreamUrl(upstreamUrl);
  const controller = new AbortController();
  const timeoutId = setTimeout(() => controller.abort(), options.timeoutMs ?? DEFAULT_TIMEOUT_MS);

  try {
    for (let redirectCount = 0; redirectCount <= MAX_REDIRECTS; redirectCount += 1) {
      const response = await fetcher(currentUrl.href, {
        method: "GET",
        redirect: "manual",
        signal: controller.signal,
        headers: { accept: "text/plain, application/octet-stream;q=0.9" },
      });

      if (response.status >= 300 && response.status < 400) {
        const location = response.headers.get("location");
        if (location === null || redirectCount === MAX_REDIRECTS) {
          throw new AppError("upstream_redirect", "上游订阅重定向无效或次数过多", 502);
        }
        currentUrl = validateUpstreamUrl(new URL(location, currentUrl).href);
        continue;
      }

      if (!response.ok) {
        throw new AppError("upstream_status", `上游订阅返回 HTTP ${response.status}`, 502);
      }

      const encoded = await readLimitedBody(response);
      const restored = restoreSubscription(decodeSubscription(encoded), mapping).text;
      if (new TextEncoder().encode(restored).byteLength > MAX_SUBSCRIPTION_BYTES) {
        throw new AppError("upstream_too_large", "恢复后的订阅过大", 502);
      }
      return encodeSubscription(restored);
    }
    throw new AppError("upstream_redirect", "上游订阅重定向次数过多", 502);
  } catch (error: unknown) {
    if (error instanceof AppError) {
      throw error;
    }
    if (controller.signal.aborted || (error instanceof DOMException && error.name === "AbortError")) {
      throw new AppError("upstream_timeout", "上游订阅请求超时", 504);
    }
    throw new AppError("upstream_fetch_failed", "无法读取上游订阅", 502);
  } finally {
    clearTimeout(timeoutId);
  }
}
