import { AppError } from "./errors";
import { fetchAndRestore, validateUpstreamUrl } from "./subscription";
import {
  openToken,
  sealToken,
  type MappingPayload,
  type SubscriptionPayload,
} from "./token";
import { createMaskedVless, parseRealVless } from "./vless";

const MAX_JSON_BODY_BYTES = 16 * 1024;
const MAX_VLESS_URI_LENGTH = 4096;
const MAX_TOKEN_LENGTH = 12 * 1024;

interface AssetBinding {
  fetch(request: Request): Promise<Response>;
}

export interface Env {
  TOKEN_KEY: string;
  ASSETS: AssetBinding;
}

interface ErrorBody {
  error: {
    code: string;
    message: string;
  };
}

function jsonResponse(body: unknown, status = 200): Response {
  return Response.json(body, {
    status,
    headers: {
      "cache-control": "no-store",
      "x-content-type-options": "nosniff",
    },
  });
}

function errorResponse(error: AppError): Response {
  const body: ErrorBody = {
    error: {
      code: error.code,
      message: error.message,
    },
  };
  return jsonResponse(body, error.status);
}

function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === "object" && value !== null && !Array.isArray(value);
}

async function readJson(request: Request): Promise<Record<string, unknown>> {
  const contentLength = Number(request.headers.get("content-length"));
  if (Number.isFinite(contentLength) && contentLength > MAX_JSON_BODY_BYTES) {
    throw new AppError("body_too_large", "请求内容超过 16 KiB", 413);
  }

  if (request.body === null) {
    throw new AppError("invalid_json", "请求必须包含 JSON 正文", 400);
  }
  const reader = request.body.getReader();
  const chunks: Uint8Array[] = [];
  let total = 0;
  while (true) {
    const result = await reader.read();
    if (result.done) {
      break;
    }
    total += result.value.byteLength;
    if (total > MAX_JSON_BODY_BYTES) {
      await reader.cancel();
      throw new AppError("body_too_large", "请求内容超过 16 KiB", 413);
    }
    chunks.push(result.value);
  }

  const bytes = new Uint8Array(total);
  let offset = 0;
  for (const chunk of chunks) {
    bytes.set(chunk, offset);
    offset += chunk.byteLength;
  }

  let parsed: unknown;
  try {
    parsed = JSON.parse(new TextDecoder("utf-8", { fatal: true, ignoreBOM: false }).decode(bytes));
  } catch {
    throw new AppError("invalid_json", "请求正文不是有效的 JSON", 400);
  }
  if (!isRecord(parsed)) {
    throw new AppError("invalid_json", "请求正文必须是 JSON 对象", 400);
  }
  return parsed;
}

function requireString(body: Record<string, unknown>, field: string): string {
  const value = body[field];
  if (typeof value !== "string" || value.trim() === "") {
    throw new AppError("invalid_request", `字段 ${field} 必须是非空字符串`, 400);
  }
  return value.trim();
}

async function handleMask(request: Request, env: Env): Promise<Response> {
  const body = await readJson(request);
  const vlessUri = requireString(body, "vlessUri");
  if (vlessUri.length > MAX_VLESS_URI_LENGTH) {
    throw new AppError("invalid_vless", "VLESS URI 过长", 400);
  }

  let parsed: ReturnType<typeof parseRealVless>;
  try {
    parsed = parseRealVless(vlessUri);
  } catch {
    throw new AppError("invalid_vless", "VLESS URI 格式无效", 400);
  }

  const result = createMaskedVless(parsed);
  const mappingToken = await sealToken(result.mapping, env.TOKEN_KEY);
  return jsonResponse({ maskedUri: result.maskedUri, mappingToken });
}

async function parseMappingToken(token: string, secret: string): Promise<MappingPayload> {
  if (token.length > MAX_TOKEN_LENGTH) {
    throw new AppError("invalid_token", "映射令牌无效", 400);
  }

  let payload: Awaited<ReturnType<typeof openToken>>;
  try {
    payload = await openToken(token, secret);
  } catch {
    throw new AppError("invalid_token", "映射令牌无效", 400);
  }
  if (payload.kind !== "mapping") {
    throw new AppError("invalid_token_type", "令牌类型不适用于此操作", 400);
  }
  return payload;
}

async function handleCreateSubscription(request: Request, env: Env): Promise<Response> {
  const body = await readJson(request);
  const mappingToken = requireString(body, "mappingToken");
  const upstreamUrl = requireString(body, "upstreamUrl");
  const mapping = await parseMappingToken(mappingToken, env.TOKEN_KEY);
  const normalizedUpstreamUrl = validateUpstreamUrl(upstreamUrl).href;

  const payload: SubscriptionPayload = {
    ...mapping,
    kind: "subscription",
    upstreamUrl: normalizedUpstreamUrl,
  };
  const token = await sealToken(payload, env.TOKEN_KEY);
  const subscriptionUrl = new URL(`/sub/${token}`, request.url).href;
  return jsonResponse({ subscriptionUrl });
}

async function handleSubscription(token: string, env: Env): Promise<Response> {
  if (token.length === 0 || token.length > MAX_TOKEN_LENGTH) {
    throw new AppError("invalid_token", "订阅令牌无效", 400);
  }

  let payload: Awaited<ReturnType<typeof openToken>>;
  try {
    payload = await openToken(token, env.TOKEN_KEY);
  } catch {
    throw new AppError("invalid_token", "订阅令牌无效", 400);
  }
  if (payload.kind !== "subscription") {
    throw new AppError("invalid_token_type", "令牌类型不适用于此操作", 400);
  }

  const mapping: MappingPayload = {
    v: 1,
    kind: "mapping",
    fakeId: payload.fakeId,
    realId: payload.realId,
    realQuery: payload.realQuery,
  };
  const restored = await fetchAndRestore(payload.upstreamUrl, mapping);
  return new Response(restored, {
    status: 200,
    headers: {
      "content-type": "text/plain; charset=utf-8",
      "cache-control": "no-store",
      "x-content-type-options": "nosniff",
    },
  });
}

async function route(request: Request, env: Env): Promise<Response> {
  const url = new URL(request.url);
  if (url.pathname === "/api/mask") {
    if (request.method !== "POST") {
      throw new AppError("method_not_allowed", "此接口仅支持 POST", 405);
    }
    return handleMask(request, env);
  }
  if (url.pathname === "/api/subscriptions") {
    if (request.method !== "POST") {
      throw new AppError("method_not_allowed", "此接口仅支持 POST", 405);
    }
    return handleCreateSubscription(request, env);
  }
  if (url.pathname.startsWith("/sub/")) {
    if (request.method !== "GET") {
      throw new AppError("method_not_allowed", "订阅链接仅支持 GET", 405);
    }
    return handleSubscription(url.pathname.slice("/sub/".length), env);
  }
  return env.ASSETS.fetch(request);
}

const worker = {
  async fetch(request: Request, env: Env): Promise<Response> {
    try {
      return await route(request, env);
    } catch (error: unknown) {
      if (error instanceof AppError) {
        return errorResponse(error);
      }
      return errorResponse(new AppError("internal_error", "服务暂时不可用", 500));
    }
  },
};

export default worker;
