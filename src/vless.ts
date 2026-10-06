import { AppError } from "./errors";
import type { MappingPayload } from "./token";

const UUID_PATTERN = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i;

// 诱饵查询串只需语法有效且不泄露真实字段；第三方服务对 type 的支持不同，按用户选择生成。
export const DECOY_QUERIES = {
  ws: "encryption=none&security=tls&type=ws&host=placeholder.invalid&path=%2Fsafesub&sni=placeholder.invalid",
  xhttp:
    "encryption=none&security=tls&type=xhttp&host=placeholder.invalid&path=%2Fsafesub&sni=placeholder.invalid&mode=auto",
} as const;

export type Transport = keyof typeof DECOY_QUERIES;

// 把真实查询串的传输参数重写为指定类型：替换 type、按目标处理 mode，其余参数原样保留。
// 仅适用于同一端点同时提供 ws 与 xhttp 的情况；若两种传输路径不同，应直接在第一步填入对应传输的真实节点。
export function applyTransportOverride(query: string, transport: Transport): string {
  const parts = query.split("&").filter((part) => part !== "");
  const rewritten = parts.map((part) =>
    part.startsWith("type=") ? `type=${transport}` : part,
  );
  if (!rewritten.some((part) => part.startsWith("type="))) {
    rewritten.push(`type=${transport}`);
  }

  let result = rewritten;
  if (transport === "ws") {
    result = rewritten.filter((part) => !part.startsWith("mode="));
  } else if (!rewritten.some((part) => part.startsWith("mode="))) {
    result = [...rewritten, "mode=auto"];
  }
  return result.join("&");
}

export interface ParsedRealVless {
  realId: string;
  realQuery: string;
}

export interface MaskedVlessResult {
  maskedUri: string;
  mapping: MappingPayload;
}

export interface RestoredLine {
  matched: boolean;
  line: string;
}

// security 白名单：只有这两个取值代表传输层已加密。
const ENCRYPTED_SECURITY_VALUES: readonly string[] = ["tls", "reality"];
// VLESS 层加密的哨兵值。encryption=none 是 VLESS 协议的必填长相，不代表任何加密。
const NO_VLESS_ENCRYPTION = "none";

// 单次 allowInsecure 取值是否视为“已开启”。只有明确的 0/false 才算关闭，其余一律按开启处理。
function isAllowInsecureEnabled(value: string): boolean {
  const normalized = value.toLowerCase();
  return normalized !== "0" && normalized !== "false";
}

// 默认拒绝地校验查询串是否属于加密传输：security 命中 TLS 白名单，或 encryption 表示 VLESS 层加密。
// 取值逐字比对、不做大小写折叠，重复同名参数逐条检查，任一条不合规即拒绝，
// 杜绝“本服务读第一个、客户端取最后一个”的缝隙。
export function assertEncryptedTransport(query: string): void {
  const params = new URLSearchParams(query);
  const securityValues = params.getAll("security");
  const encryptionValues = params.getAll("encryption");

  const tlsProtected =
    securityValues.length > 0 &&
    securityValues.every((value) => ENCRYPTED_SECURITY_VALUES.includes(value));
  const vlessEncrypted =
    encryptionValues.length > 0 &&
    encryptionValues.every((value) => value.toLowerCase() !== NO_VLESS_ENCRYPTION);

  if (!tlsProtected && !vlessEncrypted) {
    throw new AppError(
      "insecure_transport",
      "出于安全考虑，仅接受 security=tls、security=reality 或启用 VLESS 层加密（encryption 非 none）的真实节点",
      400,
    );
  }

  // allowInsecure 只在 TLS 是该节点唯一的加密与认证手段时才构成失守：
  // reality 自带服务端认证，VLESS 层加密的握手也不依赖 CA 证书，两者跳过证书校验都不会让攻击者获得解密能力。
  const tlsIsSoleProtection = securityValues.includes("tls") && !vlessEncrypted;
  if (tlsIsSoleProtection && params.getAll("allowInsecure").some(isAllowInsecureEnabled)) {
    throw new AppError(
      "allow_insecure",
      "出于安全考虑，不接受 allowInsecure 的真实节点：无法验证服务端证书",
      400,
    );
  }
}

export function parseRealVless(uri: string): ParsedRealVless {
  let parsed: URL;
  try {
    parsed = new URL(uri.trim());
  } catch {
    throw new Error("VLESS URI 格式无效");
  }

  if (
    parsed.protocol !== "vless:" ||
    !UUID_PATTERN.test(parsed.username) ||
    parsed.password !== "" ||
    parsed.hostname === "" ||
    parsed.port === "" ||
    parsed.search.length <= 1
  ) {
    throw new Error("VLESS URI 缺少有效的 UUID、主机、端口或查询参数");
  }

  return {
    realId: parsed.username.toLowerCase(),
    realQuery: parsed.search.slice(1),
  };
}

export function createMaskedVless(
  parsed: ParsedRealVless,
  transport: Transport = "ws",
): MaskedVlessResult {
  const fakeId = crypto.randomUUID();
  return {
    maskedUri: `vless://${fakeId}@placeholder.invalid:443?${DECOY_QUERIES[transport]}#SafeSub`,
    mapping: {
      v: 1,
      kind: "mapping",
      fakeId,
      realId: parsed.realId,
      realQuery: parsed.realQuery,
    },
  };
}

export function restoreVlessLine(
  line: string,
  mapping: MappingPayload,
  transport?: Transport,
): RestoredLine {
  if (!line.startsWith("vless://")) {
    return { matched: false, line };
  }

  const userStart = "vless://".length;
  const atIndex = line.indexOf("@", userStart);
  if (atIndex < 0) {
    return { matched: false, line };
  }

  const queryIndex = line.indexOf("?", atIndex + 1);
  const fragmentIndex = line.indexOf("#", atIndex + 1);
  const authorityEnd = Math.min(
    queryIndex < 0 ? line.length : queryIndex,
    fragmentIndex < 0 ? line.length : fragmentIndex,
  );
  const fakeId = line.slice(userStart, atIndex);
  const hostPort = line.slice(atIndex + 1, authorityEnd);
  const fragment = fragmentIndex < 0 ? "" : line.slice(fragmentIndex);

  try {
    const parsed = new URL(line);
    if (
      parsed.protocol !== "vless:" ||
      parsed.password !== "" ||
      parsed.hostname === "" ||
      parsed.port === "" ||
      fakeId.toLowerCase() !== mapping.fakeId.toLowerCase()
    ) {
      return { matched: false, line };
    }
  } catch {
    return { matched: false, line };
  }

  const realQuery =
    transport === undefined ? mapping.realQuery : applyTransportOverride(mapping.realQuery, transport);
  return {
    matched: true,
    line: `vless://${mapping.realId}@${hostPort}?${realQuery}${fragment}`,
  };
}
