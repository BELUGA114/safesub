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

// VLESS 层加密（VLESS Encryption）取值的形状，与 Xray-core、mihomo 的解析逻辑一致：
// mlkem768x25519plus.<mode>.<rtt>.<可选的 padding 参数...>.<密钥...>
const VLESS_ENCRYPTION_SCHEME = "mlkem768x25519plus";
const VLESS_ENCRYPTION_MODES: readonly string[] = ["native", "xorpub", "random"];
// 客户端 encryption 固定用 0rtt/1rtt；600s 这类秒数只出现在服务端 decryption 里。
const VLESS_ENCRYPTION_RTTS: readonly string[] = ["0rtt", "1rtt"];
// 密钥段是 RawURL Base64（不带 "=" 填充），解码后为 X25519 公钥或 ML-KEM-768 公钥。
const ENCRYPTION_KEY_BYTE_LENGTHS: readonly number[] = [32, 1184];
const RAW_BASE64URL_PATTERN = /^[A-Za-z0-9_-]+$/;
// Xray 以“段长不足 20 即 padding”区分密钥与 padding，padding 参数形如 100-111-1111 的长度/间隔区间，内容不校验。
const ENCRYPTION_PADDING_MAX_LENGTH = 19;
// allowInsecure 的参数名比较基准；客户端对参数名的大小写处理并不统一。
const ALLOW_INSECURE_PARAM = "allowinsecure";

// 单次 allowInsecure 取值是否视为“已开启”。只有明确的 0/false 才算关闭，其余（含空值）一律按开启处理。
function isAllowInsecureEnabled(value: string): boolean {
  const normalized = value.toLowerCase();
  return normalized !== "0" && normalized !== "false";
}

// RawURL Base64 解码后的字节数；含非法字符（含 "=" 填充）或长度非法时返回 -1。
// 不直接用 atob：它容忍填充与 +/ 等 Xray 会拒绝的写法。
function rawBase64UrlByteLength(value: string): number {
  if (!RAW_BASE64URL_PATTERN.test(value) || value.length % 4 === 1) {
    return -1;
  }
  return Math.floor((value.length * 3) / 4);
}

// encryption 取值是否真的是 VLESS 层加密。只认 Xray 与 mihomo 都能解析的形状：
// 否则任意非 none 字符串（含空值与纯空白）都会被当成“已加密”，从而同时绕开 TLS 与 allowInsecure 校验。
function isVlessEncryption(value: string): boolean {
  const segments = value.split(".");
  if (segments.length < 4 || segments[0] !== VLESS_ENCRYPTION_SCHEME) {
    return false;
  }
  if (!VLESS_ENCRYPTION_MODES.includes(segments[1] ?? "")) {
    return false;
  }
  if (!VLESS_ENCRYPTION_RTTS.includes(segments[2] ?? "")) {
    return false;
  }

  let keyCount = 0;
  for (const segment of segments.slice(3)) {
    if (segment.length <= ENCRYPTION_PADDING_MAX_LENGTH) {
      continue;
    }
    if (!ENCRYPTION_KEY_BYTE_LENGTHS.includes(rawBase64UrlByteLength(segment))) {
      return false;
    }
    keyCount += 1;
  }
  // 只有 padding、没有密钥段时 Xray 会报错，这里同样不算加密。
  return keyCount > 0;
}

// 是否存在任意写法（含大小写与空白差异）的 allowInsecure。客户端对参数名的匹配并不统一，
// 这里宽进严出：一旦出现就按“跳过证书校验”处理。
function hasAllowInsecure(params: URLSearchParams): boolean {
  for (const [name, value] of params) {
    if (name.trim().toLowerCase() === ALLOW_INSECURE_PARAM && isAllowInsecureEnabled(value)) {
      return true;
    }
  }
  return false;
}

// 默认拒绝地校验查询串是否属于加密传输：security 命中 TLS 白名单，或 encryption 是真正的 VLESS 层加密。
// security 与 encryption 的取值逐字比对、不做大小写折叠：这两个方向是放行，而客户端一旦不认识该拼写
// 就会退回明文，所以宁可不认；重复同名参数逐条检查，杜绝“本服务读第一个、客户端取最后一个”的缝隙。
export function assertEncryptedTransport(query: string): void {
  const params = new URLSearchParams(query);
  const securityValues = params.getAll("security");
  const encryptionValues = params.getAll("encryption");

  const tlsProtected =
    securityValues.length > 0 &&
    securityValues.every((value) => ENCRYPTED_SECURITY_VALUES.includes(value));
  const vlessEncrypted =
    encryptionValues.length > 0 && encryptionValues.every(isVlessEncryption);

  if (!tlsProtected && !vlessEncrypted) {
    throw new AppError(
      "insecure_transport",
      "出于安全考虑，仅接受 security=tls、security=reality 或启用 VLESS 层加密（mlkem768x25519plus）的真实节点",
      400,
    );
  }

  // allowInsecure 只在 TLS 是该节点唯一的加密与认证手段时才构成失守：
  // reality 自带服务端认证，VLESS 层加密的握手也不依赖 CA 证书，两者跳过证书校验都不会让攻击者获得解密能力。
  const tlsIsSoleProtection = securityValues.includes("tls") && !vlessEncrypted;
  if (tlsIsSoleProtection && hasAllowInsecure(params)) {
    throw new AppError(
      "allow_insecure",
      "出于安全考虑，不接受 allowInsecure 的真实节点",
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

  const realQuery = parsed.search.slice(1);
  assertEncryptedTransport(realQuery);

  return {
    realId: parsed.username.toLowerCase(),
    realQuery,
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
