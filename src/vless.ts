import type { MappingPayload } from "./token";

const UUID_PATTERN = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i;
const DECOY_QUERY =
  "encryption=none&security=tls&type=ws&host=placeholder.invalid&path=%2Fsafesub&sni=placeholder.invalid";

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

export function createMaskedVless(parsed: ParsedRealVless): MaskedVlessResult {
  const fakeId = crypto.randomUUID();
  return {
    maskedUri: `vless://${fakeId}@placeholder.invalid:443?${DECOY_QUERY}#SafeSub`,
    mapping: {
      v: 1,
      kind: "mapping",
      fakeId,
      realId: parsed.realId,
      realQuery: parsed.realQuery,
    },
  };
}

export function restoreVlessLine(line: string, mapping: MappingPayload): RestoredLine {
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

  return {
    matched: true,
    line: `vless://${mapping.realId}@${hostPort}?${mapping.realQuery}${fragment}`,
  };
}
