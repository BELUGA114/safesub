import { describe, expect, it } from "vitest";

import { AppError } from "../src/errors";
import {
  applyTransportOverride,
  assertEncryptedTransport,
  createMaskedVless,
  parseRealVless,
  restoreVlessLine,
} from "../src/vless";

// 读取抛出的 AppError 错误码；未抛出任何错误或抛的不是 AppError 时返回 undefined。
function appErrorCode(run: () => void): string | undefined {
  try {
    run();
  } catch (error: unknown) {
    return error instanceof AppError ? error.code : undefined;
  }
  return undefined;
}

const realUri =
  "vless://11111111-2222-4333-8444-555555555555@origin.example:8443?encryption=none&security=tls&type=ws&host=origin.example&path=%2Fsecret&sni=origin.example#Private%20Node";

// VLESS 层加密（VLESS Encryption）的密钥段按 RawURL Base64 编码，不带 "=" 填充：
// X25519 公钥 32 字节编码成 43 字符，ML-KEM-768 公钥 1184 字节编码成 1579 字符。
const x25519Key = "P15JKtXLmzttnqUW4cLO205qNQhvh_KbP8PtQ6Z7uUs";
const mlkem768Key = "A".repeat(1579);
// Xray 与 mihomo 只按下标解析前三段，所以客户端取值固定是 scheme.mode.rtt。
const vlessEncryption = `mlkem768x25519plus.native.0rtt.${x25519Key}`;

describe("assertEncryptedTransport", () => {
  it.each([
    "encryption=none&security=tls&type=ws&sni=origin.example",
    "encryption=none&security=reality&type=tcp&sni=origin.example",
    `security=none&encryption=${vlessEncryption}&type=ws`,
    `security=none&encryption=mlkem768x25519plus.xorpub.1rtt.${x25519Key}&type=ws`,
    `security=none&encryption=mlkem768x25519plus.random.0rtt.${x25519Key}&type=ws`,
    `security=none&encryption=mlkem768x25519plus.native.0rtt.100-111-1111.75-0-111.${x25519Key}&type=ws`,
    `security=none&encryption=mlkem768x25519plus.native.0rtt.${mlkem768Key}&type=ws`,
    "encryption=none&security=tls&allowInsecure=0",
    "encryption=none&security=tls&allowInsecure=false",
    "encryption=none&security=reality&allowInsecure=1",
    `security=tls&allowInsecure=1&encryption=${vlessEncryption}`,
  ])("接受加密传输：%s", (query) => {
    expect(() => assertEncryptedTransport(query)).not.toThrow();
  });

  // 显式标注元组类型：本仓库开启了 noUncheckedIndexedAccess，若让 it.each 把用例推断成
  // string[][]，回调里的 query 会变成 string | undefined，无法传给 assertEncryptedTransport。
  const insecureTransportCases: ReadonlyArray<readonly [string, string]> = [
    ["缺少 security 且没有 VLESS 层加密", "encryption=none&type=ws"],
    ["security=none", "encryption=none&security=none&type=ws"],
    ["security=xtls", "encryption=none&security=xtls&type=ws"],
    ["security 大小写不匹配", "encryption=none&security=TLS&type=ws"],
    ["只写了 security=none", "security=none"],
    ["encryption 全为 none 时不算加密", "security=none&encryption=None"],
    ["encryption 为空值", "security=none&encryption=&type=ws"],
    ["encryption 为空白包裹的 none", "security=none&encryption=%20none&type=ws"],
    ["encryption 为无法识别的字符串", "security=none&encryption=foo&type=ws"],
    ["encryption 缺少密钥段", "security=none&encryption=mlkem768x25519plus.native.0rtt&type=ws"],
    [
      "encryption 用了服务端的 rtt 取值",
      `security=none&encryption=mlkem768x25519plus.native.600s.${x25519Key}&type=ws`,
    ],
    [
      "encryption 的 mode 大小写不匹配",
      `security=none&encryption=mlkem768x25519plus.NATIVE.0rtt.${x25519Key}&type=ws`,
    ],
    [
      "encryption 的密钥带 Base64 填充",
      `security=none&encryption=mlkem768x25519plus.native.0rtt.${x25519Key}%3D&type=ws`,
    ],
    [
      "encryption 的密钥长度不合规",
      `security=none&encryption=mlkem768x25519plus.native.0rtt.${x25519Key.slice(0, 42)}&type=ws`,
    ],
    ["重复 security 混入 none", "encryption=none&security=tls&security=none&type=ws"],
    [
      "重复 encryption 混入 none",
      `security=none&encryption=${vlessEncryption}&encryption=none`,
    ],
  ];

  it.each(insecureTransportCases)("以 insecure_transport 拒绝未加密传输：%s", (_name, query) => {
    expect(appErrorCode(() => assertEncryptedTransport(query))).toBe("insecure_transport");
  });

  const allowInsecureCases: ReadonlyArray<readonly [string, string]> = [
    ["allowInsecure=1", "encryption=none&security=tls&allowInsecure=1&type=ws"],
    ["allowInsecure=true", "encryption=none&security=tls&allowInsecure=true&type=ws"],
    ["allowInsecure 为空值", "encryption=none&security=tls&allowInsecure=&type=ws"],
    // 参数名大小写由各家客户端自行决定，这里按大小写不敏感匹配，宁可多拦。
    ["参数名全小写", "encryption=none&security=tls&allowinsecure=1&type=ws"],
    ["参数名首字母大写", "encryption=none&security=tls&AllowInsecure=1&type=ws"],
    ["参数名全大写", "encryption=none&security=tls&ALLOWINSECURE=true&type=ws"],
    ["参数名带空白", "encryption=none&security=tls&allowInsecure%20=1&type=ws"],
    // encryption 取值不合规时不再被视为 VLESS 层加密，也就不能再豁免 allowInsecure。
    ["encryption 取值无效", "security=tls&encryption=foo&allowInsecure=1&type=ws"],
  ];

  it.each(allowInsecureCases)("以 allow_insecure 拒绝跳过证书校验：%s", (_name, query) => {
    expect(appErrorCode(() => assertEncryptedTransport(query))).toBe("allow_insecure");
  });
});

describe("parseRealVless", () => {
  it("提取恢复所需字段", () => {
    expect(parseRealVless(realUri)).toEqual({
      realId: "11111111-2222-4333-8444-555555555555",
      realQuery: "encryption=none&security=tls&type=ws&host=origin.example&path=%2Fsecret&sni=origin.example",
    });
  });

  it("接受 xhttp 传输的真实节点", () => {
    const xhttpUri =
      "vless://11111111-2222-4333-8444-555555555555@origin.example:8443?encryption=none&security=tls&type=xhttp&host=origin.example&path=%2Fsecret&sni=origin.example&mode=auto#Private";
    expect(parseRealVless(xhttpUri).realQuery).toContain("type=xhttp");
    expect(parseRealVless(xhttpUri).realQuery).toContain("mode=auto");
  });

  it.each([
    "https://example.com",
    "vless://not-a-uuid@example.com:443?security=tls",
    "vless://11111111-2222-4333-8444-555555555555@example.com:70000?security=tls",
    "vless://11111111-2222-4333-8444-555555555555@example.com:443",
  ])("拒绝无效真实节点：%s", (value) => {
    expect(() => parseRealVless(value)).toThrow("VLESS");
  });

  it("接受 reality 传输的真实节点", () => {
    const realityUri =
      "vless://11111111-2222-4333-8444-555555555555@origin.example:443?encryption=none&security=reality&type=tcp&sni=origin.example&pbk=abc#Private";
    expect(parseRealVless(realityUri).realQuery).toContain("security=reality");
  });

  it("接受启用 VLESS 层加密的真实节点", () => {
    const encryptedUri = `vless://11111111-2222-4333-8444-555555555555@origin.example:443?encryption=${vlessEncryption}&security=none&type=ws#Private`;
    expect(parseRealVless(encryptedUri).realQuery).toContain("encryption=mlkem768x25519plus");
  });

  it("以 insecure_transport 拒绝未加密的真实节点", () => {
    const plaintextUri =
      "vless://11111111-2222-4333-8444-555555555555@origin.example:8443?encryption=none&security=none&type=ws&path=%2Freal#Private";
    expect(appErrorCode(() => parseRealVless(plaintextUri))).toBe("insecure_transport");
  });

  it("以 insecure_transport 拒绝 encryption 取值无效的真实节点", () => {
    const fakeEncryptionUri =
      "vless://11111111-2222-4333-8444-555555555555@origin.example:8443?encryption=foo&security=none&type=ws#Private";
    expect(appErrorCode(() => parseRealVless(fakeEncryptionUri))).toBe("insecure_transport");
  });

  it("以 allow_insecure 拒绝跳过证书校验的真实节点", () => {
    const insecureUri =
      "vless://11111111-2222-4333-8444-555555555555@origin.example:8443?encryption=none&security=tls&allowInsecure=1&type=ws&sni=origin.example#Private";
    expect(appErrorCode(() => parseRealVless(insecureUri))).toBe("allow_insecure");
  });

  it("以 allow_insecure 拒绝参数名大小写不同的 allowInsecure", () => {
    const insecureUri =
      "vless://11111111-2222-4333-8444-555555555555@origin.example:8443?encryption=none&security=tls&allowinsecure=1&type=ws&sni=origin.example#Private";
    expect(appErrorCode(() => parseRealVless(insecureUri))).toBe("allow_insecure");
  });
});

describe("createMaskedVless", () => {
  it("生成语法有效且不泄露真实字段的节点", () => {
    const result = createMaskedVless(parseRealVless(realUri));
    const masked = new URL(result.maskedUri);

    expect(masked.protocol).toBe("vless:");
    expect(masked.hostname).toBe("placeholder.invalid");
    expect(masked.port).toBe("443");
    expect(result.mapping.fakeId).toBe(masked.username);
    expect(result.maskedUri).not.toContain("11111111-2222-4333-8444-555555555555");
    expect(result.maskedUri).not.toContain("origin.example");
    expect(result.maskedUri).not.toContain("secret");
    expect(result.maskedUri).not.toContain("Private");
  });

  it("缺省传输生成 ws 诱饵", () => {
    const result = createMaskedVless(parseRealVless(realUri));
    const masked = new URL(result.maskedUri);

    expect(masked.searchParams.get("type")).toBe("ws");
  });

  it("xhttp 传输生成含 mode 的 xhttp 诱饵", () => {
    const result = createMaskedVless(parseRealVless(realUri), "xhttp");
    const masked = new URL(result.maskedUri);

    expect(masked.searchParams.get("type")).toBe("xhttp");
    expect(masked.searchParams.get("mode")).toBe("auto");
    expect(result.mapping.fakeId).toBe(masked.username);
    expect(result.maskedUri).not.toContain("origin.example");
  });
});

describe("applyTransportOverride", () => {
  it("重写为 xhttp 时替换 type 并补充缺省 mode", () => {
    expect(
      applyTransportOverride("encryption=none&security=tls&type=ws&path=%2Fp&sni=h", "xhttp"),
    ).toBe("encryption=none&security=tls&type=xhttp&path=%2Fp&sni=h&mode=auto");
  });

  it("重写为 ws 时替换 type 并移除 mode", () => {
    expect(
      applyTransportOverride("encryption=none&security=tls&type=xhttp&path=%2Fp&sni=h&mode=auto", "ws"),
    ).toBe("encryption=none&security=tls&type=ws&path=%2Fp&sni=h");
  });

  it("保留已有的非缺省 mode", () => {
    expect(
      applyTransportOverride("security=tls&type=ws&mode=packet-up", "xhttp"),
    ).toBe("security=tls&type=xhttp&mode=packet-up");
  });

  it("查询串缺少 type 时补充 type", () => {
    expect(applyTransportOverride("security=tls&sni=h", "ws")).toBe("security=tls&sni=h&type=ws");
  });
});

describe("restoreVlessLine", () => {
  const mapping = {
    v: 1 as const,
    kind: "mapping" as const,
    fakeId: "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa",
    realId: "11111111-2222-4333-8444-555555555555",
    realQuery: "encryption=none&security=tls&type=ws&path=%2Fsecret&sni=origin.example",
  };

  it("恢复真实字段并保留第三方 IPv4 地址、端口和名称", () => {
    const input =
      "vless://aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa@203.0.113.8:2096?security=tls&type=ws#Hong%20Kong";

    expect(restoreVlessLine(input, mapping)).toEqual({
      matched: true,
      line: "vless://11111111-2222-4333-8444-555555555555@203.0.113.8:2096?encryption=none&security=tls&type=ws&path=%2Fsecret&sni=origin.example#Hong%20Kong",
    });
  });

  it("完整保留第三方 IPv6 地址和端口", () => {
    const input =
      "vless://aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa@[2001:db8::8]:2053?security=tls#IPv6";

    expect(restoreVlessLine(input, mapping).line).toContain("@[2001:db8::8]:2053?");
  });

  it("不修改 UUID 不匹配的节点", () => {
    const input =
      "vless://bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb@example.net:443?security=tls#Other";

    expect(restoreVlessLine(input, mapping)).toEqual({ matched: false, line: input });
  });

  it("不修改非 VLESS 行", () => {
    expect(restoreVlessLine("trojan://example", mapping)).toEqual({
      matched: false,
      line: "trojan://example",
    });
  });

  it("恢复 xhttp 传输的完整查询串", () => {
    const xhttpMapping = {
      ...mapping,
      realQuery:
        "encryption=none&security=tls&type=xhttp&path=%2Fsecret&sni=origin.example&mode=auto",
    };
    const input =
      "vless://aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa@203.0.113.8:443?security=tls&type=xhttp#Edge";

    expect(restoreVlessLine(input, xhttpMapping)).toEqual({
      matched: true,
      line: "vless://11111111-2222-4333-8444-555555555555@203.0.113.8:443?encryption=none&security=tls&type=xhttp&path=%2Fsecret&sni=origin.example&mode=auto#Edge",
    });
  });

  it("指定传输覆盖时重写恢复后的查询串", () => {
    const input =
      "vless://aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa@203.0.113.8:2096?security=tls&type=ws#Edge";

    expect(restoreVlessLine(input, mapping, "xhttp")).toEqual({
      matched: true,
      line: "vless://11111111-2222-4333-8444-555555555555@203.0.113.8:2096?encryption=none&security=tls&type=xhttp&path=%2Fsecret&sni=origin.example&mode=auto#Edge",
    });
  });
});
