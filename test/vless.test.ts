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

describe("assertEncryptedTransport", () => {
  it.each([
    "encryption=none&security=tls&type=ws&sni=origin.example",
    "encryption=none&security=reality&type=tcp&sni=origin.example",
    "security=none&encryption=mlkem768x25519plus.native.0rtt.s3cret&type=ws",
    "encryption=none&security=tls&allowInsecure=0",
    "encryption=none&security=tls&allowInsecure=false",
    "encryption=none&security=reality&allowInsecure=1",
    "security=tls&allowInsecure=1&encryption=mlkem768x25519plus.native.0rtt.s3cret",
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
    ["重复 security 混入 none", "encryption=none&security=tls&security=none&type=ws"],
    [
      "重复 encryption 混入 none",
      "security=none&encryption=mlkem768x25519plus.native.0rtt.s3cret&encryption=none",
    ],
  ];

  it.each(insecureTransportCases)("以 insecure_transport 拒绝未加密传输：%s", (_name, query) => {
    expect(appErrorCode(() => assertEncryptedTransport(query))).toBe("insecure_transport");
  });

  const allowInsecureCases: ReadonlyArray<readonly [string, string]> = [
    ["allowInsecure=1", "encryption=none&security=tls&allowInsecure=1&type=ws"],
    ["allowInsecure=true", "encryption=none&security=tls&allowInsecure=true&type=ws"],
    ["allowInsecure 为空值", "encryption=none&security=tls&allowInsecure=&type=ws"],
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
