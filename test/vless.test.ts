import { describe, expect, it } from "vitest";

import {
  applyTransportOverride,
  createMaskedVless,
  parseRealVless,
  restoreVlessLine,
} from "../src/vless";

const realUri =
  "vless://11111111-2222-4333-8444-555555555555@origin.example:8443?encryption=none&security=tls&type=ws&host=origin.example&path=%2Fsecret&sni=origin.example#Private%20Node";

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
