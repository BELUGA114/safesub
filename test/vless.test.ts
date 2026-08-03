import { describe, expect, it } from "vitest";

import {
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
});
