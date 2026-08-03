import { describe, expect, it } from "vitest";

import {
  decodeSecret,
  openToken,
  sealToken,
  type MappingPayload,
} from "../src/token";

const secret = "AAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh8";
const otherSecret = "Hx4dHBsaGRgXFhUUExIREA8ODQwLCgkIBwYFBAMCAQA";

const mapping: MappingPayload = {
  v: 1,
  kind: "mapping",
  fakeId: "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa",
  realId: "bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb",
  realQuery: "security=tls&type=ws&sni=example.com",
};

describe("token", () => {
  it("密封后可恢复原始映射", async () => {
    const token = await sealToken(mapping, secret);

    await expect(openToken(token, secret)).resolves.toEqual(mapping);
  });

  it("相同负载每次生成不同令牌", async () => {
    const first = await sealToken(mapping, secret);
    const second = await sealToken(mapping, secret);

    expect(first).not.toBe(second);
  });

  it("拒绝被篡改的密文", async () => {
    const token = await sealToken(mapping, secret);
    const last = token.at(-1);
    const tampered = `${token.slice(0, -1)}${last === "A" ? "B" : "A"}`;

    await expect(openToken(tampered, secret)).rejects.toThrow("令牌无效");
  });

  it("拒绝使用不同密钥解密", async () => {
    const token = await sealToken(mapping, secret);

    await expect(openToken(token, otherSecret)).rejects.toThrow("令牌无效");
  });

  it("拒绝长度不是32字节的主密钥", () => {
    expect(() => decodeSecret("c2hvcnQ")).toThrow("TOKEN_KEY 必须是 32 字节");
  });

  it("拒绝结构未知的负载", async () => {
    const token = await sealToken(
      { ...mapping, kind: "unknown" } as unknown as MappingPayload,
      secret,
    );

    await expect(openToken(token, secret)).rejects.toThrow("令牌负载无效");
  });

  it("接受 VLESS 解析器允许的 UUID v7", async () => {
    const payload: MappingPayload = {
      ...mapping,
      realId: "0198f123-4567-7abc-8def-0123456789ab",
    };
    const token = await sealToken(payload, secret);

    await expect(openToken(token, secret)).resolves.toEqual(payload);
  });
});
