import { describe, expect, it } from "vitest";

import type { MappingPayload } from "../src/token";
import {
  decodeSubscription,
  encodeSubscription,
  fetchAndRestore,
  restoreSubscription,
  validateUpstreamUrl,
} from "../src/subscription";

const mapping: MappingPayload = {
  v: 1,
  kind: "mapping",
  fakeId: "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa",
  realId: "11111111-2222-4333-8444-555555555555",
  realQuery: "encryption=none&security=tls&type=ws&path=%2Freal&sni=origin.example",
};

const fakeLine =
  "vless://aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa@edge.example:2053?security=tls#Edge";

describe("validateUpstreamUrl", () => {
  it("接受公开 HTTPS URL", () => {
    expect(validateUpstreamUrl("https://subscription.example/path?token=abc").href).toBe(
      "https://subscription.example/path?token=abc",
    );
  });

  it.each([
    "http://subscription.example/list",
    "https://user:pass@subscription.example/list",
    "https://localhost/list",
    "https://service.local/list",
    "https://127.0.0.1/list",
    "https://10.0.0.8/list",
    "https://172.20.0.8/list",
    "https://192.168.1.8/list",
    "https://[::1]/list",
    "https://[fd00::8]/list",
  ])("拒绝不安全的上游地址：%s", (value) => {
    expect(() => validateUpstreamUrl(value)).toThrow("上游 URL");
  });
});

describe("subscription codec", () => {
  it("解码标准 Base64 并严格读取 UTF-8", () => {
    expect(decodeSubscription("dmxlc3M6Ly90ZXN0Cg==")).toBe("vless://test\n");
  });

  it("接受 URL-safe Base64 和空白", () => {
    const text = "vless://example/\u00ff";
    const encoded = btoa(String.fromCharCode(...new TextEncoder().encode(text)))
      .replaceAll("+", "-")
      .replaceAll("/", "_")
      .replace(/=+$/u, "");

    expect(decodeSubscription(` ${encoded.slice(0, 5)}\n${encoded.slice(5)} `)).toBe(text);
  });

  it("拒绝无效 Base64 或无效 UTF-8", () => {
    expect(() => decodeSubscription("%%%not-base64%%%")).toThrow("Base64");
    expect(() => decodeSubscription("_w==")).toThrow("UTF-8");
  });

  it("编码结果可由标准 Base64 解码", () => {
    const encoded = encodeSubscription("节点\nvless://example");
    const bytes = Uint8Array.from(atob(encoded), (character) => character.charCodeAt(0));

    expect(new TextDecoder().decode(bytes)).toBe("节点\nvless://example");
  });
});

describe("restoreSubscription", () => {
  it("恢复所有匹配节点并保留其他行", () => {
    const other = "vless://bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb@other.example:443?security=tls#Other";
    const result = restoreSubscription(`${fakeLine}\n${other}\n${fakeLine}`, mapping);

    expect(result.matchCount).toBe(2);
    expect(result.text).toContain(
      "vless://11111111-2222-4333-8444-555555555555@edge.example:2053?encryption=none&security=tls&type=ws&path=%2Freal&sni=origin.example#Edge",
    );
    expect(result.text).toContain(other);
  });

  it("订阅中没有目标节点时明确失败", () => {
    expect(() => restoreSubscription("vless://bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb@example.com:443?x=1", mapping)).toThrow(
      "未找到伪装节点",
    );
  });
});

describe("fetchAndRestore", () => {
  it("跟随并重新验证 HTTPS 重定向", async () => {
    const encoded = encodeSubscription(fakeLine);
    const fetcher: typeof fetch = async (input) => {
      const url = input instanceof Request ? input.url : input.toString();
      if (url === "https://subscription.example/start") {
        return new Response(null, { status: 302, headers: { location: "https://cdn.example/list" } });
      }
      return new Response(encoded, { status: 200 });
    };

    const result = await fetchAndRestore("https://subscription.example/start", mapping, fetcher);

    expect(decodeSubscription(result)).toContain(mapping.realId);
  });

  it("拒绝重定向到内网", async () => {
    const fetcher: typeof fetch = async () =>
      new Response(null, { status: 302, headers: { location: "https://127.0.0.1/list" } });

    await expect(fetchAndRestore("https://subscription.example/start", mapping, fetcher)).rejects.toThrow(
      "上游 URL",
    );
  });

  it("拒绝超过响应上限的订阅", async () => {
    const oversized = "A".repeat(2 * 1024 * 1024 + 1);
    const fetcher: typeof fetch = async () => new Response(oversized, { status: 200 });

    await expect(fetchAndRestore("https://subscription.example/list", mapping, fetcher)).rejects.toThrow(
      "过大",
    );
  });

  it("到达指定超时后终止上游请求", async () => {
    const fetcher: typeof fetch = async (_input, init) =>
      new Promise<Response>((_resolve, reject) => {
        init?.signal?.addEventListener("abort", () => reject(new DOMException("Aborted", "AbortError")));
      });

    await expect(
      fetchAndRestore("https://subscription.example/list", mapping, fetcher, { timeoutMs: 5 }),
    ).rejects.toThrow("超时");
  });
});
