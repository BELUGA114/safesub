import { afterEach, describe, expect, it, vi } from "vitest";

import worker, { type Env } from "../src/index";
import { decodeSubscription, encodeSubscription } from "../src/subscription";
import { openToken, sealToken, type MappingPayload } from "../src/token";

const secret = "AAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh8";
const realUri =
  "vless://11111111-2222-4333-8444-555555555555@origin.example:8443?encryption=none&security=tls&type=ws&path=%2Freal&sni=origin.example#Private";

const env: Env = {
  TOKEN_KEY: secret,
  ASSETS: {
    fetch: async () => new Response("static asset", { status: 200 }),
  },
};

async function jsonRequest(path: string, body: unknown): Promise<Response> {
  return worker.fetch(
    new Request(`https://safesub.example${path}`, {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify(body),
    }),
    env,
  );
}

afterEach(() => {
  vi.unstubAllGlobals();
});

describe("POST /api/mask", () => {
  it("返回伪装节点和可验证的映射令牌", async () => {
    const response = await jsonRequest("/api/mask", { vlessUri: realUri });
    const body = (await response.json()) as { maskedUri: string; mappingToken: string };

    expect(response.status).toBe(200);
    expect(response.headers.get("cache-control")).toBe("no-store");
    expect(body.maskedUri).not.toContain("origin.example");
    const payload = await openToken(body.mappingToken, secret);
    expect(payload.kind).toBe("mapping");
    expect(payload.realId).toBe("11111111-2222-4333-8444-555555555555");
  });

  it("以稳定 JSON 错误拒绝非法 VLESS", async () => {
    const response = await jsonRequest("/api/mask", { vlessUri: "not-vless" });

    expect(response.status).toBe(400);
    await expect(response.json()).resolves.toMatchObject({
      error: { code: "invalid_vless" },
    });
  });
});

describe("POST /api/subscriptions", () => {
  it("将映射和上游 URL 密封为永久订阅链接", async () => {
    const maskResponse = await jsonRequest("/api/mask", { vlessUri: realUri });
    const { mappingToken } = (await maskResponse.json()) as { mappingToken: string };

    const response = await jsonRequest("/api/subscriptions", {
      mappingToken,
      upstreamUrl: "https://subscription.example/list?token=secret",
    });
    const body = (await response.json()) as { subscriptionUrl: string };
    const token = new URL(body.subscriptionUrl).pathname.slice("/sub/".length);
    const payload = await openToken(token, secret);

    expect(response.status).toBe(200);
    expect(body.subscriptionUrl).toMatch(/^https:\/\/safesub\.example\/sub\/v1\./u);
    expect(payload).toMatchObject({
      kind: "subscription",
      upstreamUrl: "https://subscription.example/list?token=secret",
    });
  });

  it("拒绝把订阅令牌当作映射令牌", async () => {
    const token = await sealToken(
      {
        v: 1,
        kind: "subscription",
        fakeId: "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa",
        realId: "11111111-2222-4333-8444-555555555555",
        realQuery: "security=tls",
        upstreamUrl: "https://subscription.example/list",
      },
      secret,
    );

    const response = await jsonRequest("/api/subscriptions", {
      mappingToken: token,
      upstreamUrl: "https://subscription.example/list",
    });

    expect(response.status).toBe(400);
    await expect(response.json()).resolves.toMatchObject({ error: { code: "invalid_token_type" } });
  });
});

describe("GET /sub/:token", () => {
  it("返回普通客户端可直接使用的真实 Base64 订阅", async () => {
    const mapping: MappingPayload = {
      v: 1,
      kind: "mapping",
      fakeId: "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa",
      realId: "11111111-2222-4333-8444-555555555555",
      realQuery: "encryption=none&security=tls&type=ws&sni=origin.example",
    };
    const token = await sealToken(
      { ...mapping, kind: "subscription", upstreamUrl: "https://subscription.example/list" },
      secret,
    );
    const upstreamLine =
      "vless://aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa@edge.example:2096?security=tls#Edge";
    vi.stubGlobal("fetch", async () => new Response(encodeSubscription(upstreamLine)));

    const response = await worker.fetch(new Request(`https://safesub.example/sub/${token}`), env);
    const restored = decodeSubscription(await response.text());

    expect(response.status).toBe(200);
    expect(response.headers.get("content-type")).toContain("text/plain");
    expect(response.headers.get("cache-control")).toBe("no-store");
    expect(restored).toBe(
      "vless://11111111-2222-4333-8444-555555555555@edge.example:2096?encryption=none&security=tls&type=ws&sni=origin.example#Edge",
    );
  });

  it("令牌无效时不回显令牌或异常细节", async () => {
    const response = await worker.fetch(new Request("https://safesub.example/sub/not-a-token"), env);
    const text = await response.text();

    expect(response.status).toBe(400);
    expect(text).not.toContain("not-a-token");
    expect(text).not.toContain("stack");
  });

  it("可读取由允许长度上限附近输入生成的订阅链接", async () => {
    const longRealUri =
      `vless://11111111-2222-4333-8444-555555555555@origin.example:443?` +
      `encryption=none&security=tls&type=ws&path=%2F${"a".repeat(3900)}#Long`;
    const maskResponse = await jsonRequest("/api/mask", { vlessUri: longRealUri });
    const maskBody = (await maskResponse.json()) as { maskedUri: string; mappingToken: string };
    const fakeId = new URL(maskBody.maskedUri).username;
    const upstreamUrl = `https://subscription.example/list?token=${"b".repeat(2000)}`;
    const createResponse = await jsonRequest("/api/subscriptions", {
      mappingToken: maskBody.mappingToken,
      upstreamUrl,
    });
    const { subscriptionUrl: createdUrl } = (await createResponse.json()) as { subscriptionUrl: string };
    vi.stubGlobal(
      "fetch",
      async () =>
        new Response(
          encodeSubscription(`vless://${fakeId}@edge.example:443?security=tls#Edge`),
        ),
    );

    const response = await worker.fetch(new Request(createdUrl), env);

    expect(response.status).toBe(200);
  });
});

describe("routing", () => {
  it("拒绝超过16 KiB的 JSON 请求体", async () => {
    const response = await jsonRequest("/api/mask", { vlessUri: "x".repeat(17 * 1024) });

    expect(response.status).toBe(413);
    await expect(response.json()).resolves.toMatchObject({ error: { code: "body_too_large" } });
  });

  it("非应用路由交给静态资源绑定", async () => {
    const response = await worker.fetch(new Request("https://safesub.example/styles.css"), env);

    expect(await response.text()).toBe("static asset");
  });
});
