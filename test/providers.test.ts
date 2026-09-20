import { describe, expect, it } from "vitest";

import { AppError } from "../src/errors";
import { DEFAULT_PROVIDER_ID, getProvider } from "../src/providers";

const fakeId = "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa";

describe("providers", () => {
  it("默认服务商 danfeng 用 ws 诱饵拼出第三方订阅 URL", () => {
    const provider = getProvider(DEFAULT_PROVIDER_ID);
    expect(provider.decoyTransport).toBe("ws");

    const url = new URL(provider.buildUpstreamUrl(fakeId));
    expect(url.origin + url.pathname).toBe("https://sub.danfeng.eu.org/sub");
    expect(url.searchParams.get("uuid")).toBe(fakeId);
    expect(url.searchParams.get("type")).toBe("ws");
    // danfeng 不支持 xhttp，诱饵不应带 xhttp 专属的 mode 参数
    expect(url.searchParams.get("mode")).toBeNull();
  });

  it("未知服务商抛出 unknown_provider", () => {
    expect(() => getProvider("nope")).toThrowError(AppError);
    try {
      getProvider("nope");
    } catch (error) {
      expect(error).toBeInstanceOf(AppError);
      expect((error as AppError).code).toBe("unknown_provider");
      expect((error as AppError).status).toBe(400);
    }
  });
});
