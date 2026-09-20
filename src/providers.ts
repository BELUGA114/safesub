import { AppError } from "./errors";
import { DECOY_QUERIES, type Transport } from "./vless";

// 内置第三方订阅服务商。给定诱饵节点的 fakeId 即可拼出对应的第三方订阅 URL，
// 免去用户手动跑一趟服务商站点。
export interface Provider {
  id: string;
  name: string;
  // 该服务商能接受的诱饵节点传输类型。danfeng 只支持 ws，因此诱饵固定用 ws，
  // 与用户选择的“最终订阅传输”相互独立。
  decoyTransport: Transport;
  buildUpstreamUrl(fakeId: string): string;
}

const danfeng: Provider = {
  id: "danfeng",
  name: "danfeng",
  decoyTransport: "ws",
  buildUpstreamUrl(fakeId: string): string {
    return `https://sub.danfeng.eu.org/sub?uuid=${fakeId}&${DECOY_QUERIES.ws}`;
  },
};

const PROVIDERS: ReadonlyMap<string, Provider> = new Map([[danfeng.id, danfeng]]);

export const DEFAULT_PROVIDER_ID = danfeng.id;

export function getProvider(id: string): Provider {
  const provider = PROVIDERS.get(id);
  if (provider === undefined) {
    throw new AppError("unknown_provider", "不支持的服务商", 400);
  }
  return provider;
}
