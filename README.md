# SafeSub

SafeSub 是部署在 Cloudflare Workers 上的无状态 VLESS 订阅恢复工具。它先生成不包含真实节点信息的伪装 VLESS，第三方服务可据此生成大量不同 `host:port` 的节点；最终订阅链接会恢复真实 UUID 和查询参数，同时完整保留第三方生成的 `host:port` 与节点名称。

## 安全模型

- 只使用一个 Cloudflare Secret `TOKEN_KEY`，不使用 KV、D1 或普通环境变量。
- 映射和第三方订阅 URL 通过 AES-256-GCM 加密并认证后封装在最终 URL 中。
- Worker 仅在请求期间短暂处理明文，不缓存订阅，不记录敏感内容。
- 最终订阅 URL 是 bearer capability。任何持有者都能通过 Worker 获取真实订阅，必须按凭证保管。
- 最终链接永久有效，但轮换或丢失 `TOKEN_KEY` 会令所有旧链接失效。
- 首版只支持 Base64 编码、逐行内容为 `vless://` URI 的订阅。

## 本地开发

要求 Node.js 22 或更高版本、pnpm 和 Cloudflare Wrangler。

```powershell
pnpm install
node -e "console.log(require('node:crypto').randomBytes(32).toString('base64url'))"
Copy-Item .dev.vars.example .dev.vars
```

将生成的密钥写入 `.dev.vars`：

```dotenv
TOKEN_KEY=生成的Base64URL密钥
```

然后启动开发服务器：

```powershell
pnpm dev
```

常用验证命令：

```powershell
pnpm test
pnpm typecheck
pnpm deploy -- --dry-run
```

## 部署

先登录 Cloudflare，并把唯一主密钥配置为 Secret：

```powershell
pnpm exec wrangler login
pnpm exec wrangler secret put TOKEN_KEY
pnpm deploy
```

不要把 `.dev.vars`、生产密钥或最终订阅 URL 提交到 Git。

### Cloudflare Access

生成接口必须受 Access 保护，而普通订阅客户端必须能匿名请求最终链接。为 Worker 主机创建两个 Self-hosted Access 应用：

| 应用路径 | 策略 |
| --- | --- |
| `safesub.<账户子域>.workers.dev/*` | `Allow`，仅包含你的邮箱或身份组 |
| `safesub.<账户子域>.workers.dev/sub/*` | `Bypass`，包含 `Everyone` |

Cloudflare 对重叠应用使用更具体的路径策略，因此 `/sub/*` 不继承根应用的登录要求。部署后务必在未登录的隐私窗口验证：页面与 `/api/*` 应跳转到 Access，已有 `/sub/*` 链接应直接返回订阅。

如果使用自定义域名，将上表域名替换为自定义域名。不要把整个 Worker 配置为公开，也不要把 `/api/*` 加入 Bypass。

## 工作流

1. 在页面中输入真实 VLESS，生成并复制伪装 VLESS。
2. 把伪装 VLESS 提交给第三方服务，获得 Base64 订阅 URL。
3. 返回 SafeSub 页面，填入第三方订阅 URL，生成最终订阅链接。
4. 在客户端中添加最终订阅链接。客户端的每次更新都会即时拉取第三方订阅并恢复真实节点。

浏览器只在 `localStorage` 中保存加密映射令牌，不保存真实 VLESS。需要迁移浏览器时，可在第一步结果中复制“加密映射令牌”。

## 恢复规则

对于伪装 UUID 匹配的每个节点：

- 恢复真实 UUID。
- 恢复真实 URI 中 `?` 后的完整查询参数。
- 完整保留第三方生成的 `host:port`。
- 保留第三方生成的节点名称。

订阅中没有匹配的伪装 UUID 时请求会失败，不会静默返回未恢复的订阅。

## 限制

- JSON 请求正文最大 16 KiB，真实 VLESS 最大 4096 字符。
- 第三方订阅 URL 最大 2048 字符，仅允许不含用户名和密码的公开 HTTPS 地址。
- 上游最多跟随 3 次 HTTPS 重定向，请求超时为 15 秒，响应最大 2 MiB。
- Worker 会拒绝明显的本机、私网、链路本地和保留 IP 字面量。域名解析后的地址仍由 Cloudflare 网络层处理，因此 Access 保护生成接口是必需边界。

自动化测试位于 `test/`