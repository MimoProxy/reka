# Clash 控制 API

Reka 可以在单独的本地 HTTP 端口为 Clash 兼容面板提供状态和常用操作。它默认关闭，启用时必须指定数字形式的回环地址和一个至少 16 字符的令牌。

```sh
export REKA_CLASH_SECRET="$(openssl rand -hex 24)"
./bin/reka -clash-listen 127.0.0.1:9090
```

在面板中填写 `http://127.0.0.1:9090` 和同一个令牌。如果面板网页来自另一个源，在启动时加上 `-clash-allow-origin https://dashboard.example`，写实际的网页源，不带尾部斜杠或路径。多个源可用逗号分隔。普通 HTTP 请求使用 `Authorization: Bearer <令牌>`。WebSocket 也接受 Clash 面板使用的 `?token=`。

| 接口 | 行为 |
| --- | --- |
| `GET /version`、`GET /configs` | 版本与只读的运行设置 |
| `GET /proxies`、`GET /proxies/{name}`、`GET /group`、`GET /group/{name}` | 节点、策略组、实际选择和可用的健康观测。重名时会加上稳定 ID |
| `GET /proxies/{name}/delay?url=…&timeout=…` | 指定节点或策略组的 HTTP(S) 延迟探测。超时单位为毫秒 |
| `PUT /proxies/{name}` | 正文为 `{"name":"节点名"}`。手动组的选择作为版本化覆盖层保存，刷新订阅后仍有效 |
| `GET /rules` | 当前生效的规则 |
| `GET /connections` | 活动连接和累计流量。普通 HTTP 返回一次快照，WebSocket 按间隔推送 |
| `DELETE /connections`、`DELETE /connections/{id}` | 关闭当前所有连接或明确指定的连接 |
| `GET /traffic`、`GET /memory`、`GET /logs` | WebSocket 或逐行 JSON。内存为 Go 运行时占用，单位为字节 |
| `GET /providers/proxies`、`GET /providers/rules` | 订阅来源和可刷新规则集。原生独立规则集使用 `rule-set/<ID>`，订阅规则使用 `<来源 ID>/<provider 名称>` |
| `GET`、`PUT /providers/{proxies\|rules}/{name}` | 读取或刷新指定 provider。订阅规则会和同一来源的资源一起校验并提交 |

路径中的名称需要 URL 编码。面板使用的配置写入、重启、升级和远程管理接口不在此兼容范围内。完整配置编辑和版本管理见[原生控制 API](control-api.md)。
