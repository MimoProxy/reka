# 连接、DNS 和请求记录

Mimo Reka 的「连接」页提供连接历史和请求记录，「规则与 DNS」的 DNS 页提供查询历史。各列表可以搜索、查看较早的记录、查看详情或清空当前配置的历史。最新页每隔约一秒刷新。

历史按配置档案隔离，只保存在运行内存中。三类各保留至多 2,000 条，共用约 8 MiB 的记录数据预算。容量不足时淘汰较早记录。重启内核会清空历史。清空某类记录也会忽略清空前已开始、之后才结束的同类记录。

| 类别 | 采集范围 |
| --- | --- |
| 连接 | TCP 与 UDP 流，包括规则拒绝、拨号失败、正常结束和主动关闭。原始目标、路由改写后的目标和可确认的实际拨号地址分别记录。 |
| DNS | Reka 解析器处理的 TUN 劫持、DNS 监听、原生 API 与内核解析。区分 Hosts、Fake IP、过滤、上游、新鲜缓存、乐观缓存、合并查询和后台刷新。 |
| HTTP 请求 | HTTP 和 mixed 入站中已解析的转发请求，包括同一客户端连接上的多次请求。CONNECT 隧道和 WebSocket 升级仍在连接记录中查看。 |
| HTTPS 请求 | 本机 HTTPS 调试会话处理的 HTTP/1.1 或 HTTP/2 请求，以及 TCP 转发中匹配 MITM 配置的 HTTP/1.1 或 HTTP/2 请求。普通 TLS 透传和 HTTP/3 提供连接层信息。 |

DNS 历史记录查询名、RR 类型、客户端、来源、作用域、耗时、响应码及带 TTL 的答案。上游获胜者记录真实出口和协议，使用 fallback、合并等状态可单独筛选。合并请求和后台刷新分别以 `upstream_query_id`、`parent_id` 关联。连接或请求缺少测量值时，相应字段留空。HTTPS 的 `tls_ms` 是调试器到源站的 TLS 阶段，`dial_ms` 测量 Reka 的实际出站建立过程，可包含本地解析时间。

## HTTPS 调试

在「连接 → 请求记录 → HTTPS 调试」中填写需要调试的域名，可附端口。比如 `example.com` 或 `example.com:8443`。开启后，将待调试的客户端指向显示的本机 HTTP 代理地址，并提供本次会话的用户名和密码。导出的 CA 文件是公钥证书，可配置在待调试客户端的信任范围内。临时代理监听在 `127.0.0.1`，只接受选定的 HTTPS 目标。源站仍使用正常的证书验证。

会话最长一小时，停止调试或切换配置会关闭该入口及其隧道。请求按当前 Reka 规则处理。连接到其他域名的普通流量仍走各自原有入口。

摘要保存方法、主机、路径、HTTP 版本、状态码、字节数及实测耗时。查询字符串和 URL 凭证在记录时移除，常见凭证路径段脱敏。调试详情中的头只保留固定的诊断字段。正文预览需独立开启，每个方向最多保留前 8 KiB，并标明编码、实际读到的大小及截断状态。预览使用应用层字节，转发内容保持原样。

TCP 转发中的 MITM 请求以原 TLS 连接的 ID 关联，记录命中的重写规则和正文超限透传次数。连接字节数以客户端侧 TLS 密文计量。字段见 [MITM 状态](control-api.md#mitm-status)。

## 控制 API

这些方法通过 `GetCapabilities.methods` 发现，使用现有认证后的本机控制通道。

| 方法 | 参数及响应 |
| --- | --- |
| `ListConnectionHistory`、`ListDNSHistory`、`ListRequestHistory`、`ListScriptHistory` | 可选 `limit`（最多 100）、`before`（上一页的 `next`）、`query`。返回 `{epoch, rows:[{cursor,data}], next? ,expired?}`。游标失效后从最新页重新读取。 |
| `ClearHistory` | `{kind:"connections"\|"dns"\|"requests"\|"scripts"}`。返回 `{cleared}`。 |
| `GetRequestDetail` | `{cursor}`。用请求列表的游标读取保留中的调试详情。 |
| `StartHTTPSDebug` | `{targets:[...], capture_body?:false}`。返回监听地址、会话凭证、到期时间和公开 CA。 |
| `GetHTTPSDebug`、`StopHTTPSDebug` | 查询或关闭当前调试会话。 |
| `GetMITMStatus` | 查询 TCP 转发使用的 MITM 配置、CA 加载情况、绕过表和累计计数。 |

`ListScriptHistory` 每行是一次已结束的脚本运行：脚本 ID、名称、模块、类型（`http-request`、`http-response`、`cron`、`generic`、`event`）、HTTP 脚本对应的方法、URL、请求和连接 ID，以及开始时间、耗时、结果和错误。

`ListConnections` 仍可读取活动连接，`QueryDNS` 仍可单独发起查询。
