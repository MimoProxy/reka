# Reka 原生配置字段参考

本文介绍 `schema-version: 1` 的 YAML 字段。入门请看[配置与使用指南](configuration.md)，JSON 请求字段见[控制 API](control-api.md)。

## 1. 文件、合成顺序和基本约束

每个配置版本包含四份 YAML：

| 文件 | 顶层字段 | 用途 |
| --- | --- | --- |
| `profile.yaml` | `schema-version`、`imports`、`outbounds`、`groups`、`rules`、`rule-sets`、`sub-rules`、`geodata`、`dns`、`listeners`、`log`、`routing`、`sniff`、`process` | 节点、分组、路由和 DNS；必须有 `schema-version: 1` |
| `local.yaml` | `schema-version`、`listeners`、`log`、`control`、`network`、`routing`、`sniff`、`process`、`network-scenes` | 本机端口、日志、控制通道、系统接管和场景；可为空 |
| `sources.yaml` | `schema-version`、`sources` | 导入和订阅的原生快照 |
| `overlay.yaml` | `schema-version`、`patches` | 对已合成资源的持久覆盖 |

合成顺序是：内置默认值 → 显式启用的 sources → profile → overlay → local。local 中显式设置的 `listeners` 会**整表替换** profile 的监听器，包括 `listeners: []`；节点和分组用相同 ID 覆盖时也替换整个对象。`network`、`control` 只能放在 local，不能放进 profile。

解析严格检查未知字段、重复键、类型错误和多份 YAML 文档。每份文件最大 16 MiB，嵌套深度上限 32。不同协议不适用的字段会报错，即使字段值为空或 `false`。

原生资源 `id` 最长 64 个字符，以字母或数字开头，其余允许字母、数字、`.`、`_`、`-`。`name` 是显示名称，引用统一使用 `id`。source 资源合成后的 ID 是 `source/id`；YAML 引用写 `airport/hk`，API 路径中的单个 ID 段写 `airport~1hk`。普通规则的 `id` 可省略，source 中每条规则必须有 ID。详细合成和覆盖规则见 [Sources 与 overlays](source-overlays.md)。

## 2. 本机监听、日志和控制通道

```yaml
listeners:
  - id: mixed
    type: mixed
    listen: "127.0.0.1:7890"
    udp: true
log:
  level: info
network:
  mode: off
```

| 字段 | 类型 / 默认值 | 含义及限制 |
| --- | --- | --- |
| `listeners` | 对象列表，默认无监听器 | 可放 profile 或 local；local 优先 |
| `listeners[].id` | 必填字符串 | 稳定 ID |
| `listeners[].type` | 必填字符串 | `mixed`、`socks`、`http` |
| `listeners[].listen` | 必填字符串 | 字面 IP 与非零端口，例如 `127.0.0.1:7890`、`[::1]:7890`；不能写 `localhost:7890` |
| `listeners[].udp` | 布尔，mixed/socks 默认 `true` | SOCKS5 UDP ASSOCIATE；HTTP 不支持 UDP，不能为其显式设 `true` |
| `log.level` | 字符串，默认 `info` | `debug`、`info`、`warn`、`error` |
| `control.listen` | 字符串，默认使用 state-root 对应地址 | 只在 local 中设置；macOS/Linux 使用 `unix:///绝对路径/control.sock`，Windows 使用命名管道；更改需重启 |

mixed 同端口接受 HTTP 代理和 SOCKS4/4a/5；socks 类型支持 SOCKS4/4a/5。监听器支持 `users: [{username: Alice, password: secret://listeners/mixed/alice}]`；省略/空列表为免认证。最多 1024 个用户，用户名和密码均为 1–255 字节，用户名不能含冒号，凭据不能含 CR/LF/NUL，用户名不得重复。两者均可引用秘密，API 读取时遮罩；修改用户名后不能沿用旧密码掩码。没有监听 TLS 配置字段。控制通道独立于代理监听器，其默认地址及身份检查见[控制 API](control-api.md)。

## 3. 节点 `outbounds`

### 3.1 通用字段与协议选择

| 字段 | 类型 / 默认值 | 含义 |
| --- | --- | --- |
| `id` | 必填字符串 | 节点 ID；不能与分组 ID 重复 |
| `name` | 可选字符串 | 显示名称，不影响路由引用 |
| `type` | 必填字符串 | 见下面协议表 |
| `server` | 字符串 | 服务器域名或 IP，不含 URL 协议、路径和端口 |
| `port` | 整数 | 通常必填，范围 1–65535；HY2 端口跳跃和 Realm 见后文 |
| `udp` | 布尔，通常默认 `true` | 是否允许原生 UDP；HTTP 和 reject 不提供原生 UDP |
| `dialer` | 对象 | 物理出站参数或经过其他节点，见 3.6 |
| `multiplex` | 对象，默认关闭 | 通用多路复用，见 3.7 |

`direct` 和 `reject` 无需声明即可使用。`pass` 和 `reject-drop` 是额外路由动作，也可按 ID 引用：`pass` 继续尝试后面的规则，`reject-drop` 丢弃流量。它们不建立代理服务器连接。

| `type` | 身份和主要字段 | TLS / 扩展 |
| --- | --- | --- |
| `direct` | 无需 `server`、`port` | 可设 `udp`、`dialer` |
| `reject` | 无服务器字段 | 不允许 dialer / multiplex |
| `http` | `server`、`port`；可选 `username` + `password` | 可选 `tls`；`headers: [{name: X-Key, value: value}]`；无原生 UDP |
| `socks` | `server`、`port`；可选 `username` + `password` | SOCKS5 出站；可选 `tls`、`udp` |
| `shadowsocks` | `server`、`port`、`method`、`password` | `plugin`、`udp-over-tcp`、`udp-over-tcp-version`，见 3.8 |
| `vless` | `server`、`port`、`uuid` | `tls`、`flow`、`encryption`、`packet-encoding`、`transport` |
| `vmess` | `server`、`port`、`uuid` | `tls`、`protocol`、`packet-encoding`、`transport` |
| `trojan` | `server`、`port`、`password` | **必须有** `tls`；可用 `transport` |
| `hysteria2` | `server`、`port`、`password` | **必须有** `tls`；`protocol` 配置带宽、混淆、跳端口、Realm |
| `tuic` | `server`、`port`、`uuid`、`password` | **必须有** `tls`；`protocol` 配置拥塞控制等 |
| `snell` | `server`、`port`、`password`（PSK） | **必须有** `protocol.version: 5` 或 `6`；不接受顶层 `tls` |

HTTP / SOCKS 的 `username`、`password` 必须成对设置。HTTP 节点配置了用户名密码时，它们优先于自定义 `Proxy-Authorization`。UUID 必须是合法 UUID，不是任意字符串。

Shadowsocks 支持的 `method`：`2022-blake3-aes-128-gcm`、`2022-blake3-aes-256-gcm`、`2022-blake3-chacha20-poly1305`、`aes-128-gcm`、`aes-192-gcm`、`aes-256-gcm`、`chacha20-ietf-poly1305`、`xchacha20-ietf-poly1305`。2022 密码使用相应 Base64 密钥。

### 3.2 `tls`

提供 `tls: {}` 即启用普通 TLS；不需要 `enabled: true`。

| 字段 | 类型 / 默认值 | 含义及约束 |
| --- | --- | --- |
| `server-name` | 字符串 | SNI；服务器是域名时通常默认采用 `server`，用 IP 连接时应填服务器证书对应域名 |
| `insecure` | 布尔，默认 `false` | 跳过普通 TLS 证书验证；REALITY 不接受此字段为 true |
| `fingerprint` | 可选字符串 | TCP uTLS ClientHello 模板；`chrome`、`firefox`、`edge`、`safari`、`360`、`qq`、`ios`、`android`、`random`、`randomized`；HY2/TUIC 的 QUIC 不接受它 |
| `alpn` | 字符串列表 | ALPN；grpc/h2 必须包含 `h2`，ws/httpupgrade/http 若显式指定则必须为 `[http/1.1]` |
| `certificate-sha256` | 字符串 | **完整 DER 证书**的 SHA-256 十六进制摘要，可带冒号；与 ClientHello `fingerprint` 不同 |
| `verify-name` | 字符串 | 独立证书验证名称，保留原 SNI |
| `certificate`、`private-key` | 成对 PEM 字符串或 secret 引用 | 客户端证书和私钥；使用内联内容，不是文件路径 |
| `reality` | 对象 | 仅 VLESS，见下文 |
| `ech` | 对象 | ECH，见下文 |
| `carrier` | 对象 | VMess/VLESS/Trojan 的替代安全握手，见 3.9 |

证书 pin 是叶证书时直接信任该证书；pin 是中间证书或根证书时仍需验证叶证书链和名称。REALITY 不接受普通证书 pin、验证名称和客户端证书配置。

REALITY：

```yaml
tls:
  server-name: www.example.com
  fingerprint: chrome
  reality:
    public-key: "替换为服务器的32字节Base64URL公钥"
    short-id: "ab12"
    x25519mlkem768: true
```

`public-key` 使用无 `=` 填充的 Base64URL；`short-id` 为偶数位十六进制，最多 16 位，可为空。REALITY 必填 `server-name`，省略 `fingerprint` 时采用 `chrome` 并报告警告。`x25519mlkem768` 默认 false；是否开启应与服务器要求一致。

ECH 写作 `ech: {enabled: true, config: BASE64_ECHCONFIGLIST}`。省略 `config` 时通过活动 DNS 的 proxy-server 解析作用域查询 HTTPS 记录；`query-server-name` 可指定查询域名，自动模式需要配置原生 DNS 或启用 `dns.from`。ECH 数据缺失和认证失败会报错；不自动降级到明文 SNI。ECH 不能与 REALITY 或 `tls.carrier` 共用。

### 3.3 VLESS 扩展

| 字段 | 值 | 限制 |
| --- | --- | --- |
| `flow` | 空或 `xtls-rprx-vision` | Vision 至少需要 TLS 或有效 VLESS encryption |
| `packet-encoding` | `xudp`（默认）、`packetaddr`、`none` | `packet` 是 packetaddr 别名；packetaddr 的目标解析使用普通目标 DNS 作用域 |
| `encryption` | 空、`none` 或 `mlkem768x25519plus.MODE.RTT.KEY...` | 可用 secret 引用；需与服务器匹配 |

VLESS encryption 的 MODE 为 `native`、`xorpub`、`random`；RTT 为 `1rtt`、`0rtt`，relay key 使用 X25519 或 ML-KEM-768 公钥。上限为 32 个 relay key、32 个 padding phase、65553 字节总 padding。错误密钥使连接失败。

没有 VLESS encryption 时，Vision 要求原始 TCP，不能配置 `transport`。启用该加密层后，Vision 可搭配 WS、gRPC、HTTPUpgrade、HTTP、H2、XHTTP，且可不带外层 TLS；H2 本身仍要求 TLS。`tls.carrier` 的组合限制见 3.9。

### 3.4 `protocol`：协议专属参数

只填写对应协议的参数；HY2 的带宽、Snell 的版本等都位于 `protocol` 内。

| 协议 | 字段 | 类型、单位和可用值 |
| --- | --- | --- |
| VMess | `security` | 默认 `auto`；`auto`、`none`、`zero`、`aes-128-gcm`、`chacha20-poly1305` |
| VMess | `alter-id` | 整数，0–65535，默认 0 |
| HY2 | `up-bps`、`down-bps` | 精确**字节/秒**；可省略以使用自动带宽行为 |
| HY2 | `up-mbps`、`down-mbps` | 兼容字段，整数 Mbps；每个方向与对应 `*-bps` 二选一 |
| HY2 | `obfs` | `{type: salamander, password: ...}`，或 gecko |
| HY2 | `server-ports` | 字符串列表，使用显式 `起始:结束`，例如 `["443:443", "20000:20100"]`；最多 1024 个范围 |
| HY2 | `hop-interval-seconds`、`hop-interval-max-seconds` | 秒，0–86400；省略/0 默认 30 秒，下限按 5 秒执行；max 非零时不得小于 min |
| HY2 | `realm` | Realm 控制服务配置，见下文 |
| TUIC | `congestion-control` | `cubic`、`new_reno`、`bbr`；可省略，使用底层协议默认值 |
| TUIC | `udp-relay-mode` | `native`、`quic`；可省略 |
| TUIC | `zero-rtt` | 布尔，默认 false |
| TUIC | `heartbeat` | 非负整数，**毫秒**；省略/0 使用协议默认值 |
| Snell | `version` | 必填，`5` 或 `6`；v5 采用固定依赖的 v4 兼容 wire client |
| Snell | `user-key` | 可选字符串或 secret 引用 |
| Snell | `reuse` | 布尔，默认 false |
| Snell v6 | `mode` | 空、`default`、`unshaped`、`unsafe-raw` |
| Snell v5 | `obfs` | `{type: http, host: front.example}` 或 tls；none/空表示无混淆；v6 不接受 obfs |

VMess 的 `packet-encoding` 位于节点顶层，可省略或填写 `xudp`、`packetaddr`。

HY2 gecko 写作 `{type: gecko, password: ..., min-packet-size: 512, max-packet-size: 1200}`；省略大小时分别为 512 / 1200 字节，要求 `1 <= min <= max <= 2048`。salamander 不接受包大小字段。Snell 的 obfs 不接受 password。

配置了 HY2 `server-ports` 时可以省略 `port`；正常静态节点仍需要 `server`。启用 `realm` 时静态 `server` / `port` 可省略，且不能同时启用跳端口。

`protocol.realm` 字段：

| 字段 | 含义 |
| --- | --- |
| `enabled` | true 启用 |
| `server-url` | HTTP(S) 控制服务地址，不能含 URL 凭据、query 或 fragment |
| `token` | Bearer token，可用 secret 引用 |
| `realm-id` | 必填 Realm ID，最多 1024 字符 |
| `stun-servers` | 必填 1–64 个 STUN `host[:port]`，默认端口 3478 |
| `tls` | 控制服务独立 TLS；支持 SNI、ALPN、pin、verify-name 和客户端 PEM，不支持 TCP fingerprint、ECH、REALITY |

Realm 的 `tls` 验证控制服务，节点顶层 `tls` 验证最终 QUIC peer，两者独立。

### 3.5 `transport`

省略即原始流。对象内 `type` 必填，其余字段只适用于对应类型。

| `type` | 字段 | 适用及约束 |
| --- | --- | --- |
| `ws` | `path`、`host`、`headers`、`max-early-data`、`early-data-header` | VLESS/VMess/Trojan；early data 0–65536 字节 |
| `grpc` | `service-name` | VLESS/VMess/Trojan |
| `httpupgrade` | `path`、`host`、`headers` | VLESS/VMess/Trojan |
| `http` | `method`、`paths`、`headers`、`host` | VLESS/VMess；每次连接选择路径和各 header 的值 |
| `h2` | `hosts`、`path` | VLESS/VMess；必须启用 TLS |
| `xhttp` | `host`、`path`、`headers`、`xhttp` | 仅 VLESS；见 3.10 |

`headers` 使用 `[{name: X-Key, value: ...}]` 列表格式，值可用 secret 引用。`paths`、`hosts` 是字符串列表，`path`、`host` 是单个字符串，不要混用。协议 ALPN 和 Vision 的限制见前文。

### 3.6 `dialer` 与链式代理

| 字段 | 值 | 含义 |
| --- | --- | --- |
| `proxy` | 节点或分组 ID | 经另一个节点连接当前服务器 |
| `interface-name` | 本机网卡名 | 物理 socket 绑定接口 |
| `routing-mark` | 0–4294967295 整数 | 平台 socket 路由标记 |
| `ip-version` | 空、`dual`、`ipv4`、`ipv6`、`ipv4-prefer`、`ipv6-prefer` | 服务器地址解析/连接策略 |
| `tfo`、`mptcp` | 布尔，默认 false | TCP Fast Open / MPTCP；宿主不支持时返回错误 |

`dialer: {proxy: parent}` 不会在 parent 不可用时改为直连。包括所有未选中分组成员在内的整个节点/分组图都必须无环。配置 proxy 后，它优先于子节点的物理 socket 参数；接口、mark 等应放在 parent。UDP 也要求父节点和经过的分组允许 UDP。替换父节点会重建依赖它的子节点，已有连接按旧实例排空。

### 3.7 `multiplex`

| 字段 | 默认 / 约束 |
| --- | --- |
| `enabled` | false |
| `protocol` | 可省略，或 `smux`、`h2mux`、`yamux` |
| `max-connections`、`min-streams`、`max-streams` | 非负整数；0 交给多路复用实现的默认行为 |
| `padding` | false |
| `only-tcp` | false；true 时保留原生 UDP 路径 |
| `statistic` | false；仅保留兼容元数据，Reka 始终报告自己的逐连接流量 |
| `brutal` | `{enabled: true, up-bps: 1250000, down-bps: 2000000}`；单位字节/秒，两方向至少 65536 |

可用于建立连接的各类出站；reject、pass、reject-drop 不支持。完整 multiplex 将 UDP 也送入 TCP carrier，因此它可以使 `udp: false` 的节点通过该封装承载 UDP；如果只想保持 TCP 多路复用，请显式设 `only-tcp: true`。Brutal 需要兼容服务端及 Linux TCP Brutal 内核模块，数值配置本身不保证实测吞吐量。

### 3.8 Shadowsocks 的 UoT 与 `plugin`

`udp-over-tcp: true` 开启 UoT；`udp-over-tcp-version` 为 `1` 或 `2`，默认 `1`。不开 UoT 时，原生 SS UDP 绕过 TCP plugin。以下 carrier 内置于内核，无需另起同名插件进程。

| `plugin.type` | 字段 / 例子 |
| --- | --- |
| `obfs` | `mode: http` 或 `tls`；`host` |
| `v2ray-plugin` | `mode: websocket`、`host`、`path`、`tls`、`mux`、`headers`；还接受 `http-upgrade`、`fast-open`（需要 http-upgrade） |
| `gost-plugin` | `mode: websocket`、`host`、`path`、`tls`、`mux`、`headers` |
| `shadow-tls` | `host`、`version: 1\|2\|3`（默认 2）、`password`、`tls` |
| `restls` | `host`、`password`、`version-hint: tls12\|tls13`、`restls-script`、`force-tls12`、`client-fingerprint`、`tls` |
| `jls` | `host`、`username`、`password`、`alpn`、`client-fingerprint` |
| `kcptun` | `kcp: {...}`；自动启用 UoT |

obfs/v2ray/gost 的 host 省略时默认 `bing.com`；其他有 host 的 plugin 必须明确填写。WebSocket plugin 的 `mux` 默认 true。其 `tls` 与 SS 密码独立，支持 pin、verify-name、客户端 PEM 与 ECH；显式 Host header 也设置 SNI。ShadowTLS/Restls 不支持 ECH；Restls 的 ClientHello 模板放在 `client-fingerprint`，不放 `tls.fingerprint`。plugin 不再接受 `tls.carrier`。Restls script 最大 8192 字节。

kcptun 的 `kcp` 使用这些原名：`key`、`crypt`、`mode`、`conn`、`autoexpire`、`scavengettl`、`mtu`、`ratelimit`、`sndwnd`、`rcvwnd`、`datashard`、`parityshard`、`dscp`、`nocomp`、`acknodelay`、`nodelay`、`interval`、`resend`、`nc`、`sockbuf`、`smuxver`、`smuxbuf`、`framesize`、`streambuf`、`keepalive`。时间单位中 interval 是毫秒，autoexpire/scavengettl/keepalive 是秒；缓冲区和 MTU 是字节。defaults 跟随固定参考实现，建议显式设置 `key` 或 secret 引用。`mode` 的 normal/fast/fast2/fast3 会覆盖 nodelay、interval、resend、nc；自定参数用 manual。连接槽上限 64，各配置缓冲区不超过 64 MiB。具体边界在 `internal/compat/kcptun/config.go`。

### 3.9 `tls.carrier` 安全握手

只适用于 VMess / VLESS / Trojan，放在节点 `tls` 内；伪装名称、ALPN 和 ClientHello 由同一 TLS 对象的其余字段配置。

| `carrier.type` | 专属字段 |
| --- | --- |
| `shadow-tls` | `version`（1、2、3，默认 2）、`password` |
| `restls` | `password`、`version-hint`、`script`（最多 8192 字节） |
| `jls` | `username`、`password`，均必填 |

这些模式与 REALITY/ECH 互斥。ShadowTLS/Restls 使用普通证书验证选项；JLS 使用凭据认证，不接受普通证书 pin、verify-name、客户端证书或 insecure。Vision 搭配 ShadowTLS/Restls 或没有 ClientHello 模板的 JLS 时，需要有效 VLESS encryption；有模板的 JLS 组合按其握手能力验证。凭据可用 secret 引用。

### 3.10 XHTTP

VLESS 节点使用 `transport: {type: xhttp, host: front.example, path: /tunnel, xhttp: {mode: auto}}`，完整配置见 [xhttp.yaml](../examples/config/xhttp.yaml)。主端点服务器、端口、TLS 位于节点顶层，Host/path/headers 位于 transport；主 `xhttp` 中不能重复填写端点字段。

`transport.xhttp` 字段：

| 字段 | 值 / 默认与限制 |
| --- | --- |
| `mode` | 默认 auto；auto、packet-up、stream-up、stream-one；stream-one 不允许独立下载端点 |
| `no-grpc-header`、`x-padding-obfs-mode` | 布尔 |
| `x-padding-bytes` | 范围字符串，默认 `"100-1000"`，0–8192 字节 |
| `sc-max-each-post-bytes` | 范围字符串，默认 `"1000000"`，1–4194304 字节 |
| `sc-min-posts-interval-ms` | 范围字符串，默认 `"30"`，1–60000 毫秒 |
| `session-length` | 范围字符串，默认 `"16-32"`，1–256 |
| `uplink-chunk-size` | 范围字符串，默认 `"0"`，0–1048576 字节 |
| `x-padding-key`、`x-padding-header`、`session-key`、`seq-key`、`uplink-data-key` | 对应字段名称，最长 128 字节，header/cookie 名必须是合法 token |
| `x-padding-placement` | header、queryInHeader、query、cookie |
| `x-padding-method` | repeat-x 或 tokenish，亦可省略 |
| `uplink-http-method` | 合法 HTTP 方法名 |
| `session-placement`、`seq-placement` | path、query、header、cookie，亦可省略 |
| `uplink-data-placement` | body、header、cookie；header/cookie 需配置 uplink-data-key |
| `session-table` | 最长 256 字节；使用支持的预定义表或 URL-safe ASCII 字符表 |
| `xmux` | XHTTP 连接复用对象，区别于节点通用 multiplex |
| `download-settings` | 独立下载对象，仅允许一层；见下文 |

`xmux` 各项为数字或范围**字符串**：`max-concurrency`（0–65536）、`max-connections`（0–1024）、`c-max-reuse-times` / `h-max-request-times`（0–1073741824）、`h-max-reusable-secs`（0–604800 秒）；省略按复用实现默认值。`h-keep-alive-period` 是整数字符串，-1–3600 秒。

`download-settings` 可包含上述传输参数以及 `server`、`port`、`tls`、`disable-tls`、`host`、`path`、`headers`，省略 server/port/host/path/TLS 时使用相应上传端点设置；headers 和传输参数按下载对象自身配置，不应假定整份上传对象被复制。下载端点 TLS/ECH/证书和连接池独立。`disable-tls: true` 与显式 tls 互斥，不能递归嵌套 download-settings。启用混淆 padding 时必须明确 placement，header/queryInHeader 需 header 名，非 header 位置需 key。headers 名称不能重复，总量最多 16 KiB。

支持 HTTP/1.1、HTTP/2、HTTP/3；显式 `tls.alpn` 只能选单个 `http/1.1`、`h2` 或 `h3`。HTTP/3 不能搭配 REALITY、TCP 安全载体或 uTLS fingerprint。Vision 经 XHTTP 需要 VLESS encryption。Clash 导入支持 `network: xhttp` / `xhttp-opts`，其中 reuse-settings 与 xmux 不能同时填写。更多行为及互操作范围见[功能扩展说明](feature-expansion.md)。

## 4. 分组 `groups`

| 字段 | 类型 / 默认值 | 含义 |
| --- | --- | --- |
| `id`、`type` | 必填字符串 | type 为 `select`、`url-test`、`fallback`、`load-balance` |
| `name`、`icon` | 可选字符串 | 显示元数据 |
| `members` | ID 列表 | 节点或其他分组，不得重复；展开和过滤后至少一个成员 |
| `selected` | 可选成员 ID | 手动固定选择，写入版本并保留到重启；自动分组也可固定 |
| `include-all` | 布尔，默认 false | 添加原生已声明节点；source 分组局限于同 source，不自动添加内置动作 |
| `filter`、`exclude-filter` | Go/RE2 正则字符串 | 对节点显示名称（缺省时 ID）包含/排除过滤；分组成员按 ID 过滤；原生字段不支持 .NET lookaround |
| `disable-udp` | 布尔，默认 false | 拒绝经过本组链路的 UDP |
| `url` | HTTP(S) URL | 自动探测，默认 `https://www.gstatic.com/generate_204` |
| `interval` | 秒，默认 300 | 0 采用默认；上限 604800 |
| `timeout` | 毫秒，默认 5000 | 0 采用默认；上限 60000 |
| `tolerance` | 非负毫秒，默认 0 | url-test 的切换容差 |
| `lazy` | 布尔，默认 true | 成员/分组被使用后再启动探测 |
| `strategy` | 可选字符串 | load-balance 的 `consistent-hashing` 或 `round-robin`；省略使用一致性哈希 |
| `expected-status` | 可选字符串 | 原生默认 HTTP 200–399；可写 `204/300-399`、`200,204`、`*` |

url-test 选最快健康成员，fallback 按成员顺序选第一个健康成员。全部失败时尝试第一个配置成员，不会添加 DIRECT。运行时探测结果不产生新配置版本；`selected` 则是持久配置。分组不能有环。探测调度和一致性哈希细节见[自动分组](automatic-groups.md)；Clash 导入后的 filter 和 HTTP 状态默认值可能与原生不同。

## 5. 路由 `rules`、规则集与子规则

普通规则包含可选 `id`、`match`，以及二选一的 `outbound` 或 `call`。按顺序匹配，首个选出动作的规则生效；缺少兜底时最终直连，并给出验证警告。`{source: airport}` 是在当前位置展开 source 规则的标记，不能同时带 match/outbound/call。

| `match` 条件 | 值 / 含义 |
| --- | --- |
| `domain` | 精确域名，不区分大小写 |
| `domain-suffix` | 域名本身及其子域名 |
| `domain-keyword` | 域名包含关键词 |
| `domain-regex` | Go/RE2 域名正则 |
| `domain-pattern` | Clash 标签通配：`example.org` 精确、`+.example.org` 包含本域、`.example.org` 仅子域、`*.example.org` 一层标签 |
| `ip-cidr` | 目标 IPv4/IPv6 CIDR |
| `src-ip-cidr` | 来源 IP CIDR |
| `dst-port`、`src-port` | 端口或闭区间，例如 `443`、`"1000-2000"` |
| `network` | `tcp`、`udp` |
| `process-name` | 发起连接的进程 basename；无法取得进程时不匹配 |
| `process-path`、`process-path-regex` | 进程完整路径的精确 / .NET 兼容正则匹配 |
| `process-name-wildcard`、`process-path-wildcard` | 进程名 / 完整路径通配，`*` 任意跨度，`?` 一个字节 |
| `uid` | OS UID 或闭区间，0 不匹配未知拥有者 |
| `in-name`、`in-user` | 本机 listener ID / 已认证用户名，区分大小写，`/` 分隔备选值 |
| `in-type` | HTTP、SOCKS4、SOCKS5、TUN；SOCKS 包括 SOCKS4/5 |
| `in-port` | 本机代理监听端口；TUN 不匹配 |
| `process-name-regex` | 不区分大小写的 .NET 兼容正则，支持 lookaround，匹配预算 50 ms；无法取得进程时不匹配 |
| `rule-set` | 一个已声明的规则集 ID |
| `geoip` | 内置仅 `LAN`；其他国家使用锁定地理资源对应的 rule-set |
| `and`、`or` | 非空条件列表，按书写顺序短路 |
| `not` | 恰好含一个条件的列表 |
| `all` | 必须写 `true`，兜底 |

入口和进程路径规则的未知值不匹配；端口/UID 表达式支持 `/` 分隔备选值及闭区间，最多 28 段。完整大小写、平台和匹配语义见[高级规则](advanced-rules.md)。

一个 match 只能有一种条件，普通条件可用列表表示“任一值匹配”。`no-resolve: true` 是目的 IP 类条件的修饰符；不会启动域名解析，但可使用已得到的地址。默认 IP 规则会使用当前 DNS 解析域名后匹配，优先第一条 IPv4 答案，否则第一条 IPv6；失败只是不匹配该规则。ExplainRoute 禁止解析时可能给出 `undetermined`。

```yaml
rule-sets:
  - id: sites
    entries:
      - {domain-suffix: example.org}
sub-rules:
  - id: secure
    rules:
      - {id: block, match: {and: [{rule-set: sites}, {dst-port: 443}]}, outbound: reject}
rules:
  - {id: private, match: {geoip: LAN, no-resolve: true}, outbound: direct}
  - {id: call-secure, match: {network: tcp}, call: secure}
  - {id: final, match: {all: true}, outbound: direct}
```

`rule-sets[].entries` 是条件列表，按 OR 合并，可引用其他集合；`sub-rules[]` 是 `{id, rules}`。call 的 guard 成立后才进入子规则，子规则没有选中动作则回到父列表继续。循环引用（包括未使用的定义）无效。

外部规则集字段为 `id`、`behavior`、`format`、`hash`；地理资源还用 `code`，classical 引用映射用 `references: [{name: ..., to: ...}]`。`hash` 是完整 SHA-256，字节必须事先存在于本机 state 的资源存储，不接受运行期 URL/文件路径下载。规则 provider、MRS、GeoIP DAT/MMDB、GeoSite DAT 和资源边界见[规则资源](rule-resources.md)。

## 6. DNS `dns`

DNS 放在 profile 或 source 内；不配置时使用系统解析。启用原生 DNS 必须提供 `nameserver`；从 source 启用可写 `dns: {from: airport}`，并在 profile 中指定本地 listen 等覆盖。

| 字段 | 类型 / 原生默认值 | 含义 |
| --- | --- | --- |
| `from` | source ID | 选用已导入 source 的 DNS，不自动启用所有 source DNS |
| `listen` | 可选 `IP:port` | 内核 DNS UDP/TCP 服务地址；省略不监听本地 DNS 端口 |
| `nameserver` | endpoint 字符串列表 | 普通解析上游，必填 |
| `default-nameserver` | endpoint 列表，默认 system | bootstrap：解析上游服务器域名；允许 IP endpoint、system，或已指定物理网卡的 DHCP DNS，且只能直连 |
| `proxy-server-nameserver` | endpoint 列表 | 解析代理节点服务器；不得依赖另一个代理 |
| `direct-nameserver` | endpoint 列表 | 直连目的地解析 |
| `direct-nameserver-follow-policy` | false | direct 解析是否继续遵循 nameserver-policy |
| `nameserver-policy` | `{id, pattern, servers}` 列表 | 首个 pattern 匹配生效，servers 非空；支持域名模式和规则集选择器 |
| `fallback` | endpoint 列表 | 备用解析上游 |
| `fallback-filter` | 对象 | `geoip`、`geoip-code`、`geoip-set`、`geosite`、`ipcidr`、`domain`；地理条件需要显式锁定资源 |
| `hosts` | `{id, addresses}` 列表 | id 为域名，addresses 为 IP 列表，或**单个域名别名**；通过 use-hosts 启用 |
| `use-hosts` | false | 启用上述 hosts |
| `use-system-hosts` | false | 读取本机 hosts；每代配置准备时读取一次 |
| `enhanced-mode` | 默认 `redir-host` | `redir-host` 或 `fake-ip` |
| `fake-ip-range` | 默认 `198.18.0.0/16` | IPv4 fake 地址段，至少四个地址 |
| `fake-ip-range6` | 默认 `fc00::/18` | IPv6 fake 地址段，至少四个地址 |
| `fake-ip-filter` | 模式字符串列表 | 域名模式、rule-set/geosite 选择器 |
| `fake-ip-filter-mode` | 默认 `blacklist` | blacklist 匹配则绕过 fake 分配；whitelist 仅匹配项分配 fake |
| `fake-ip-ttl` | 秒，省略为 60，范围 0–86400 | **显式 0 即响应 TTL 为 0**，另保留 60 秒连接映射租约 |
| `max-concurrent-upstreams` | 默认 4 | 0 采用默认；1–16，限制并发竞争的上游 worker |
| `cache-stale-ttl` | 默认 0 秒 | 0 禁用；最大 86400 秒，允许过期普通答案以 TTL 0 返回并后台刷新 |
| `cache-size` | 默认 4096 | 0 采用默认；最大 1000000 |
| `ipv6` | false | false 时客户端 AAAA 得到空地址答案 |
| `respect-rules` | false | 普通上游连接按当前路由规则选出站 |
| `prefer-h3` | false | HTTPS 上游进行 TLS/QUIC 握手选择，只在选中的传输发送 DNS 查询 |

endpoint 支持裸 `IP[:port]`、`udp://`、`tcp://`、`tls://`、`https://`、`http://`、`quic://`、`h3://` 和 `system`。默认端口：UDP/TCP 53、DoT/DoQ 853、HTTPS/H3 443、HTTP 80。DoH/H3 默认路径 `/dns-query`。

fragment 的裸值选择节点或分组，例如 `https://1.1.1.1/dns-query#proxy`。可用 `&` 连接选项，例如 `https://dns.example/dns-query#proxy&h3=true`。支持：`h3`、`skip-cert-verify`、`name-cert-verify`、`ecs`（IP/CIDR）、`ecs-override`、`disable-ipv4`、`disable-ipv6`、`disable-reuse`、`disable-qtype-N`（DNS 类型编号）。布尔值必须写 true/false。证书选项仅用于加密传输；`h3=true` 只适用于 HTTPS/H3。

Fake IP 映射写入 `<state-root>/cache/fake-ip.json`，重启恢复未过期映射；正在使用的映射在租约结束前不会重新分配。hosts 别名链出现环时拒绝解析。DNS 模型和作用域、fallback 顺序、缓存以及凭据遮罩见 [DNS 与 Fake IP](dns.md)。

## 7. 系统接管 `local.network`

| 字段 | 默认 / 值 | 含义 |
| --- | --- | --- |
| `mode` | `off`、`system-proxy`、`tun`；默认 off | 存储的系统接管意图 |
| `proxy-bypass` | Windows system-proxy 专用 | 系统代理绕过串；空采用 `<local>`，最长 8192 字节，无控制字符；其他平台非空报错 |
| `proxy-listener` | listener ID | system-proxy 必填，必须指向 loopback mixed 监听器 |
| `service` | macOS 网络服务名 | macOS 的 system-proxy / 完整 TUN 接管必填，例如 `Wi-Fi`；不是 en0/en1 网卡名。Windows 可省略 |
| `tun.stack` | 默认 mixed | `mixed`、`system`、`gvisor` |
| `tun.mtu` | 默认 1500 | 范围 1280–9000 |
| `tun.address4` | 默认 `172.19.0.1/30` | IPv4 TUN 地址及前缀 |
| `tun.address6` | 默认空 | 配置后才能声明 IPv6 接管和 IPv6 routes |
| `tun.routes` | CIDR 列表 | 省略/空表示为已配置地址族安装默认路由 |
| `tun.exclude-routes` | CIDR 列表 | 接管排除地址段 |
| `tun.bind-interface` | 可选网卡名 | 物理出站接口 |
| `tun.dns-hijack` | 默认 false | 截获 TCP/UDP 53 并交给配置 DNS；完整 TUN 接管要求 true |
| `tun.app-mode` | 默认 all | Android 的 `all`、`include`、`exclude` |
| `tun.apps` | 包名列表 | include/exclude 时必须非空；all 时不得填写 |

当前 Linux 只提供本地代理监听模式，不提供该模式下的 TUN 或系统代理接管。macOS/Windows 支持 TUN 和 system-proxy；Android 的 TUN 由宿主 VPN 服务提供，应用路由仅 Android 支持。启动普通代理无需开启接管。

完整 TUN 模式必须配置原生 DNS、`dns-hijack: true` 和显式 `default-nameserver`，上游不能使用 system，以避免系统解析回到自身。系统权限/服务安装、macOS service、状态恢复和切换中断语义见[系统接管](network-takeover.md)及[分发与安装](distribution.md)。

## 8. Sources、订阅和 overlay

profile 的 `imports[]` 包含 `source`，以及 `outbounds`、`groups`、`rule-sets`、`sub-rules` 的布尔开关。规则通过 `rules: [{source: airport}]` 在指定位置展开；DNS 通过 `dns.from` 选用，互不自动启用。

`sources.sources[]` 包含 `id`、`outbounds`、`groups`、`rules`、`rule-sets`、`sub-rules`、`dns`，以及可选 `subscription` 和 `lock`。订阅 URL 不应直接写进 profile 的 outbounds。

| `subscription` YAML 字段 | 含义 |
| --- | --- |
| `url` | 订阅 URL 或 secret 引用 |
| `format` | `auto`（省略时自动识别）、`clash` 或 `links` |
| `interval` | 秒；0/省略为 3600，显式值 30–604800 |
| `nodes-only`、`allow-partial`、`paused` | 仅节点、允许不完整导入、暂停自动刷新 |
| `headers` | `{name, value}` 列表，value 可用 secret 引用 |
| `geodata` | `{id, url}` 资源列表，URL 可用 secret 引用 |
| `provider-directory` | 显式授权的本地 provider **绝对路径**目录 |
| `certificate-files` | 最多 64 个 `{path, value}`，将唯一外来证书路径映射到 PEM 内容/secret，而不是远程任意读文件 |

`lock` 保存资源 SHA-256 和请求身份，通常由刷新流程产生。其 `root` 为根文档 hash，`resources[]` 中包含 `id`、`kind`、`name`、`hash`、`request` 及可选 `format` / `behavior`。这些字段用于固定资源，不是下载指令。

`overlay.patches[]` 使用 `op: set|remove|insert`、`path`、可选 `value` 以及插入位置 `before` / `after`。选择导入分组时，CLI 会自动把选择持久化进 overlay。订阅 CLI、刷新默认值与失败保留旧快照行为见[订阅](subscriptions.md)；转换见 [Clash 导入](clash-import.md)，完整四文件例子见 [Sources 与 overlays](source-overlays.md)。

## 9. 凭据与热更新

用户名、密码、UUID、VLESS encryption、header 值、客户端 PEM、plugin/carrier 凭据、kcptun key、Realm token 等支持 `secret://名称`。例如 `password: secret://nodes/hk/password`，通过 `rekactl secret set nodes/hk/password` 从标准输入存入。DNS endpoint 暂不支持 secret 引用；URL 含凭据时按 URL 规则遮罩。

API 默认将内联凭据显示为 `********`，把遮罩原样提交会保留存储值。`secret://` 引用本身可以显示；已解析凭据不会进入 effective JSON。磁盘上的原生文档如果写了明文凭据，仍然存储该明文，遮罩不是磁盘加密。

保存 `<state-root>/edit/` 中的配置文件会提交一次事务；无效文件保留旧运行配置，错误写到同名 `.errors`。多个文件需一起生效时使用一次 API 请求；CLI 的完整文件 commit 每次只替换一份文档。路由和选择变化影响新连接，旧连接保留原出站；更换节点地址/凭据会创建新实例并排空旧实例。control 地址需重启，TUN 参数变化可能中断接管流量。事务、回滚和可运行命令见[配置与使用指南](configuration.md)。

## 10. 路由模式与嗅探

`routing` 和 `sniff` 均可放在 profile / local，local 对象整体优先。routing 默认为 `{mode: rule}`；mode 接受 rule/global/direct，global 模式必须设置 `global: 节点或组ID`，任何已填写的 global 目标都必须存在。模式切换保留原始规则，影响新连接；network.mode 另行管理系统接管。

| `sniff` 字段 | 默认 / 边界 |
| --- | --- |
| `enabled` | false，省略整个对象也关闭 |
| `protocols` | 省略/空为 `[http, tls, quic]`；不允许重复或其他协议 |
| `timeout-ms` | 0/省略为 300；10–2000 毫秒 |
| `max-bytes` | 0/省略为 65536；512–262144 字节 |
| `max-packets` | 0/省略为 8；1–32 |
| `override-destination` | false；true 才允许拨号目标改成嗅探域名 |

嗅探补充缺少入口域名的路由信息，保留已有域名/Fake IP 含义；不能解开 ECH 内部名称。最多并发 64 个嗅探操作，溢出直接路由；超时或无效数据也会原样重放。开启后，CONNECT/SOCKS 可能先确认隧道再因路由拒绝而关闭。详见[功能扩展](feature-expansion.md)。

### 10.1 网络场景

在 `local.yaml` 定义场景。自动模式按列表顺序选择第一个匹配项，`interface` 匹配默认路由网卡名，`ip-cidr` 匹配其任一地址。两项同时配置时须同时满足。启用 TUN 且指定 `bind-interface` 时检查该网卡。仅指定 `id` 的场景可手动选择。

```yaml
network-scenes:
  - id: home
    interface: en0
    ip-cidr: [192.168.50.0/24]
  - id: travel
```

在 `profile.yaml` 的 `rules` 中使用 `network-scene`，可与域名等条件组合。以下规则只有在 `home` 场景下才让指定域名走直连。

```yaml
rules:
  - id: home-printer
    match: {and: [{network-scene: home}, {domain-suffix: printer.home.arpa}]}
    outbound: direct
```

`rekactl scene` 显示识别结果，`rekactl scene use travel` 临时选择场景，`rekactl scene auto` 恢复自动识别。场景变化影响新连接。自动识别依赖系统默认路由监视，Android 可手动选择。

## 11. 源码核对入口

字段声明：[`model/types.go`](../internal/config/model/types.go)、[`model/dialer.go`](../internal/config/model/dialer.go)、[`dns/config.go`](../internal/dns/config.go)、[`platform/config.go`](../internal/platform/config.go)。协议约束：[`compile.go`](../internal/config/compile/compile.go)、[`protocol.go`](../internal/config/compile/protocol.go)、[`ss_plugin.go`](../internal/config/compile/ss_plugin.go)、[`tls_carrier.go`](../internal/config/compile/tls_carrier.go)、[`realm.go`](../internal/config/compile/realm.go)。运行时默认值也可能由固定依赖填充；接入方应查询当前内核 `GetCapabilities` 并在提交前验证配置。
