# Reka 配置与使用指南

本文介绍 schema 1 / 控制 API 1 的启动、订阅、配置修改和排查。通过 `GetCapabilities` 查询当前内核支持的功能。

- 查 YAML 字段：[配置字段参考](configuration-reference.md)。
- 开发脚本或 GUI：[控制 API 手册](control-api.md)，附可运行的 Python 客户端。
- 已有订阅：[第 4 节](#4-使用订阅clash-配置或分享链接)。
- 配置 TUN / 系统代理：[第 7 节](#7-系统代理与-tun)。

## 1. 先跑通一个本地代理

### 准备与启动

从源码运行需要 Go 1.27+、Python 3 和 make。在仓库根目录执行：

```sh
make build
```

得到 `bin/reka`（内核）和 `bin/rekactl`（控制工具）。推荐使用这个入口，它带上本项目需要的构建标签、组件修正和链接参数。已有发行包时可直接使用其中的两个可执行文件；下文的 `./bin/` 相应替换为解压位置，示例 YAML 可从仓库的 [examples/config](../examples/config/) 复制。

下面使用独立的 `.reka-demo` 状态目录和 `127.0.0.1:17890` 代理端口，`network.mode` 为 `off`。示例通过本地代理接收请求，随后从本机直连目标。换成真实代理节点见第 3 节。

终端一，在仓库根目录执行并保持运行：

```sh
./bin/reka -state-root "$PWD/.reka-demo" \
  -profile examples/config/profile.yaml \
  -local examples/config/local.yaml
```

终端二，同样进入仓库根目录：

```sh
./bin/rekactl -state-root "$PWD/.reka-demo" status
./bin/rekactl -state-root "$PWD/.reka-demo" get effective

# HTTP 代理
curl --proxy http://127.0.0.1:17890 https://example.com/

# SOCKS5；h 表示把目标域名交给内核解析
curl --proxy socks5h://127.0.0.1:17890 https://example.com/
```

外网请求是否成功还取决于本机到目标的连通性。应用里填写 HTTP 或 SOCKS5 代理 `127.0.0.1:17890` 即可使用；启动监听器后，应用需要主动使用该代理。`mixed` 端口同时接受 HTTP 和 SOCKS。

停止前台内核：在终端一按 `Ctrl+C`。下次使用同一个状态目录启动即可恢复配置：

```sh
./bin/reka -state-root "$PWD/.reka-demo"
```

**`-profile`、`-local`、`-sources`、`-overlay` 只在状态目录首次初始化时导入。** 后续修改使用 `rekactl commit`、API 或 `<state-root>/edit/`，见第 5 节。重复传入初始文件不会覆盖已保存的配置。

### 最小配置

[profile.yaml](../examples/config/profile.yaml)：

```yaml
schema-version: 1

groups:
  - id: proxy
    type: select
    members: [direct, reject]
    selected: direct

rules:
  - id: final
    match: {all: true}
    outbound: proxy
```

[local.yaml](../examples/config/local.yaml)：

```yaml
listeners:
  - id: mixed
    type: mixed
    listen: "127.0.0.1:17890"
log:
  level: info
network:
  mode: off
```

`direct` 和 `reject` 是内置出站，无需声明。规则按顺序匹配，第一条命中就生效；没有匹配时默认直连，所以建议总是写最后的 `all: true`。裸启动内核不会自动创建代理监听端口。

### Windows 命令

在仓库根目录的 PowerShell 中：

```powershell
$rekaDemoRoot = Join-Path (Get-Location) '.reka-demo'
.\bin\reka.exe -state-root $rekaDemoRoot -profile .\examples\config\profile.yaml -local .\examples\config\local.yaml
```

另开 PowerShell，进入同一目录：

```powershell
$rekaDemoRoot = Join-Path (Get-Location) '.reka-demo'
.\bin\rekactl.exe -state-root $rekaDemoRoot status
curl.exe --proxy http://127.0.0.1:17890 https://example.com/
```

后续示例使用 macOS/Linux shell；Windows 将路径和可执行文件后缀相应替换，API 内容和 YAML 格式相同。

## 2. 配置保存在哪里

Reka 自己保存配置历史。每个版本有四份 YAML：

| 文件 | 用途 | 通常由谁维护 |
| --- | --- | --- |
| `profile.yaml` | 节点、策略组、路由规则、DNS、来源引用 | 你或 GUI |
| `local.yaml` | 本机监听端口、日志、控制地址、系统代理/TUN | 你或 GUI |
| `sources.yaml` | 订阅和导入产生的原生资源快照 | 导入器、订阅刷新 |
| `overlay.yaml` | 对导入资源的持久修改、导入组的手动选择 | 你、CLI 或 GUI |

生效顺序：内置默认值 → profile 显式引用的来源 → profile → overlay → local。本机设置覆盖 profile 中对应的设置。`sources` 中存在节点后，还需通过 profile 的 `imports` 将它引入。

| 平台 | 用户态默认状态目录 |
| --- | --- |
| macOS | `~/Library/Application Support/Reka` |
| Windows | `%LOCALAPPDATA%\Reka` |
| Linux | `$XDG_STATE_HOME/reka`，未设置时 `~/.local/state/reka` |
| Android | 宿主应用传入的私有目录，见 [Android 接入](android-integration.md) |

本文一直显式传入 `-state-root "$PWD/.reka-demo"`，操作的是演示实例。已安装的系统服务另有状态目录和控制地址，见[安装文档](distribution.md)。

## 3. 添加自己的代理节点

### Trojan 完整示例

复制 [proxy.yaml](../examples/config/proxy.yaml)，将 `server` 和 TLS `server-name` 改成服务端提供的值。主要内容如下：

```yaml
schema-version: 1

outbounds:
  - id: my-trojan
    name: 我的节点
    type: trojan
    server: proxy.example.com
    port: 443
    password: secret://outbounds/my-trojan/password
    tls:
      server-name: proxy.example.com

groups:
  - id: proxy
    type: select
    members: [my-trojan, direct]
    selected: my-trojan

rules:
  - id: local-domains
    match: {domain-suffix: [lan, local]}
    outbound: direct
  - id: private-addresses
    match:
      ip-cidr: [127.0.0.0/8, 10.0.0.0/8, 172.16.0.0/12, 192.168.0.0/16, "::1/128", "fc00::/7", "fe80::/10"]
      no-resolve: true
    outbound: direct
  - id: final
    match: {all: true}
    outbound: proxy
```

内核保持第 1 节的演示配置运行时，先保存密码，再提交修改后的文件：

```sh
# private-password.txt 是你自己准备的密码文件，内容为节点密码
./bin/rekactl -state-root "$PWD/.reka-demo" secret set outbounds/my-trojan/password < /path/to/private-password.txt
./bin/rekactl -state-root "$PWD/.reka-demo" validate /path/to/my-proxy.yaml
./bin/rekactl -state-root "$PWD/.reka-demo" plan /path/to/my-proxy.yaml
./bin/rekactl -state-root "$PWD/.reka-demo" commit /path/to/my-proxy.yaml -m "添加代理节点"
```

`validate` 和 `plan` 会解析、检查配置，不建立远端代理连接。提交成功后再用 `curl --proxy` 验证服务端连通性。

`secret set` 从标准输入读取并去掉末尾换行，避免把密码写在命令参数里。也可以在 YAML 的 `password` / `uuid` 中填写真实值；API 默认显示 `********`。已有配置中的掩码可原样提交来保留值。首次启动若唯一问题是秘密尚未设置，内核会保存第 1 版并等待你用 `secret set` 补齐。

### 其他常用节点

以下是 `outbounds` 的单个条目，替换上面节点后，也要同步调整组的 `members` 和 `selected`。域名、端口、凭据及协议参数以服务端为准。

Shadowsocks：

```yaml
- id: my-ss
  type: shadowsocks
  server: ss.example.com
  port: 8388
  method: chacha20-ietf-poly1305
  password: secret://outbounds/my-ss/password
```

VLESS + REALITY + Vision：

```yaml
- id: my-vless
  type: vless
  server: vless.example.com
  port: 443
  uuid: secret://outbounds/my-vless/uuid
  flow: xtls-rprx-vision
  packet-encoding: xudp
  tls:
    server-name: camouflage.example.com
    fingerprint: chrome
    reality:
      public-key: "替换为服务端提供的无填充base64url公钥"
      short-id: "ab12"
```

Hysteria2：

```yaml
- id: my-hy2
  type: hysteria2
  server: hy2.example.com
  port: 443
  password: secret://outbounds/my-hy2/password
  tls:
    server-name: hy2.example.com
```

WireGuard can route private-subnet traffic through a single peer. Supply the peer's base64 public key and store the local private key under the referenced secret name.

```yaml
- id: private-net
  type: wireguard
  server: vpn.example.com
  port: 51820
  protocol:
    private-key: secret://outbounds/private-net/private-key
    public-key: "<peer public key>"
    address: [10.8.0.2/32]
    allowed-ips: [192.168.10.0/24]
```

See the [WireGuard field reference](configuration-reference.md#wireguard) for dual-stack addresses, keepalives, WARP reserved bytes and defaults.

VMess、TUIC、Snell、HTTP/SOCKS、TLS、WS/gRPC/H2、插件、链式代理等见[配置字段参考](configuration-reference.md)。原生类型名是 `shadowsocks` / `socks`；Clash 的 `ss` / `socks5` 等写法应走导入。

### Access a home network through WireGuard

Add a WireGuard outbound to `profile.yaml` with the home subnet in its `allowed-ips`. Use the peer's public key and the local address assigned by the peer administrator. Store the private key under the referenced secret name.

```yaml
schema-version: 1
outbounds:
  - id: home-wg
    type: wireguard
    server: home.example.com
    port: 51820
    protocol:
      private-key: secret://outbounds/home-wg/private-key
      public-key: "<peer public key>"
      address: [10.8.0.2/32]
      allowed-ips: [10.0.0.0/24]
rules:
  - match: {all: true}
    outbound: direct
```

Add the route on each device that needs it in `local.yaml`.

```yaml
link:
  wireguard:
    - outbound: home-wg
      routes: [10.0.0.0/24]
```

For an imported `.conf`, enable the source in the profile with `imports: [{source: home, outbounds: true}]` and use the full `home/p-…` ID from the import preview as `outbound`. Keep the profile's rules for other traffic. Omit `routes` to use the peer's `allowed-ips` if those prefixes are all valid local routes. For a full-tunnel peer, list just the home subnets under `routes`. [Importing a WireGuard `.conf`](clash-import.md#wireguard-conf-files)

In `rule` mode, connections to IP addresses in `10.0.0.0/24` use `home-wg` before the profile rules are evaluated. In `global` mode, the home route takes precedence over the global target. In `direct` mode, the home route is inactive. Reka matches available destination IPs with `no-resolve`. If you join a network that overlaps the configured home subnet, remove the entry or set `routes: []` while you are on that network. [Field reference](configuration-reference.md#linkwireguard)

### 手动切换与自动选择

```sh
./bin/rekactl -state-root "$PWD/.reka-demo" select proxy direct
./bin/rekactl -state-root "$PWD/.reka-demo" select proxy my-trojan
./bin/rekactl -state-root "$PWD/.reka-demo" group-status
```

`select` 使用稳定 ID，选择会保存并在重启后保留。`name` 只负责显示。自动选最快节点使用 `url-test`，按顺序故障切换使用 `fallback`，分配连接使用 `load-balance`。详见[字段参考](configuration-reference.md)及[自动组专题](automatic-groups.md)。

## 4. 使用订阅、Clash 配置或分享链接

导入分两步：先把资源放入 `sources`，再让 profile 使用这些资源。这里采用“只导入节点、由自己管理分流规则”的路径。

### 在线订阅

内核运行时，先保存订阅地址，再添加刷新任务：

```sh
# private-url.txt 内容为完整订阅 URL
./bin/rekactl -state-root "$PWD/.reka-demo" secret set subscriptions/airport/url < /path/to/private-url.txt
./bin/rekactl -state-root "$PWD/.reka-demo" subscription set airport secret://subscriptions/airport/url -nodes-only -interval 3600
./bin/rekactl -state-root "$PWD/.reka-demo" subscription refresh airport
./bin/rekactl -state-root "$PWD/.reka-demo" subscription list
./bin/rekactl -state-root "$PWD/.reka-demo" get sources
```

`airport` 是你给来源起的稳定 ID。显式 `refresh` 会等待结果，自动任务也会按间隔运行。失败保留上一次可用快照。`pause` 暂停自动刷新，`resume` 恢复，`remove` 删除刷新定义并保留已下载快照。

首次刷新成功后，提交 [subscription.yaml](../examples/config/subscription.yaml)：

```yaml
schema-version: 1

imports:
  - source: airport
    outbounds: true

groups:
  - id: proxy
    type: select
    include-all: true

rules:
  - id: local-domains
    match: {domain-suffix: [lan, local]}
    outbound: direct
  - id: private-addresses
    match: {ip-cidr: [127.0.0.0/8, 10.0.0.0/8, 172.16.0.0/12, 192.168.0.0/16], no-resolve: true}
    outbound: direct
  - id: final
    match: {all: true}
    outbound: proxy
```

```sh
./bin/rekactl -state-root "$PWD/.reka-demo" validate examples/config/subscription.yaml
./bin/rekactl -state-root "$PWD/.reka-demo" plan examples/config/subscription.yaml
./bin/rekactl -state-root "$PWD/.reka-demo" commit examples/config/subscription.yaml
./bin/rekactl -state-root "$PWD/.reka-demo" get effective
```

`include-all: true` 将已引入的非内置节点加入组。未指定 `selected` 时使用首个成员；在 `get effective` 中查出节点的完整 ID 后，可执行 `select proxy airport/p-实际ID`。导入器生成的 ID 不是节点显示名称，不要直接用订阅里的中文名称当 ID。也可改用显式 `members: [airport/p-实际ID]`。

### 本地 Clash 文件或分享链接

```sh
# 先预览转换报告，不修改配置
./bin/rekactl -state-root "$PWD/.reka-demo" import -source airport -nodes-only /path/to/clash.yaml

# 再导入节点
./bin/rekactl -state-root "$PWD/.reka-demo" import -source airport -nodes-only -apply /path/to/clash.yaml

# 分享链接列表也可以使用相同来源 ID
./bin/rekactl -state-root "$PWD/.reka-demo" import -source airport -format links -nodes-only -apply /path/to/links.txt
```

随后提交上面的 `subscription.yaml` 即可使用这些节点；本地文件导入无需在线刷新任务。使用同一 `source` ID 会替换该来源快照。

要保留订阅原来的组、规则和 DNS，省略 `-nodes-only` 并阅读[来源与覆盖层](source-overlays.md)中的引用方式：`imports` 显式开启 `groups` / `rule-sets` 等，`rules` 中用 `{source: airport}` 插入来源规则，DNS 用 `dns: {from: airport, listen: "127.0.0.1:5353"}` 启用。仅导入不会自动采用这些设置。

原生配置严格检查未知字段，Clash 转换也会报告兼容问题。完整转换默认拒绝含不支持内容的输入；`-allow-partial` 明确允许丢弃部分资源或选项，使用前先读报告。详见[Clash 导入](clash-import.md)、[字段支持表](clash-support.md)及[订阅/provider](subscriptions.md)。

## 5. 日常修改、保存与恢复

所有 `rekactl` 命令都连接运行中的内核，包括 `validate` 和导入预览。全局参数 `-state-root`、`-c`、`-json` 放在子命令之前。

### 修改一两个字段

```sh
./bin/rekactl -state-root "$PWD/.reka-demo" set -local /log/level '"debug"'
./bin/rekactl -state-root "$PWD/.reka-demo" set -local /listeners/mixed/listen '"127.0.0.1:17891"'
./bin/rekactl -state-root "$PWD/.reka-demo" origin /listeners/mixed/listen
```

`set` 的值采用 JSON；字符串可加 JSON 双引号。修改端口后，应用代理地址也要调整为 `17891`。

### 编辑完整文件后提交

```sh
./bin/rekactl -state-root "$PWD/.reka-demo" get profile > /tmp/my-profile.yaml
# 编辑 /tmp/my-profile.yaml 后：
./bin/rekactl -state-root "$PWD/.reka-demo" validate /tmp/my-profile.yaml
./bin/rekactl -state-root "$PWD/.reka-demo" plan /tmp/my-profile.yaml
./bin/rekactl -state-root "$PWD/.reka-demo" commit /tmp/my-profile.yaml -m "调整分流规则"
```

修改本机设置用 `get local` 和 `validate/plan/commit -local FILE`。来源、覆盖层分别使用 `-sources` / `-overlay`。默认提交基于当时的活动版本；多个编辑器同时工作时，记录读取时的版本号并传 `commit FILE -base 版本号`，过期版本会返回冲突。

事务依次校验、规划、准备资源、保存版本和切换运行状态。新端口已被占用等准备错误会拒绝修改。规则和选组只影响新连接；替换节点时已有连接继续使用旧实例并排空，强制排空超时为 30 秒。相同地址切换监听协议或重建 TUN 可能中断，先看 `plan` 的 `interrupts` / 网络变更说明。

### 直接编辑导出的文件

内核把四份文档导出到 `<state-root>/edit/`，本例为 `.reka-demo/edit/`。在这里保存会自动提交，默认约每 500 ms 检测一次。错误写入同名的 `.errors` 文件，原配置继续运行；修好后重新保存即可。停机期间的编辑也会在下次启动时被检查并提交。

如果 `.errors` 提示 `conflict`，先把编辑内容另存到目录外，读取最新配置并合并，再用 `commit FILE -base 最新版本号` 显式提交。其他 CLI/API 操作提交后，应等导出的文件更新再开始编辑。

每个文件单独形成一次事务。要同时删除节点并修改其他文档中的引用，使用单个 API 请求一起提交，见[配置事务 API](control-api.md)。初次传给 `-profile` 的原始文件不会被持续监测。

### 历史与恢复

```sh
./bin/rekactl -state-root "$PWD/.reka-demo" revisions
./bin/rekactl -state-root "$PWD/.reka-demo" restore 1
```

`restore` 会先要求确认；自动化脚本可显式加 `-yes`。恢复把旧的四份文档一起作为新版本提交，仍会检查端口和依赖。秘密值保存在独立秘密存储中，版本恢复不会把已修改的秘密值恢复成旧值。

## 6. DNS 与规则写法

省略 `dns` 时使用系统解析。下面的原生 DNS 配置放在 profile 顶层；`listen` 提供 UDP/TCP DNS 服务，可按需要省略：

```yaml
dns:
  listen: "127.0.0.1:5353"
  nameserver: ["https://1.1.1.1/dns-query"]
  default-nameserver: ["223.5.5.5"]
  proxy-server-nameserver: ["223.5.5.5"]
  enhanced-mode: redir-host
  ipv6: false
```

`nameserver` 解析一般目标，`default-nameserver` 引导解析 DNS 上游主机名，`proxy-server-nameserver` 解析代理服务器地址。应选择当前网络能访问的上游。配置监听地址不会自动改变系统 DNS。Fake IP、按域名选上游、hosts、DoQ/DoH3、DNS 路由等见[字段参考](configuration-reference.md)和[DNS 专题](dns.md)。

常用规则示例（放在 `rules` 内，并置于最终规则之前）：

```yaml
- id: block-one
  match: {domain: ads.example.com}
  outbound: reject
- id: work
  match: {domain-suffix: corp.example.com}
  outbound: direct
- id: proxy-web
  match: {dst-port: ["80", "443"]}
  outbound: proxy
```

每个 `match` 选择一个主条件，多个值表示任意一个匹配；`no-resolve` 是 IP 条件修饰项。组合条件使用 `and` / `or` / `not`。IP 规则默认可以为域名目标发起解析，`no-resolve: true` 跳过这一步。原生 `nameserver-policy` / `hosts` 使用带 `id` 的列表，格式与 Clash 的映射写法不同；已有 Clash 文档请通过导入转换。

资源 `id` 是引用、修改和历史追踪使用的标识。普通 ID 最多 64 字符，以字母或数字开头，可含字母、数字、`.`、`_`、`-`。导入资源完整 ID 为 `来源/资源`。YAML 的组成员用 `airport/node`，API/CLI 字段路径用 `/groups/airport~1proxy/selected`，其中 `~1` 转义 `/`。推荐给每条规则也设置 ID。

## 7. 系统代理与 TUN

第 1 节的 `network.mode: off` 可以先验证节点与规则。macOS / Windows 系统代理在 local 中配置；macOS 必须将 `service` 填为实际网络服务名称（可用 `networksetup -listallnetworkservices` 查看），Windows 可省略此行：

```yaml
network:
  mode: system-proxy
  proxy-listener: mixed
  service: Wi-Fi     # macOS 必填，按实际网络服务名称修改；Windows 可省略
```

TUN 需要相应平台权限或已安装的系统服务。完整接管前先在 profile 配置明确的 DNS 上游及 bootstrap，避免 DNS 回环。local 示例：

```yaml
network:
  mode: tun
  service: Wi-Fi     # macOS 完整接管必填；Windows 可省略
  tun:
    stack: mixed
    mtu: 1500
    address4: 172.19.0.1/30
    dns-hijack: true
```

先 `plan -local FILE` 再 `commit -local FILE`。IPv6 接管需要另外配置 `address6`；仅有 IPv4 地址时不会接管 IPv6。macOS/Windows 支持上述模式，Android 通过宿主 VpnService 接入，Linux 当前只支持 `off`。安装服务、权限、DNS 设置、退出恢复及接管限制见[系统接管](network-takeover.md)和[分发安装](distribution.md)。退出接管可提交 `network: {mode: off}`。

## 8. 路由模式、嗅探与入口认证

`routing.mode` 决定请求走哪里，与负责系统接管的 `network.mode` 分开。profile / local 均可设置 routing，本机对象整体优先：

```yaml
routing:
  mode: global
  global: proxy
```

`rule`（默认）按规则分流，`direct` 全部直连，`global` 交给明确指定的原生节点或组 ID。切换模式保留已保存的规则。上例要求 proxy 已存在；可用下列命令一次设置本机路由模式：

```sh
./bin/rekactl -state-root "$PWD/.reka-demo" set -local /routing '{"mode":"global","global":"proxy"}'
./bin/rekactl -state-root "$PWD/.reka-demo" set -local /routing '{"mode":"rule"}'
```

可在同一个 `routing` 对象中设置 `block-quic: proxy` 来拦截走代理的 QUIC，或设置 `block-quic: all` 来一并拦截直连 QUIC，默认值为 `off`。匹配的 UDP 数据包被丢弃后，支持回退的客户端会改用 TCP。UDP 443 以外的流量仅在嗅探识别为 QUIC 时才会被此开关拦截。

当 IP 目标缺少域名且当前路由规则包含域名条件时，内核默认通过 HTTP Host、TLS SNI 和 QUIC SNI 补充分流信息。可在 profile 或 local 自定义嗅探设置。以下示例显式开启嗅探，适用于收集连接域名等场景。

```yaml
sniff:
  enabled: true
  protocols: [http, tls, quic]
  timeout-ms: 300
  max-bytes: 65536
  max-packets: 8
  override-destination: false
```

设置 `sniff: {enabled: false}` 可关闭嗅探。local 的 `sniff` 对象整体覆盖 profile。已有入口域名和 Fake IP 仍用于路由。默认只补充路由信息，`override-destination: true` 才允许把实际拨号目标改成嗅探域名。嗅探无法获取 ECH 加密的内部名称。嗅探可增加有限的等待时间，收到的数据会原样重放。完整示例见 [advanced.yaml](../examples/config/advanced.yaml)。

代理监听器现支持 `users` 认证列表，见 [local-auth.yaml](../examples/config/local-auth.yaml)。先设置其引用的秘密，再用 `commit -local FILE` 提交。客户端需填写对应账号密码。`users` 省略或为空时免认证；修改凭据会重启监听器，已接受连接保留原路由。可用 `in-user` 区分已认证用户，也可按入口名称、协议和端口、进程完整路径及 UID 分流，见[高级规则](advanced-rules.md)和[字段参考](configuration-reference.md)。

VLESS 的 XHTTP 示例见 [xhttp.yaml](../examples/config/xhttp.yaml)，需要替换服务器、SNI 和 UUID。具体上传/下载端点、HTTP/3 与 TLS 限制见[字段参考](configuration-reference.md#310-xhttp)。

## 9. 客户端待机启动

CLI 默认恢复已保存配置。需要在恢复状态时先关闭系统接管，可使用：

```sh
./bin/reka -state-root "$PWD/.reka-demo" -defer-network
```

它会在恢复接管前把 `local.network.mode` 持久提交为 `off`，其他本机设置保留；这会产生普通配置事务，之后启用接管仍须显式提交。它不会把 `routing.mode` 改成 direct。

最新 macOS 客户端每次会话均以此模式启动，校验配置和选组后保持待机，等待用户主动启用网络模式。如果确认接管已关闭，但 profile 因缺少秘密等原因启动失败，仍提供控制接口供修复，`GetStatus.start_error` 会说明原因；无法确认已关闭接管或待机转换失败则终止启动。Android 对应入口为 `Native.startOff`。详见[客户端说明](../clients/mimo-reka/README.md)。

## 10. 常用排查

| 现象 | 检查方式 |
| --- | --- |
| `rekactl` 无法连接 | 内核是否运行、双方 `-state-root` 是否相同；自定义控制地址用 `-c` |
| 启动成功但代理端口不可用 | `status` 查看监听器，`get` / API 查看 `start_error`；确认 local 有 listeners、端口可用、秘密已设置 |
| 改了启动时的 YAML 没变化 | 使用 `commit FILE` 或编辑 `edit/` 内导出文件；初始文件参数只首次导入 |
| 订阅成功但没用上节点 | 检查 profile 的 `imports`、组成员、最终规则和 `get effective` 中的实际 ID |
| 配置提示未知字段 | 查[原生字段参考](configuration-reference.md)；Clash YAML 用 `import` 转换 |
| 编辑后配置未生效 | 查看 `.reka-demo/edit/*.errors`、提交诊断和引用冲突 |
| 想知道请求走哪个节点 | 用 `explain`，它解释路由，不建立实际代理连接 |
| TUN 保存了但未接管 | 查看 API 的 `runtime.network.state`、`error` 和权限；以运行状态为准 |

```sh
./bin/rekactl -state-root "$PWD/.reka-demo" explain example.com:443
./bin/rekactl -state-root "$PWD/.reka-demo" explain example.com:443 -resolve
./bin/rekactl -state-root "$PWD/.reka-demo" connections
./bin/rekactl -state-root "$PWD/.reka-demo" close all
./bin/rekactl -state-root "$PWD/.reka-demo" -json status
./bin/rekactl -state-root "$PWD/.reka-demo" watch
```

`explain` 默认不联网；遇到需要 DNS 的 IP 规则可返回尚不能确定，`-resolve` 才允许解析。`close all` 会主动断开当前连接。`watch` 显示配置、运行时和 `log` 事件；进程日志也输出到运行 `reka` 的终端 stderr。历史日志可通过 API `GetLogs` 查询。测速、累计流量、分页规则、DNS 查询与缓存刷新见[API 手册](control-api.md#10-测速流量规则dns日志和资源上传)。

如果在 local 设置了 `control.listen`，或启动时使用 `-control`，`rekactl -state-root` 仍只推导默认地址。请显式指定：

```sh
./bin/rekactl -c unix:///absolute/path/control.sock status
# 或设置 REKA_CONTROL 环境变量供后续命令使用
```

控制 API 没有 HTTP 端口。脚本接入使用[API 手册](control-api.md)和 [examples/control_client.py](../examples/control_client.py)。
