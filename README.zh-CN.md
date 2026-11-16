<div align="center">

<h1>Reka</h1>

<p><a href="README.md">English</a> · <strong>简体中文</strong></p>

<p>用 Go 编写的代理内核：配置由内核自己掌管，修改配置不重启、不断连接</p>

<p>
  Reka 取自俄语 “Река”，意为“河流”。<br />
  河道可以改，水照常流。
</p>

</div>

Reka（Reka proxy core）是一个无界面的代理内核，面向 macOS、Windows 和 Android。它正作为 [Mimo](https://github.com/MimoProxy/Mimo) 客户端的内核开发，任何 GUI 都可以通过它的控制 API 驱动它。

> **状态：1.0 候选验收阶段，尚未正式发布。** 实现与实测范围见[候选验收说明](docs/validation.md)，固定参数性能结果见[可复现对照报告](docs/benchmarks.md)。构建不签名，请核对随附的 SHA-256、构建元数据和对应源码；正式发布在发行评审后进行。

## 为什么

Clash 系内核只读一份扁平的配置文件：GUI 每次重新生成它，API 的修改只留在内存里，订阅刷新会冲掉手改的内容；不少修改还要重载，已有连接随之中断。Reka 围绕两条原则设计：

- **配置只有一份真相。** 内核拥有配置。文件、CLI、API 和 GUI 都通过同一个带版本的事务提交，只有新配置已经运行并且落盘，才算提交成功。
- **改配置不重启。** 规则、选组、节点和监听器按资源差异生效。已经建立的连接继续使用它开始时的出站，直到自然结束。

## 现在能做什么

- **配置**：原生 YAML 主配置加本机设置，合成时记录每个字段的来源。严格解析，诊断带行号、列号和字段路径。内核写回配置时保留你的注释。
- **来源与覆盖**：主配置显式引用原生来源快照，节点与组按来源命名空间隔离，规则在指定位置展开；覆盖参数和手动选组独立保存。来源替换通过同一个配置事务生效，引用失效时拒绝激活。已支持 Clash/分享链接的本地转换和兼容报告，已支持 HTTP(S) 后台刷新与引用的 HTTP/inline/file provider，原文独立锁定，失败保留旧版。
- **事务**：版本历史与恢复、多个客户端之间的冲突检测、按操作 ID 安全重试、每一步都能崩溃恢复；手动编辑的文件也走同一个提交流程。
- **热更新**：出站按指纹复用或替换，旧实例排空后才关闭；监听器先绑定新端口再停止旧端口；端口被占用时在任何改动生效之前就会被发现。
- **路由**：按顺序首条命中的规则（`domain`、`domain-suffix`、`domain-keyword`、`domain-regex`、`ip-cidr`、`src-ip-cidr`、`dst-port`、`src-port`、`network`、`process-name`、全匹配），域名规则带索引；锁定规则集/地理库、递归逻辑与子规则；不发起网络请求的路由解释。
- **协议**：mixed、SOCKS5、HTTP 监听器，UDP 按目标分流；DIRECT、REJECT、HTTP、SOCKS5、Shadowsocks、VLESS + REALITY + Vision + XUDP、VMess、Trojan、Hysteria2、TUIC v5、Snell v5/v6 出站；VLESS encryption 还支持 Vision 与已列出的流式传输组合；VMess/VLESS/Trojan 支持 WS、gRPC、HTTPUpgrade、H2、通用多路复用及 ShadowTLS/Restls/JLS 安全载体，Shadowsocks 支持文档列出的七类插件。REALITY 客户端由 Reka 自己实现，支持 X25519MLKEM768。
- **DNS 与自动组**：按作用域的 DNS 策略、bootstrap、fallback、hosts 和缓存，DoT/DoH/DoQ/DoH3、hosts 别名与持久化 Fake IP 世代；select/url-test/fallback/load-balance 的健康检查有并发限制，观测状态不写配置。
- **秘密**：`secret://` 引用，保存在 macOS 钥匙串、Windows DPAPI、Android Keystore 回调或权限为 0600 的文件中。
- **控制 API**：在 Unix 域套接字或 Windows 命名管道上传输长度前缀的 JSON，只接受当前用户连接，带事件流；命令行工具 `rekactl`。
- **系统接管**：本机网络意图、TUN 路由与 DNS 劫持、系统设置条件恢复以及 launchd/SCM 服务；只改规则不替换设备，实测范围见验收说明。
- **Android**：JNI/Kotlin、VpnService fd、socket protect、分应用路由及显式 VPN 重建。

## 构建

需要 Go 1.27 或更新版本。

```sh
make build        # bin/reka 和 bin/rekactl
make test         # 单元测试和端到端测试
make android      # bin/android/libreka.so（需要 ANDROID_HOME 和 NDK）
```

## 快速开始

`profile.yaml`：

```yaml
schema-version: 1
outbounds:
  - id: my-ss
    type: shadowsocks
    server: ss.example
    port: 8388
    method: 2022-blake3-aes-128-gcm
    password: secret://outbounds/my-ss/password
groups:
  - id: proxy
    type: select
    members: [my-ss, direct]
rules:
  - match: {domain-suffix: [lan, local]}
    outbound: direct
  - match: {ip-cidr: [10.0.0.0/8, 192.168.0.0/16], no-resolve: true}
    outbound: direct
  - match: {all: true}
    outbound: proxy
```

`local.yaml`：

```yaml
listeners:
  - {id: mixed, type: mixed, listen: "127.0.0.1:7890"}
```

```sh
./bin/reka -profile profile.yaml -local local.yaml   # 导入为第 1 个版本，等待其中的秘密
printf '%s' '<base64 密钥>' | ./bin/rekactl secret set outbounds/my-ss/password   # 存好后开始运行
./bin/rekactl status
./bin/rekactl select proxy direct                     # 生效时不断开已有连接
./bin/rekactl explain www.example.com:443 -resolve
./bin/rekactl revisions
./bin/rekactl restore 1
```

状态保存在 `~/Library/Application Support/Reka`（macOS）、`%LOCALAPPDATA%\Reka`（Windows）或 `~/.local/state/reka`（Linux）；用 `-state-root` 可以指定其他目录。当前配置还会导出到 `<state-root>/edit/`，在那里保存修改即可提交。

## 文档

- [候选验收说明](docs/validation.md) · [性能与原始数据](docs/benchmarks.md)
- [分发与安装](docs/distribution.md)
- [系统接管](docs/network-takeover.md)
- [GUI 接入与原生示例](docs/gui-integration.md)
- [Android 接入](docs/android-integration.md)

- [配置参考](docs/configuration.md)（英文）
- [控制 API](docs/control-api.md)（英文）
- [后台订阅与 provider](docs/subscriptions.md)（英文）
- [Clash 导入与限制](docs/clash-import.md)（英文）
- [字段支持表](docs/clash-support.md)（英文）
- [来源与覆盖层](docs/source-overlays.md)（英文）
- [DNS 与 Fake IP](docs/dns.md)
- [自动组与健康检查](docs/automatic-groups.md)

## 许可

[GPL-3.0](LICENSE)。Reka 使用了 [sing-box](https://github.com/SagerNet/sing-box) 家族的协议组件（sing、sing-tun、sing-vmess、sing-shadowsocks 等）；Reka 是独立项目，与 sing-box 没有关联，也未获其背书。
