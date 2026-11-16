# Changelog

## 1.1.0 — 2026-11-17

### Added

- Atomic profile workspaces on Unix: switch in the same kernel process, keep independent configuration revisions, selections, subscriptions and resources, reject stale profile contexts, recover interrupted switches, and retain the original profile when a switch fails. Includes bounded full-history migration and archive/resource export APIs. Windows retains its existing single-profile service; workspaces fail closed until a namespace ACL policy is available.
- Native GeoIP DAT/MMDB, GeoSite DAT and ASN MMDB assets and matching, plus process path/glob, UID, protocol and inbound conditions, and rule/global/direct routing modes.
- Bounded HTTP/TLS/QUIC sniffing and VLESS XHTTP, XMUX, separate download endpoints, advanced TLS/REALITY/ECH configuration and authenticated listeners.
- Control operations for outbound probes, cumulative and per-process traffic, DNS queries/cache flush, idle-network reset, structured logs and effective rules.
- Subscription-Userinfo parsing for provider-declared usage, total and expiry; failed refreshes retain the last successful metadata.
- Chunked, hash-verified resource staging and referenced-resource backups; individual resources can be up to 128 MiB. The standalone macOS companion adds URL resource imports and scheduled conditional updates without changing the original Mimo.

### Significant fixes

- Preserve retired backend leases across hot updates and detours; keep established flows attached to their original outbound.
- Prevent late subscription work and equal-revision client requests from crossing profile boundaries. Invalid target configuration, occupied listener ports and activation failures preserve or restore the prior profile.

### Performance

- Bounded parallel DNS upstream queries and reusable upstream pools; idle reset keeps Fake IP mappings.
- Bounded process accounting retains closed-connection totals for the current kernel session.

### Experience

- Standby startup with `-defer-network` turns takeover off before client readiness checks; invalid network-off configurations remain available for repair.
- Windows installer file-version metadata follows the selected release version.

Validation for this version is recorded separately from the historical 1.0 device, sleep/wake and power checkpoints. Builds remain unsigned. See [profile API and limitations](docs/profile-switching.md).

### 简体中文

#### 新增功能

- Unix 原子档案工作区：同一内核进程切档，配置版本、选组、订阅与资源各自独立；拒绝过期档案请求，支持中断恢复，切换失败继续使用原档案。新增有容量限制的完整历史迁移及档案／资源导出 API。Windows 保持原单档案服务，档案工作区在实现独立 ACL 策略前明确拒绝启用。
- 原生 GeoIP DAT/MMDB、GeoSite DAT、ASN MMDB 数据库与匹配条件；进程路径／通配符、UID、协议和入口条件；规则、全局和直连路由模式。
- 有界 HTTP/TLS/QUIC 嗅探；VLESS XHTTP、XMUX、独立下载端点、TLS/REALITY/ECH 高级选项和监听认证。
- 节点探测、累计及进程流量、DNS 查询／清缓存、空闲网络重置、结构化日志与实际生效规则等控制操作。
- 解析 Subscription-Userinfo 的套餐用量、总量与到期时间，刷新失败保留上次成功元数据。
- 按摘要分块上传和引用资源备份，单个资源上限提升至 128 MiB。独立 macOS 客户端提供 URL 资源导入和自动条件更新，不改动原来的 Mimo。

#### 重大修复

- 热更新和 detour 保留旧后端租约，已有连接继续使用原出口。
- 防止迟到的订阅任务及版本号相同的旧档案请求跨档写入；目标配置无效、端口冲突或激活失败时保留／恢复原档案。

#### 性能优化

- DNS 上游查询限制并发并复用连接池，重置空闲网络时保留 Fake IP 映射。
- 有界进程统计保留本次内核运行中已关闭连接的累计字节。

#### 体验改进

- `-defer-network` 在客户端就绪检查前关闭接管；接管关闭的错误配置仍可连接并修复。
- Windows 安装器文件版本随发行版本更新。

本版验证与历史 1.0 的设备、休眠唤醒和耗电记录分别说明，构建仍不签名。切档保留接管模式；接管参数变化可能重建 TUN 并中断相关连接。详见[档案接口与限制](docs/profile-switching.md)。

## 1.0.0 — 2026-11-16

First public release of the Reka proxy core.

- Versioned native configuration, source snapshots and overlays, durable transactions, secret storage, CLI and local control API.
- Hot updates retain existing flows while replacing and draining protocol instances, listeners and pools.
- Clash/share-link import, scoped DNS and Fake IP, automatic groups, locked rule resources and the documented protocol/transport/security options.
- macOS and Windows system takeover and service integration; Android JNI/Kotlin library with host-owned VpnService, socket protection and app routing.
- Six desktop targets, Android arm64 library, macOS packages and native Windows installers, with checksums, build metadata, dependency notices and corresponding source.
- [Validation scope](docs/validation.md), [reproducible benchmarks](docs/benchmarks.md), [configuration](docs/configuration.md) and [integration documentation](docs/gui-integration.md).

Packages are unsigned. Linux system takeover, iOS and Mimo GUI integration are outside this release. Concurrent VPNs require coordinated DNS ownership. The Android long power measurement retains its earlier checkpoint; the final library has separate idle-resource validation.

### 简体中文

Reka 代理内核首次公开发行。

- 原生配置、来源快照与覆盖层、持久化事务、秘密存储、CLI 和本地控制 API。
- 热更新保留既有连接，旧协议实例、监听器与连接池按租约排空。
- Clash／分享链接导入、作用域 DNS 与 Fake IP、自动策略组、锁定规则资源，以及文档列出的协议、传输和安全选项。
- macOS／Windows 系统接管和服务；Android JNI／Kotlin 库，由宿主管理 VpnService、socket protect 和分应用路由。
- 六个桌面目标、Android arm64 库、macOS 安装包及双架构原生 Windows 安装器，附校验和、构建元数据、依赖声明和对应源码。

构建不签名。Linux 系统接管、iOS 与 Mimo GUI 接入属于后续工作；多个 VPN 须协调 DNS 所有权。Android 长时耗电与最终库空闲资源核验保留各自的测量版本。
