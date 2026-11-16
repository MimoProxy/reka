# Changelog

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
