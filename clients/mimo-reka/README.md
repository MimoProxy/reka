# Mimo Reka for macOS

沿用 Mimo 的界面与交互，以 Reka 1.0.0 为唯一代理内核的独立 macOS 客户端。最低 macOS 14。

## 构建与打包

在仓库根目录运行：

```sh
./clients/mimo-reka/script/build_and_run.sh
./clients/mimo-reka/script/build_and_run.sh --package
```

产物：`clients/mimo-reka/dist/Mimo Reka.app` 和同目录 ZIP。构建优先使用 Xcode 工具链，不修改全局 `xcode-select`。Yams 源码随项目附带，构建不需要下载依赖；使用正式发行的 Reka 本机架构二进制。试用包使用本地 ad-hoc 签名，未公证。

## 独立运行

- 应用 ID：`org.mimoproxy.MimoReka`，进程为 `MimoReka` 与 `MimoRekaHost`。
- 配置目录：`~/Library/Application Support/MimoReka`，每份配置拥有独立来源、覆盖层和版本历史。
- 默认代理端口为 `127.0.0.1:17891`，首次创建配置遇到占用会使用空闲端口，界面显示实际地址。
- 初次启动只运行回环代理。系统代理和 TUN 需要在界面中主动启用；不会读取或改写原 Mimo 的工作区、Helper 或内核。
- 开启网络模式时由 macOS 请求管理员授权，运行独立的会话监督器，不安装 launchd 服务。管理员配置以 root 私有目录为准，控制 socket 仅向本机所属用户开放。

## 功能

仪表盘、多个配置档案、多来源导入、内核后台订阅刷新、策略与节点浏览、自动组健康状态、规则与 DNS、四层原生配置编辑、变更预览、配置历史恢复、连接管理、内核日志，以及系统代理和增强模式入口。

节点导入默认严格转换来源中的节点、策略与规则，也可以主动选择仅导入节点；无法转换的内容会阻止激活。原文中的 DNS 需要明确配置使用，不会静默替换本机解析策略。完整导入的来源规则优先匹配，应在其实际引用的策略组中选择节点。订阅刷新和选组均由 Reka 的版本化事务完成，失败保留旧版本。

仪表盘显示活动连接的上传与下载字节，进程内存使用 RSS；不将这些数据解释为累计流量、速率或真实物理内存。首版不展示独立测速、历史流量、MITM、模块和 Tailscale 控件。

管理员授权会将四层配置与锁定的订阅资源复制到独立的 root 私有运行目录。已有 `secret://` 登录钥匙串引用不能直接迁移，应用会在停止原会话前明确拒绝。普通内联凭据配置可正常迁移；旧用户态版本仍保留为归档。网络授权配置后续启动需要重新授权。当前增强模式仅接管 IPv4，IPv6 不接管。

## 验证

```sh
MIMO_REKA_BIN_DIR="$(DEVELOPER_DIR=/Applications/Xcode.app/Contents/Developer xcrun swift build --package-path clients/mimo-reka --show-bin-path)"
DEVELOPER_DIR=/Applications/Xcode.app/Contents/Developer \
MIMO_REKA_KERNEL_BINARY="$PWD/bin/releases/1.0.0/reka-1.0.0-darwin-arm64/reka" \
MIMO_REKA_HOST_BINARY="$MIMO_REKA_BIN_DIR/MimoRekaHost" \
MIMO_REKA_LISTEN_PORT=0 \
xcrun swift test --package-path clients/mimo-reka
```

测试使用隔离状态与回环服务。`python3 clients/mimo-reka/script/test-session-host.py` 另外验证授权会话的资源迁移、认证停止与 GUI 崩溃清理；该测试专用编译开关不进入打包产物。网络接管验证应在确认现有 VPN/代理归属后进行，普通构建和测试不会开启它们。

本地开发支持 `MIMO_REKA_HOME` 覆盖应用数据根目录，`MIMO_REKA_PROOF_PATH` 导出本应用内容截图，`MIMO_REKA_APPEARANCE=light|dark` 和 `MIMO_REKA_MIN_WINDOW=1` 用于布局验收。
