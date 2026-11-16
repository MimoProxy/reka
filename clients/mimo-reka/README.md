# Mimo Reka for macOS

沿用 Mimo 的界面与交互，以 Reka 为唯一代理内核的独立 macOS 客户端。最低 macOS 14。

## 构建与打包

在仓库根目录运行：

```sh
./clients/mimo-reka/script/build_and_run.sh
./clients/mimo-reka/script/build_and_run.sh --package
```

产物：`clients/mimo-reka/dist/Mimo Reka.app` 和同目录 ZIP。构建优先使用 Xcode 工具链，不修改全局 `xcode-select`。Yams 源码随项目附带，构建不需要下载依赖；从当前工作区源码以锁定依赖、正式构建参数生成本机架构内核，记录内核提交、源码 SHA-256 和许可证；可用 REKA_KERNEL_PATH 显式指定已验证内核。试用包使用本地 ad-hoc 签名，未公证。

## 进程、套餐与完整备份

连接页的“进程识别”可选关闭、按规则需要、所有新连接；默认按规则需要以保持原配置语义。选择“所有新连接”后，新连接主动显示可执行路径、可用的 PID/UID；“应用流量”按路径和用户汇总本次内核运行的累计字节，连接关闭后保留。最多记录 1024 个具体身份，未知和超限单独归类，重启清零。

订阅卡片显示服务方 Subscription-Userinfo 声明的用量、剩余和到期时间。缺失值显示未提供，零值不推断无限套餐，刷新失败保留上次成功数据并标记；这些数值与本机连接流量分别统计。

配置菜单或设置“配置与数据”可打开“完整备份与恢复”。备份包含四层配置、选组、来源名称和引用资源（客户端最多 128 个/64 MiB）；文件含内联凭据，以 0600 权限保存。secret:// 仅备份引用，需要原钥匙串或另行补充秘密值。恢复先做资源摘要校验与配置预览，网络接管保持关闭；端口冲突会拒绝提交并保留当前配置。

## 本轮新增

- 独立节点/策略 HTTP 延迟测试，自定义地址与超时，不改变选择。
- 本次内核运行累计流量和采样速率；重启按 epoch 重新采样。
- 规则、全局、直连路由模式；全局出口明确选择，修改先预览。
- HTTP/TLS/QUIC 有界嗅探，连接详情显示嗅探域名、协议及可用的进程信息。
- 进程路径、通配符、UID、入口条件；路由解释与实际生效规则分页。
- DNS 分范围查询、清缓存与空闲连接重置，保留 Fake IP 映射；并发上游数和过期缓存设置。
- VLESS XHTTP、XMUX、独立下载端点、TLS/REALITY/ECH；监听认证用户。
- 结构化日志筛选，以及规则集/provider/GeoIP/GeoSite 文件上传、校验与引用。

所有会话以 `-defer-network` 待机启动，校验配置与持久化选组后保持接管关闭，由用户主动启用网络模式。上次未确认的网络提交不会在新会话自动执行，未知操作留档待核对。原本已关闭接管的错误配置仍提供控制接口供 GUI 修复。

## 独立运行

- 应用 ID：`org.mimoproxy.MimoReka`，进程为 `MimoReka` 与 `MimoRekaHost`。
- 配置目录：`~/Library/Application Support/MimoReka`，每份配置拥有独立来源、覆盖层和版本历史。
- 默认代理端口为 `127.0.0.1:17891`，首次创建配置遇到占用会使用空闲端口，界面显示实际地址。
- 初次启动只运行回环代理。系统代理和 TUN 需要在界面中主动启用；不会读取或改写原 Mimo 的工作区、Helper 或内核。
- 开启网络模式时由 macOS 请求管理员授权，运行独立的会话监督器，不安装 launchd 服务。管理员配置以 root 私有目录为准，控制 socket 仅向本机所属用户开放。

## 功能

仪表盘、多个配置档案、多来源导入、内核后台订阅刷新、策略与节点浏览、自动组健康状态、规则与 DNS、四层原生配置编辑、变更预览、配置历史恢复、连接管理、内核日志，以及系统代理和增强模式入口。

可视化编辑入口：配置列表的“可视化编辑”打开监听、日志、DNS、Fake IP、来源引用和节点表单；代理页“+”新建策略，当前策略的“编辑”修改类型、成员、健康检查与顺序；规则页支持新增、修改、删除和上下移动。订阅节点、策略与规则的修改写入覆盖层，不改写来源快照。所有变更先由内核校验、显示计划，再应用。高级 YAML 入口继续保留，未在表单中展示的已有字段不会被清除。

节点导入默认严格转换来源中的节点、策略与规则，也可以主动选择仅导入节点；无法转换的内容会阻止激活。原文中的 DNS 需要明确配置使用，不会静默替换本机解析策略。完整导入的来源规则优先匹配，应在其实际引用的策略组中选择节点。订阅刷新和选组均由 Reka 的版本化事务完成，失败保留旧版本。

仪表盘显示活动连接的上传与下载字节，进程内存使用 RSS；不将这些数据解释为累计流量、速率或真实物理内存。累计流量仅限本次内核运行，不提供跨会话历史流量；不展示 MITM、模块和 Tailscale 控件。

管理员授权会将四层配置与锁定的订阅资源复制到独立的 root 私有运行目录。已有 `secret://` 登录钥匙串引用不能直接迁移，应用会在停止原会话前明确拒绝。普通内联凭据配置可正常迁移；旧用户态版本仍保留为归档。网络授权配置后续启动需要重新授权。当前增强模式仅接管 IPv4，IPv6 不接管。

## 验证

```sh
MIMO_REKA_BIN_DIR="$(DEVELOPER_DIR=/Applications/Xcode.app/Contents/Developer xcrun swift build --package-path clients/mimo-reka --show-bin-path)"
DEVELOPER_DIR=/Applications/Xcode.app/Contents/Developer \
MIMO_REKA_KERNEL_BINARY="$PWD/clients/mimo-reka/.build/core/reka" \
MIMO_REKA_HOST_BINARY="$MIMO_REKA_BIN_DIR/MimoRekaHost" \
MIMO_REKA_LISTEN_PORT=0 \
xcrun swift test --package-path clients/mimo-reka
```

测试使用隔离状态与回环服务。`python3 clients/mimo-reka/script/test-session-host.py` 另外验证授权会话的资源迁移、认证停止与 GUI 崩溃清理；该测试专用编译开关不进入打包产物。网络接管验证应在确认现有 VPN/代理归属后进行，普通构建和测试不会开启它们。

本地开发支持 `MIMO_REKA_HOME` 覆盖应用数据根目录，`MIMO_REKA_PROOF_PATH` 导出本应用内容截图，`MIMO_REKA_APPEARANCE=light|dark` 和 `MIMO_REKA_MIN_WINDOW=1` 用于布局验收。
