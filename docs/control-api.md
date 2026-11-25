# Reka 控制 API 使用手册

本文介绍 **API v1 / 配置 schema v1** 的请求格式和常用方法。先启动内核请看[配置与运行指南](configuration.md)。

Reka 提供本机 IPC：macOS/Linux 使用 Unix socket，Windows 使用命名管道，Android 使用库调用。**内核没有 HTTP REST 控制接口，也不兼容 mihomo 的 `/proxies`、`/configs` 等接口**，不能直接用 `curl http://127.0.0.1:9090/...` 控制。仓库 dashboard 是另一个工具，其 HTTP 地址不是内核 API 地址。

## 1. 先实际调用一次

在仓库根目录启动[配置指南](configuration.md)中的 `.reka-demo` 实例后，另开终端执行：

```sh
# Python 3，无需安装依赖，每次自动完成 Hello 握手
python3 examples/control_client.py --socket "$PWD/.reka-demo/control.sock" GetStatus
python3 examples/control_client.py --socket "$PWD/.reka-demo/control.sock" GetCapabilities
python3 examples/control_client.py --socket "$PWD/.reka-demo/control.sock" GetConfiguration
python3 examples/control_client.py --socket "$PWD/.reka-demo/control.sock" \
  ExplainRoute '{"destination":"example.com:443","network":"tcp"}'

# Ctrl-C 结束；--watch 必须搭配 Subscribe
python3 examples/control_client.py --socket "$PWD/.reka-demo/control.sock" \
  --watch Subscribe '{"types":["config.committed","runtime.generation"]}'
```

[示例客户端](../examples/control_client.py)支持 `--socket /path` 或 `--socket unix:///path`。参数可直接写 JSON、用 `@request.json` 读取文件，或用 `-` 从标准输入读取。它只演示 Unix socket；Windows 用户可先用 `rekactl`。它是顺序调用示例；并发 GUI 应使用持续读循环，按响应 `id` 分发请求并单独处理事件。

无需写代码时，CLI 可以完成同样的操作：

```sh
./bin/rekactl -state-root "$PWD/.reka-demo" -json status
./bin/rekactl -state-root "$PWD/.reka-demo" -json get
./bin/rekactl -state-root "$PWD/.reka-demo" -json group-status
```

`rekactl` 全局参数放在子命令前。下面的 ID、revision、generation 都是示意值；写入时应读取当前 revision。

## 2. 地址、握手与消息格式

### 控制地址

| 平台 | 默认 state-root | 默认控制地址 |
| --- | --- | --- |
| macOS | `~/Library/Application Support/Reka` | `<state-root>/control.sock` |
| Linux | `$XDG_STATE_HOME/reka`，未设置时 `~/.local/state/reka` | `<state-root>/control.sock` |
| Windows | `%LOCALAPPDATA%\Reka` | `pipe://reka-<hash>`，实际为 `\\.\pipe\reka-<hash>` |
| Android | 宿主传入的应用私有目录 | 默认通过 `Native.call` 直接调用 |

Windows hash 由用户和 state-root 生成，使用 `rekactl -state-root ...` 或启动日志中的地址。自定义地址通过 `reka -control ADDRESS` 或 `local.control.listen` 指定，启动参数优先。控制地址改变需要重启；`-control -` 禁用 socket/管道。

Unix socket 权限为 `0600`，服务检查对端用户；Windows 管道限制当前用户和 LocalSystem，拒绝远程客户端。特权服务可用 `-owner UID/SID` 指定控制用户，见[系统接管](network-takeover.md)。普通客户端无需密码或 HTTP Bearer token。

### 帧

```text
4 字节无符号大端整数 N + N 字节 UTF-8 JSON
```

最大 JSON 长度 **16 MiB**，按字节计算；没有换行分隔符。必须循环读取完整的头和正文，一次 `recv` 不一定得到完整消息。超长输入帧会关闭连接；响应过大时返回错误，支持分页的接口应分页读取。

Android `Native.call` 传入一个 JSON 字符串，**不带四字节长度头**；`Host.onMessage` 接收事件。同样必须先 Hello，见[Android 集成](android-integration.md)。

### 握手与响应

每条新连接先发送：

```json
{"id":1,"method":"Hello","params":{"versions":[1],"client":"my-client/1.0"}}
```

成功响应：

```json
{"id":1,"result":{"version":1,"server":"reka/dev","schema_versions":[1],"epoch":"9f2c123456789abc"}}
```

`id` 是 uint64，建议从 1 递增；响应沿用请求 ID。`server` 包含构建版本，`epoch` 每次内核启动时变化。每次重连重新 Hello。

一般响应为 `{"id":2,"result":...}`；请求错误为：

```json
{"id":2,"error":{"code":"unknown_method","message":"unknown method UnknownMethod"}}
```

事件没有请求 ID，形如 `{"event":{...}}`。**事件可能先于请求响应到达**，包括 Subscribe 的首次 snapshot；不能把收到的第一帧直接当作响应。

API 参数通常用 `snake_case`，配置文档和 patch 路径使用 YAML 的 `kebab-case`，例如 API `nodes_only` 对应 YAML `nodes-only`。

## 3. 接口总览

未列参数时传 `{}`。先读取 `GetCapabilities`，以当前构建宣告的能力为准。

| 方法 | params | result |
| --- | --- | --- |
| `Hello` | `versions: [1]`，可选 `client` | `version`、`server`、`schema_versions`、`epoch` |
| `GetCapabilities` | 无 | API/schema 版本、方法列表、协议/规则/平台能力 |
| `GetStatus` | 无 | 配置版本与运行时状态 |
| `ProbeOutbound` | `outbound`、`url`，可选 `timeout_ms` | 显式节点/组的测速结果 |
| `GetConnectionTimeline` | `id`，可选历史 `epoch` | 连接阶段和关联的 DNS、HTTP 摘要 |
| `AddTemporaryRule` / `ListTemporaryRules` / `RemoveTemporaryRule` | `rule` 和可选 `ttl_seconds`，或 `id` | 临时分流规则 |
| `RunNodeArena` | `outbounds`，可选 `url`、`rounds`、`timeout_ms` | 多轮测速排名与逐轮结果 |
| `GetNetworkScene` / `SetNetworkScene` | 读取，或设置 `scene` | 当前场景和默认接口信息 |
| `GetTrafficBudgets` | 空 | 当前订阅的套餐流量预算 |
| `GetTraffic` | 无 | 累计 upload_total/download_total、sampled_at、epoch |
| `GetRules` | 可选 `offset`、`limit` | 活动模式与分页规则 |
| `QueryDNS` | `name`，可选 `type`、`scope`、`fake` | rcode、answer、authority、extra |
| `FlushDNSCache` | 无 | cleared：清除的普通缓存条数 |
| `ResetNetwork` | 无 | cleared，并清理空闲连接 |
| `GetLogs` | 可选 `limit` | events：近期 log 事件数组 |
| `StageResource` | `hash`、`size`、`offset`、`data` | hash、size、received、ready |
| `GetConfiguration` | 可选 `reveal: false` | 四份 YAML、生效配置、诊断 |
| `ValidateConfiguration` | change | `valid`、`diagnostics` |
| `PlanConfiguration` | change | `valid`、`plan`、`plan_hash` 或 `conflict` |
| `CommitConfiguration` | change，加可选 `operation_id`、`plan_hash`、`source`、`message` | 提交结果，必须检查 `state` |
| `GetOperation` | `operation_id` | 已记录的提交结果 |
| `ListRevisions` | 无 | `active`、`revisions`（新到旧） |
| `RestoreRevision` | `revision`、`base_revision`，可选 `operation_id` | 恢复为新版本的提交结果 |
| `GetGroupStatus` | 无 | 自动组观察状态数组 |
| `ListConnections` | 可选 `offset`、`limit` | `total`、`offset`、`connections` |
| `CloseConnections` | `ids: [数字]` 或 `all: true` | `closed` 数量 |
| `ExplainRoute` | `destination`，可选 `inbound`、`network`、`source`、`addresses`、`resolve`、`process`、`process_uid`、`inbound_type`、`inbound_port`、`inbound_user` | 路由解释 |
| `ImportSource` | `import`，可选 `reveal` | `report`、规范化 `sources` YAML、可选 `masked` |
| `ConfigureSubscription` | `source_id`、`base_revision`、`subscription` | 提交结果 |
| `ListSubscriptions` | 无 | 订阅安全状态数组 |
| `RefreshSubscription` | `source_id`，可选 `wait: false` | 刷新状态 |
| `AddModule` | `module`、`base_revision`，可选 `position` | 提交结果 |
| `RemoveModule` | `module_id`、`base_revision` | 提交结果 |
| `SetModuleEnabled` | `module_id`、`enabled`、`base_revision` | 提交结果 |
| `SetModuleArguments` | `module_id`、`arguments`、`base_revision` | 提交结果 |
| `RefreshModule` | `module_id`，可选 `wait: false` | 模块刷新状态 |
| `ListModules` | 无 | 模块、参数声明、刷新状态和报告摘要，不含 URL 或路径 |
| `GetModuleReport` | `module_id` | 完整模块转换报告 |
| `PreviewModule` | `data`，可选 `arguments` | 转换报告 |
| `SetSecret` | `name`、`value`，可选 `apply: true` | `name`、`ref`，可选 `apply` 提交结果 |
| `DeleteSecret` | `name` | `deleted` 名称 |
| `ListSecrets` | 无 | `names` 数组，不含值 |
| `GenerateMITMCA` / `ImportMITMCA` / `GetMITMCA` / `ExportMITMCA` / `DeleteMITMCA` | 见 [MITM CA](#mitm-ca) | CA 状态、公开证书或删除结果 |
| `GetMITMStatus` | 无 | 当前转发配置、CA 加载结果、临时绕过和累计计数，见 [MITM 状态](#mitm-status) |
| `Subscribe` | 可选 `types`、`epoch`、`after` | `subscribed: true`、`epoch`，持续推送事件 |
| `Unsubscribe` | 无 | `subscribed: false` |

以下功能的方法会按版本出现在 `GetCapabilities.methods` 中。

- `GetProfileState`、`SwitchProfile`、`GetProfileSwitchOperation`、`DeleteInactiveProfile`、`ExportProfileArchive` 和 `InstallProfile` 见[原子切档与档案迁移](profile-switching.md)。
- `GetProcessTraffic` 见[进程流量统计](process-accounting.md)。
- `ExportManifest` 和 `ReadResource` 见[资源导出](resource-export.md)。
- 历史查询、清空和 HTTPS 调试方法见[连接、DNS 和请求记录](traffic-history.md#控制-api)。

## 4. 读取与诊断

### GetCapabilities

字段包括 `api_version`、`schema_version`、`methods`、`outbound_types`、`listener_types`、`group_types`、`rule_conditions`、`shadowsocks_methods`、`tls_fingerprints`、`platform`、`process_lookup`、`configuration_layers`、`source_formats`、`import_support`、`network_modes`、`sniff_protocols` 和可选 `tun_stacks`。

不同平台的系统接管能力不同。不要根据 API 版本推断 TUN、系统代理、进程查询或某种协议支持，读取对应能力字段。

### GetStatus

以下是结构示例，实际数组和计数依配置而定：

```json
{
  "revision":3,
  "runtime":{
    "network":{"mode":"off","state":"Stopped","ipv6":false},
    "generation":5,"revision":3,"connections":0,
    "outbounds":["direct"],
    "listeners":[{"id":"mixed","action":"mixed","listen":"127.0.0.1:17890"}],
    "draining":0,"forced_closes":0,"acquire_retries":0
  },
  "goroutines":12
}
```

`revision` 是持久配置版本，`runtime.generation` 是运行时代次，不保证相等。此处 listeners.action 表示监听协议类型（mixed/socks/http），与变更计划中的 action 含义不同。`runtime.network` 是实际系统接管状态，可额外有 `device`、`error`；配置里的 mode 只是意图。若有 `start_error`，说明已保存配置未正常启动，控制端仍可读取和修正配置。

### GetConfiguration

`revision` 是配置版本。`profile`、`local`、`sources`、`overlay` 是 **YAML 字符串**。另有可选 `effective`、`diagnostics`、`masked`、`start_error`。`effective.provenance` 是字段来源，`effective.source_hashes` 是 source 快照摘要。`effective.scripts` 按合成顺序列出脚本元数据和锁定哈希，`effective.script-fingerprint` 标识脚本配置及其源码引用。

默认遮罩内联凭据为 `********`；`reveal:true` 显示文档中的内联值，不要把结果写进普通日志。`secret://...` 引用不是获取 secret 原值的接口。`effective` 是编译摘要，省略部分协议/DNS/传输凭据，不能当作原始配置提交。编辑使用原始文档或 patch；遮罩原样传回按已有字段身份保留原值。

### ExplainRoute

```json
{"destination":"example.com:443","network":"tcp","source":"127.0.0.1:50000","resolve":false}
```

目标必须是 `host:port`，IPv6 使用 `[::1]:443`。network 默认 tcp，仅接受 tcp/udp。source 是客户端地址，inbound 是入口 ID，process 是模拟进程名或完整路径；新增 inbound_type、inbound_port、inbound_user 和 process_uid 可模拟入口协议、本机监听端口、认证用户和进程 UID。addresses 可提供 IP 字符串数组供 IP 规则判断。

结果含 `matched`、`rule_index`，适用时还有 `rule_id`、`rule`、`chain`、`outbound`、`outbound_type`、`fingerprint`、`resolved`、`resolve_error`、`undetermined`。域名遇到需要解析的 IP 规则，而未允许 resolve、也未提供地址时，可能返回 undetermined。`resolve:true` 允许 DNS 查询。该接口不建立目标代理连接，不切换组或推进轮询。

### GetGroupStatus / 连接管理

GetGroupStatus 返回自动组数组，每项含 `id`、`type`、`selected`、`results`；成员观察含 `member`、`alive`、`delay_ms`、`checked`。select 组持久选择从配置读取；此接口不能触发手动测速，切换选择用配置提交。见[自动组](automatic-groups.md)。

ListConnections 的 offset 应为非负数；limit 为 1–1000，省略、≤0 或 >1000 时用 100。连接含 `id`、`inbound`、`network`、`source`、`destination`、`outbound`、`start`、`upload`、`download`，以及 `generation`、`revision`、`rule_index`、可选 `rule_id`、`rule`、`chain`、`fingerprint`。流量单位为字节。可选的新字段有 `sniffed_domain`、`protocol`、`process_path`、`process_uid`；进程信息按需查询，缺省不代表 UID 为 0。

`destination_domain` 记录入站提供的域名或 Fake IP 映射中的域名。活动连接的 `destination` 发生改写时，`original_destination` 保留入站收到的地址和端口。

`ListConnections`、`ListConnectionHistory` 和 `GetConnectionTimeline` 的连接条目可包含 `mitm`、`mitm_requests`、`mitm_matched_ids` 和 `mitm_body_passthroughs`。每条连接和请求最多保留 24 个去重后的重写 ID。正文超限按请求、响应两个方向分别计数。MITM 连接的 `upload` 和 `download` 与总量、按进程统计采用相同口径，均为客户端侧的 TLS 密文字节，包括握手。MITM 的 QUIC 拒绝在连接记录中使用 `reject_reason: mitm-quic`。

`ListRequestHistory` 中的 MITM 请求带 `mitm: true` 和父连接的 `connection_id`，适用时还带 `matched_ids`、`body_passthroughs` 和 `resource_error`。同一 TLS 连接内的多个请求共享连接 ID。请求记录沿用现有的 URL 和头字段脱敏。

```json
{"id":10,"method":"ListConnections","params":{"offset":0,"limit":100}}
{"id":11,"method":"CloseConnections","params":{"ids":[123,124]}}
{"id":12,"method":"CloseConnections","params":{"all":true}}
```

最后一个请求会主动关闭全部当前连接；只查看用 ListConnections。

## 5. 修改配置：读取 → 校验 → 规划 → 提交

### change 结构

```json
{
  "base_revision":12,
  "patch":[
    {"op":"set","path":"/groups/proxy/selected","value":"direct"},
    {"op":"insert","path":"/rules","before":"final","value":{"id":"example","match":{"domain":"example.org"},"outbound":"direct"}},
    {"op":"remove","path":"/rules/old-rule"}
  ],
  "local_patch":[{"op":"set","path":"/log/level","value":"debug"}]
}
```

这只是结构示例，实际调用只保留当前文档中有效的操作。

| 字段 | 作用 |
| --- | --- |
| `base_revision` | 客户端读取时的版本；Plan/Commit 要求仍为活动版本 |
| `profile`、`local`、`sources`、`overlay` | 可选，替换对应整份 YAML，值为字符串 |
| `patch`、`local_patch`、`sources_patch`、`overlay_patch` | 可选，编辑对应文档；先替换整份，再依次应用 patch |
| `import` | 可选，原子替换一个导入 source，格式见后文 |

未提供的文档保留原值。四份文档可以一次原子修改。Validate 只编译候选，不能替代版本冲突检查；Plan 和最终 Commit 才检查 base_revision。

patch 支持 `set`、`remove`、`insert`，**不是 RFC 6902 JSON Patch**。set/insert 需要 JSON value；insert 路径指向列表，可用 before 或 after 放到指定 ID 旁，均省略则追加。元素使用稳定 id，无 ID 才使用 `#0`、`#1` 等从零开始的位置。路径转义 `~` → `~0`、`/` → `~1`：例如 `airport/proxy` 对应 `/groups/airport~1proxy/selected`。

`patch` 只改 profile。source 策略组的用户选择通常应写进 **overlay**：向 overlay_patch 的 `/patches` 插入 `{op:set,path:/groups/airport~1proxy/selected,value:airport/node-id}`，使选择在 source 更新后继续覆盖。见[来源与覆盖](source-overlays.md)。

### 可运行事务示例

下面仅把本机日志级别设为 debug，不需要节点，不改变路由或系统网络：

```sh
python3 - <<'PY'
import sys
import uuid
sys.path.insert(0, "examples")
from control_client import Client

with Client(".reka-demo/control.sock") as c:
    cfg = c.call("GetConfiguration")
    change = {
        "base_revision": cfg["revision"],
        "local_patch": [{"op": "set", "path": "/log/level", "value": "debug"}],
    }
    checked = c.call("ValidateConfiguration", change)
    if not checked["valid"]:
        raise SystemExit(checked)
    planned = c.call("PlanConfiguration", change)
    if not planned["valid"] or planned.get("conflict") or planned["plan"].get("blocked"):
        raise SystemExit(planned)
    request = dict(change, operation_id="example-" + uuid.uuid4().hex,
                   plan_hash=planned["plan_hash"], message="Set local log level")
    result = c.call("CommitConfiguration", request)
    print(result)
    if result["state"] != "committed":
        raise SystemExit("Configuration was not committed")
PY
```

切换原生 profile 的 select 组，可把 local_patch 换成下列 patch，同时保留正确的 base_revision：

```json
{"patch":[{"op":"set","path":"/groups/proxy/selected","value":"hk"}]}
```

proxy 必须存在，hk 必须是可选成员。变化影响新连接，已有连接保留原出口。希望已有连接也重建时，可提交后有选择地 CloseConnections。

### 校验、计划、结果

校验返回 `valid`、可选 `diagnostics`。诊断含 `severity`（error/warning）、`code`、`message`，以及可选 `document`、`path`、`line`、`column`。warning 本身不阻止提交。

规划返回 `base_revision`、`valid`，以及可选 `plan`、`plan_hash`、`diagnostics`、`conflict`。先检查 valid/conflict，再检查 plan.blocked。计划包括：

- `outbounds`、`listeners`：资源 id/action，以及可选连接数、监听地址、说明；action 是 keep/create/replace/remove/rebind/restart。
- `rules_changed`、`rules`、`groups`、`log_level`：规则变化、规则数量、组选择变化、日志变化。
- `dns_changed`、`automatic_groups_changed`、`network_changed`、`network_note`：DNS、自动组、系统接管变化；另有 `routing_changed` 和 `sniff_changed`。
- `draining`、`blocked`、`interrupts`、`restart_required`：排空数量、阻止原因、中断提示、需重启字段。

Validate/Plan 不下载订阅、不绑定端口、不执行系统接管；准备阶段仍可能遇到端口占用。plan_hash 锁定候选文档，推荐随 Commit 提交。

**收到 result 不代表提交成功，必须检查 result.state**：

```json
{"id":20,"result":{"operation_id":"my-op-001","state":"committed","revision":13,"generation":20}}
```

```json
{"id":20,"result":{"operation_id":"my-op-001","state":"rejected","error":{"code":"conflict","message":"revision 13 is active, not 12"},"conflict":{"base":12,"active":13,"changes":[]}}}
```

committed 表示已提交；`no_change:true` 时 revision 可保持原值。rejected 表示未切换，查看 error、diagnostics、conflict.changes。failed 表示切换失败并尝试恢复旧版本；`degraded:true` 表示恢复不完整，需读取最新状态。SetSecret.apply、ConfigureSubscription、RestoreRevision 也须检查提交结果。

### 重试与历史

operation_id 可省略由服务器生成，但自行生成并保存可以应对响应丢失。合法 ID 为 1–128 个字母、数字、`.`、`_`、`-`，不能是 `.` 或 `..`。

写入断线后，重连 Hello，再调用 `GetOperation {"operation_id":"my-op-001"}`。找不到记录时可用**相同 ID 和原始候选/plan_hash**重试；已记录结果直接返回。同 ID 配不同候选返回 operation_reused。重新读取、修改了候选后应分配新 ID。超时不能证明提交失败。

ListRevisions 返回 active/revisions。历史项包含 revision、base、source、created、文档 SHA-256，和可选 operation、message、restored_from。当前没有读取任意历史文档的独立 API。RestoreRevision 把旧版四份文档提交为**新 revision**，不倒退版本计数：

```json
{"revision":5,"base_revision":13,"operation_id":"restore-5-001"}
```

## 6. 导入与订阅

### ImportSource：只转换本地内容

```json
{
  "import":{
    "source_id":"airport","format":"clash",
    "data":"proxies:\n  - {name: test, type: direct}\n",
    "nodes_only":true,"allow_partial":false
  },
  "reveal":false
}
```

format 接受 auto/clash/links；data 是文件内容，不是路径或 URL。可选 certificate_files 是外部配置引用路径到 PEM 内容的映射。nodes_only 只转换节点；默认完整转换遇到不支持的语义会阻止应用，allow_partial 接受部分转换前应检查报告。

此接口不下载、不写配置。检查 report.can_apply、partial、节点/组/规则计数、bindings、ignored、diagnostics。默认 sources 已遮罩凭据，**第一次导入不能把遮罩当作真实凭据提交**。实际应用把同一原始 import 对象连同 base_revision 交给 Validate/Plan/Commit，在同一事务保存 source 和凭据。

导入不会自动设置系统代理；profile 仍需明确 imports 或引用资源。见[Clash 导入](clash-import.md)和[来源与覆盖](source-overlays.md)。

### ConfigureSubscription / RefreshSubscription

```json
{
  "source_id":"airport","base_revision":13,
  "subscription":{
    "url":"secret://subscriptions/airport/url","format":"auto",
    "interval":3600,"nodes_only":true,"allow_partial":false,"paused":false,
    "headers":[{"name":"User-Agent","value":"Reka"}]
  }
}
```

先用 SetSecret 或 rekactl secret set 保存真实 URL。ConfigureSubscription 保存定义、保留快照；subscription 为 null 仅移除刷新定义。paused 暂停自动检查，但允许手动刷新。interval 单位秒，省略/0 为 3600，显式值为 30–604800。其他可选参数是 `geodata:[{id:"geoip"|"geosite",url:"..."}]`、`certificate_files:[{path:"...",value:"PEM 或 secret://..."}]`、`provider_directory`。API 使用下划线字段，YAML 使用连字符字段。

```json
{"id":30,"method":"RefreshSubscription","params":{"source_id":"airport","wait":true}}
{"id":31,"method":"ListSubscriptions","params":{}}
```

wait 默认为 false，尽快返回当前任务状态；true 等待同 source 的共享任务完成。刷新失败也可通过状态返回，需检查 state/stale/error_code，不能只检查外层 error。

状态含 source_id、state（如 pending/paused/refreshing/current/stale/failed）、stale，以及可选 last_attempt、last_success、next_attempt、error_code、revision、root_hash、fallback_resources，不包含 URL/header 凭据。失败保留之前有效快照。资源限额、下载路由和文件 provider 用法见[订阅文档](subscriptions.md)。

### Surge 模块

`GetCapabilities.source_formats` 包含 `surge-module` 时，可用 `AddModule` 安装 Surge 模块。请求中的 `module` 接受 `id`、`url` 或绝对 `file`、可选的 `enabled`、`interval` 和 `arguments`。`position` 是从零开始的列表索引，省略时追加。安装成功时同一事务保存模块定义和锁定快照。所有模块修改方法都要检查提交结果的 `state`。

`SetModuleArguments` 替换完整的参数覆盖映射。传入空对象可恢复模块默认值。`PreviewModule.data` 接收原始模块文本，使用当前策略表，且不下载资源或写配置。远程 Map Local 和脚本在预览中会提示缺少锁定资源。`GetModuleReport` 返回当前生效模块的逐行转换结果，包含 `scripts` 计数和 `script_items`。`ListModules` 的报告摘要也包含这两个字段。

`script_items` 列出可转换脚本的 `id`、`name`、`type`、`pattern`、`requires_body`、`binary_body_mode`、可选 `max_size`（字节）、`timeout`（秒）、`engine`、`locked` 和锁定时的 `hash`。省略 `max_size` 表示使用平台默认值。`RefreshModule` 的 `wait` 和状态字段沿用订阅刷新结构，以 `module_id` 标识模块。脚本下载失败时，模块状态可附带 `script_errors`，每项包含 URL 的 SHA-256 `request` 和错误 `code`。单个脚本下载失败时，模块的其他条目可以正常生效。 [Surge 模块](modules.md)

## 7. Secret 管理

```json
{"id":40,"method":"SetSecret","params":{"name":"outbounds/hk/password","value":"YOUR_PASSWORD","apply":true}}
{"id":41,"method":"ListSecrets","params":{}}
{"id":42,"method":"DeleteSecret","params":{"name":"outbounds/hk/password"}}
```

配置里使用 `password: secret://outbounds/hk/password`。SetSecret 默认 apply 为 true，保存后重新应用当前配置，返回 name/ref/apply（提交结果）。apply:false 只保存，不立即更新已有实例。apply 失败时 secret 可能已保存，应检查结果后修正配置。

名称最长 256 字符，使用字母、数字、`.`、`_`、`-` 和分段 `/`，不允许空段、`.` 或 `..` 段。ListSecrets 只返回名称；没有读取原值的 API。DeleteSecret 不会重新应用配置，不要直接删除仍被配置引用的值。

### MITM CA

| 方法 | params | result |
| --- | --- | --- |
| `GenerateMITMCA` | 可选 `replace`，默认 `false` | 新建根证书，返回 CA 状态 |
| `ImportMITMCA` | `pkcs12`、`password`，可选 `replace`，默认 `false` | 导入根证书，返回 CA 状态 |
| `GetMITMCA` | 无 | 当前 CA 状态 |
| `ExportMITMCA` | 可选 `format`，默认 `pem`，也可传 `der` | `format`、`data`、`fingerprint_sha256` |
| `DeleteMITMCA` | 无 | `{"deleted":true}` |

未安装时，CA 状态只有 `{"installed":false}`。已安装时返回 `installed`、`ref`、`subject`（证书通用名称）、`fingerprint_sha256`、`serial_number`、`key_type`、`not_before`、`not_after` 和 `expired`。

`pkcs12` 使用标准 base64 编码，允许首尾空白和换行。已有 CA 时，生成或导入需显式传 `replace:true`，否则返回 `conflict`。未安装时，导出和删除返回 `not_found`。导出的 `data` 在 `pem` 格式下是证书文本，在 `der` 格式下是 DER 证书的 base64。所有回复都不包含 CA 私钥。

`secret://mitm/ca` 是 `local.yaml` 的 `mitm.ca` 专用引用。`SetSecret` 和 `DeleteSecret` 拒绝 `mitm/` 下的名称。`ListSecrets` 仍可列出名称。生成、导入或删除后，重新应用配置以使 TCP 转发载入最新的 CA 状态。

<a id="mitm-status"></a>

### MITM 状态

`GetMITMStatus` 返回 `enabled`、`ca_loaded`、可选 `ca_error`、`h2`、`hostname_count`、`pinning_bypasses`、`connections_total` 和 `requests_total`。`enabled` 表示本机配置中的开关，`ca_loaded` 表示活动配置拥有可用的 CA。CA 状态随配置激活更新。

`h2` 在配置启用 HTTP/2 时为 `"not supported yet"`，省略该开关或设为 `false` 时为 `"disabled"`。MITM 只协商 HTTP/1.1。

`pinning_bypasses` 的每项包含 `hostname`、`reason`、`expires_at`。列表跨配置代际生效，按主机名记录，保留至多 256 项。`connections_total` 从进入 MITM 转发时开始计数，包含后续握手失败的连接。`requests_total` 统计已解析的请求，包含本地响应。两个计数均从本次内核运行开始累计。

## 8. 事件订阅与恢复

```json
{"id":50,"method":"Subscribe","params":{"types":["config.committed","subscription.updated"],"epoch":"9f2c123456789abc","after":41}}
```

types 省略/空数组接收全部事件；同连接再次 Subscribe 替换上次订阅。epoch/after 均可省略。

| type | 含义 |
| --- | --- |
| `snapshot` | 当前快照，data 包含 status/revision |
| `config.committed` | 配置已提交，data 含 revision、operation、source、generation、plan |
| `config.rejected` | 配置被拒绝，携带提交结果 |
| `runtime.generation` | 运行时切换 |
| `candidate.invalid` | 手工编辑候选失败 |
| `subscription.updated` | 订阅观察状态更新 |
| `module.updated` | 模块刷新状态更新 |
| `traffic_budget.updated` | 订阅用量观测更新后的预算 |
| `log` | 实际启用的日志记录，data 含 level、message、time |

```json
{"event":{"epoch":"9f2c123456789abc","seq":42,"type":"config.committed","time":"2026-11-16T08:00:00Z","data":{"operation":"my-op-001","revision":13,"generation":20,"source":"api","plan":{}}}}
```

seq 在一个 epoch 内递增。服务器保留最近 512 条事件；游标可用时重放 after 之后的事件，进程重启或游标不可用时先发 snapshot。snapshot 不受 types 过滤。

单订阅队列最多 256 条；慢客户端可能丢事件，下一条成功投递事件带 dropped 数量。收到 dropped>0 或 epoch 变化时重新读取配置/运行时并重建缓存。过滤后 seq 不连续属正常情况，不能只凭缺号判断丢包。

断线后新建连接、Hello、用最后已处理的 epoch/seq 再次 Subscribe；收到 snapshot 以快照为准。GUI 不要用事件直接覆盖用户尚未保存的编辑。

## 9. 错误速查

需要检查两层：**外层 error** 是请求/服务错误；**result.state/result.error** 是事务结果。

| code | 处理 |
| --- | --- |
| `hello_required` | 当前连接先发 Hello |
| `unsupported_version` | 客户端与服务器没有共同版本 |
| `unknown_method` | 查看 GetCapabilities.methods，核对大小写 |
| `bad_request` | 检查参数、patch 路径、操作 ID |
| `invalid` | 配置不能编译，查看 diagnostics |
| `conflict` | 读取最新文档、合并修改、用新操作 ID |
| `plan_changed` | 候选与计划 hash 不符，重新规划 |
| `prepare_failed` | 新实例/端口准备失败，旧配置继续运行 |
| `blocked` | 排空实例过多、任务忙等，查看具体原因 |
| `activate_failed` | 检查恢复结果、degraded、GetStatus |
| `operation_reused` | 同操作 ID 配不同候选，不能盲目重试 |
| `not_found` | 操作、历史版本、secret 或订阅不存在 |
| `internal` | 内部/I/O 错误；写入后先协调 operation 状态 |

身份校验失败可能直接断开连接，没有 JSON 错误。超时/EOF 不能证明写入失败，按操作 ID 查询结果。

## 10. 测速、流量、规则、DNS、日志和资源上传

客户端可通过 `GetCapabilities.methods` 查询内核提供的方法。调用前先执行 `Hello`。

### 连接时间线、临时规则和节点擂台

```sh
./bin/rekactl timeline
./bin/rekactl timeline 42
./bin/rekactl temp-rule add -ttl 15m 'DOMAIN-SUFFIX,example.com,direct'
./bin/rekactl temp-rule list
./bin/rekactl temp-rule remove temp-1
./bin/rekactl arena -rounds 3 hk jp sg
./bin/rekactl scene
./bin/rekactl budget
```

时间线以连接 ID 关联已有 DNS 和 HTTP 摘要，并显示接收、嗅探、路由、拨号和结束的时间。可查询正在转发的连接及当前历史缓冲区保留的已结束连接。保存历史 ID 的客户端可附带对应 `epoch`。

临时规则接受 Clash 单行条件和原生出站或组 ID。规则模式按最近添加优先，然后进入保存的规则。有效期默认 5 分钟，范围 1 秒到 24 小时。到期、移除或切换配置档后，后续连接按生效规则重新判定。已有连接继续使用建立时的路由。

擂台固定一份配置快照，比较 2 到 16 个节点或策略组。每个候选默认跑 3 轮，最多 5 轮，每轮最多 4 项并行，全场限时 30 秒。排名依次按成功次数、中位延迟和极差，结果供选择节点时参考。

场景定义和预算示例见[配置字段手册](configuration-reference.md#101-网络场景)。

### ProbeOutbound

```json
{"outbound":"proxy","url":"https://www.gstatic.com/generate_204","timeout_ms":5000}
```

outbound 必须是现有原生节点/组 ID；返回 `outbound`、实际 `resolved_outbound`、`delay_ms` 和 `status_code`。URL 仅 HTTP(S)，不得含 userinfo，最长 8192 字符。超时省略/0 为 5000 ms，允许 100–30000 ms；最多 16 个并发探测槽。探测经指定出站真实联网，不修改持久选择、不推进轮询；不跟随跳转，200–399 视为成功，最多读取 4096 字节正文。参数错误、不可用节点、HTTP 失败等当前可返回外层 `internal`，应结合 message 处理，不能仅凭 error code 分类为内核故障。

### GetTraffic / GetRules

GetTraffic 返回累计用户流量（字节），包括已关闭连接：

```json
{"upload_total":1234,"download_total":5678,"sampled_at":"2026-11-16T08:00:00Z","epoch":"example-epoch"}
```

计算速率时使用同 epoch 的两次采样差值；进程重启后重新建立基线。它与当前连接列表中仍活跃流的计数不同。

GetRules 参数为 `{offset:0,limit:100}`；负 offset 当作 0，limit 省略/≤0/>1000 时为 100。结果含 `generation`、`revision`、`mode`、`total`、`rules`，每条含 `index`（零起）、可选 `id`、`type`、`payload`、`outbound`、`description`。它查询**活动路由器**，global/direct 模式不能用来重建原始 rules；原配置仍从 GetConfiguration 读取。

### QueryDNS / FlushDNSCache / ResetNetwork

```json
{"name":"example.com","type":"A","scope":"normal","fake":false}
```

type 默认 A，支持 DNS 类型名；scope 默认 normal，可选 proxy/direct/bootstrap；查询最多 10 秒。结果 `rcode` 是 DNS 状态码，`answer`、`authority`、`extra` 为 RR 文本字符串数组；应同时检查 rcode，空答案也可能是成功查询。需要活动 DNS 服务，未配置原生 DNS 时应先提交 DNS 配置。

`fake` 默认 false；显式 true 才允许使用配置的 Fake IP 分配行为，实际仍取决于作用域、增强模式和过滤规则。FlushDNSCache 返回 `{cleared:数量}`，清普通作用域缓存并阻止旧后台刷新重新写回，保留 Fake IP 映射及已有流。ResetNetwork 也返回 cleared，另外关闭空闲 DNS/出站连接；它不切换 network.mode，不安装系统路由，也不保证重建已有 TCP 会话。

### GetLogs

参数 `{limit:100}`；允许 1–256，其他值回到 100。返回 `{events:[...]}`，按时间从旧到新排列，读取与事件重放共用的有界历史，可能不足请求数量。每条是完整事件信封，type 为 log，data 含 level、message、time；仅收集配置日志级别实际启用的记录。实时日志用 `Subscribe {types:["log"]}`，继续按 epoch/seq/dropped 处理恢复，不是独立文件日志下载。

```sh
python3 examples/control_client.py --socket "$PWD/.reka-demo/control.sock" GetTraffic
python3 examples/control_client.py --socket "$PWD/.reka-demo/control.sock" GetRules '{"offset":0,"limit":100}'
python3 examples/control_client.py --socket "$PWD/.reka-demo/control.sock" GetLogs '{"limit":20}'
python3 examples/control_client.py --socket "$PWD/.reka-demo/control.sock" --watch Subscribe '{"types":["log"]}'
```

### StageResource 与本地 provider / 地理库

先把本地字节上传到内核的不可变资源存储，再通过 SHA-256 引用；服务不读取客户端任意文件路径。

```json
{"hash":"替换为完整小写SHA256","size":3,"offset":0,"data":"YWJj"}
```

data 为 Base64（示例内容 abc），hash 是**解码后完整资源**的摘要；size/offset/received 均以解码字节计。单资源最多 16 MiB，每块最多 1 MiB，按连续 offset 上传，完全相同的重复块可重试。最多 4 个未完成上传，闲置超过 2 分钟后在后续上传时清理；过期请求从 offset 0 重来。结束时核对 SHA-256，返回 ready:true 才能引用；重传已存在资源返回完整 received 和 ready:true。上传不激活配置。

下面的客户端示例上传一个本地 provider 文件；替换路径后运行：

```python
import base64
import hashlib
import sys
from pathlib import Path
sys.path.insert(0, "examples")
from control_client import Client

data = Path("/path/to/provider.yaml").read_bytes()
if not data or len(data) > 16 * 1024 * 1024:
    raise ValueError("provider size must be 1 byte through 16 MiB")
digest = hashlib.sha256(data).hexdigest()
with Client(".reka-demo/control.sock") as c:
    for offset in range(0, len(data), 1024 * 1024):
        result = c.call("StageResource", {
            "hash": digest, "size": len(data), "offset": offset,
            "data": base64.b64encode(data[offset:offset + 1024 * 1024]).decode(),
        })
    if not result["ready"]:
        raise RuntimeError(result)
print(digest)
```

随后 ImportSource 或 change.import 可附加 `provider_resources: {"proxy-providers/pool":"完整SHA256","rule-providers/sites":"完整SHA256"}` 和 `geodata_resources: {"geoip":"完整SHA256","geosite":"完整SHA256"}`。键需与原始 Clash 文档声明的 provider 精确对应；优先用带种类的名称避免歧义。最多 1024 个 provider 映射、2 个地理库映射，去重后的输入资源总计最多 32 MiB；缺失/损坏字节会拒绝导入。先预览报告，再按原有 Validate→Plan→Commit 流程激活。

本文以 [handler.go](../internal/control/handler.go)、[协议与 wire types](../internal/api/) 和配置服务实现为依据。v1 会继续增加可选字段；客户端应允许响应中的未知字段，并通过 GetCapabilities 判断具体能力。

### 独立远程规则集与地理库

`InstallManagedResource` 接收 `base_revision`、`kind`（`rule-set` 或 `geodata`）、`id`、`url`、`format`、`interval` 和 `automatic`。规则集还需要 `behavior`。接口先下载首个版本并校验，再把锁定的摘要和更新设置写入当前档案。返回普通配置提交结果。

`ListManagedResources` 返回不含 URL 的更新状态。`RefreshManagedResource` 使用 `{kind, id, wait}`。设 `wait: true` 可等待本次结果，失败时状态为 `stale`，已有版本继续运行。`resource.updated` 事件使用同一状态结构。 [独立远程资源](rule-resources.md#independent-remote-resources)

### 托管脚本

这两个接口也接受 profile 中含 `hash` 及 `download` 或 `file` 的 `script` 资源。首次配置脚本时通过 `StageResource` 入库源码，再提交脚本定义。设置 `download.automatic: true` 可定期检查远程源码，`file` 资源由显式刷新更新。 [脚本配置](configuration-reference.md#脚本-scripts)

Clash 兼容面板可使用[独立的本地 HTTP 接口](clash-api.md)。
