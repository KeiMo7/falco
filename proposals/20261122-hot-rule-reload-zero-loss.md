# 规则热更新零丢事件设计（Hot Rule Reload without Event Loss）

日期：2026-11-22
状态：待评审（运维侧需求，第二轮讨论稿）

## 1. 背景与问题

当前规则变更通过 SIGHUP 触发**全量重启**：`g_restart_signal` 置位后，各事件源线程退出
`inspector->next()` 循环（`app/actions/process_events.cpp:216`），主循环按 `app/app.cpp:63`
的整条 `run_steps` 流水线重新执行——新建 `falco_engine`、重新加载规则、重开 inspector、
重开输出。生产环境 600+ 规则实测该窗口约 800ms，期间采集停止，窗口内事件无法保证被处理。

目标：规则切换过程中事件不丢、不重复告警、语义确定，且失败可回退、版本可追溯。

### 1.1 现状代码中已确认的关键事实

| 事实 | 位置 | 对设计的影响 |
|---|---|---|
| SIGHUP = 进程内全量重跑流水线，非增量更新 | `falco.cpp:67`、`app/app.cpp:55` | 800ms 主要耗在重建，而非切换动作本身 |
| `falco_engine::process_event()` 仅在「每个调用方固定使用不同 source_idx」前提下线程安全；`filter_ruleset::run()` 对规则集**原地变更不具备线程安全性** | `engine/falco_engine.h:248-261`、`falco_engine.cpp:378` | 排除「原地改规则集」方案，必须做不可变快照 |
| `app::state` 以 `shared_ptr<falco_engine>` 持有引擎 | `app/state.h:96` | 原子换指针是天然的发布点 |
| 规则加载已是 reader→collector→compiler→`load_rules()`→enable→`complete_rule_loading()` 的独立流水线，且已有独立的 `validate_rules_files` 动作 | `app/actions/load_rules_files.cpp`、`engine/rule_loader*` | 新引擎可完整复用同一套解析/编译/匹配代码，无需另写 |
| 输出在入队前已完成全部渲染（`format_event` + 字段提取），入队的是自包含 `ctrl_msg`；输出队列本身就是 TBB `concurrent_bounded_queue`，有界且有丢弃计数 | `falco_outputs.cpp:124-166`、`falco_outputs.h:122-126` | 规则删除不可能吞掉已命中的告警；事件缓冲可复用同一队列原语，不新增依赖 |
| `restart_handler` 已具备「先 dry-run 校验、再触发重启」的防抖与校验骨架，`reload_state` 已有 generation 计数（requested/covered/applied/rejected） | `app/restart_handler.cpp`、`app/reload_state.h` | 热更新协调器可挂接现有机制，而非另起炉灶 |
| 事件具备源内唯一编号 `ev->get_num()` 与时间戳 `ev->get_ts()` | `process_events.cpp:384` | 可构造事件唯一键，用于去重验收与版本追溯 |
| 已存在规则文件 sha256 记录 `m_loaded_rules_filenames_sha256sum` | `load_rules_files.cpp:86` | 版本指纹直接复用 |
| inspector 打开时按 `sc_codes_for_ruleset()` 计算的 syscall 集合配置内核采集掩码 | `configure_interesting_sets.cpp:277`、`helpers_inspector.cpp:199` | 新规则引用新 syscall 的处理需要专门设计（见 §9） |

## 2. 总体架构

两个核心机制：

1. **不可变规则快照 + 原子指针发布（RCU 风格）**：新版本规则在后台编译进一个**全新的
   `falco_engine` 实例**，全程不碰正在服务的引擎；编译校验通过后，以一次指针原子存储完成
   发布。匹配线程每次处理事件时读取一次快照指针，整个匹配过程持有该 `shared_ptr`，旧引擎
   在所有在途匹配结束后自动释放。
2. **采集与匹配解耦的有界队列流水线**：每个事件源拆成 collector（仅负责 `next()` 取事件并入队）
   与 matcher（出队、取快照、匹配、送输出）两个线程。切换期间 collector 不停止，事件进入
   有界缓冲；matcher 始终有一个完整可用的快照，不存在「无规则可用」的瞬间。

```
                 内核 ring buffer
                       │ inspector->next()
        ┌──────────────▼──────────────┐
        │ collector 线程（每源一个）     │  切换期间不停止
        └──────────────┬──────────────┘
                       │ 深拷贝事件 → 有界队列（条数+字节双上界，TBB）
        ┌──────────────▼──────────────┐
        │ matcher 线程（每源一个）       │
        │   每事件读取一次快照指针        │◄──── snapshot_holder（原子 shared_ptr）
        │   engine->process_event()    │            ▲
        └──────────────┬──────────────┘            │ 一次性原子发布
                       │ rule_result               │
                       ▼                    ┌───────┴────────┐
              falco_outputs 有界队列         │ hot_reload_     │
              （现有，不改语义）             │ coordinator 线程 │
                                            │ 后台编译新引擎   │
                                            └────────────────┘
```

硬约束对应关系：

- **复用解析与匹配逻辑**：coordinator 调用从 `load_rules_files` 动作中抽出的同一套加载函数，
  对新引擎实例执行；匹配仍走原 `falco_engine::process_event()`，不新增第二套实现。
- **缓冲有上界**：队列同时配置条数上限与字节预算；工作项持有事件深拷贝，内存可精确计量。
- **切换不阻塞采集超过阈值**：编译在后台线程，发布是一次指针存储；collector 永不参与编译。
  仅有「队列满且队头为不可驱逐事件」时 collector 才阻塞，阻塞时长有直方图指标与配置阈值。
- **不新增依赖**：队列使用已在用的 TBB `concurrent_bounded_queue`；原子指针使用 C++17 标准库。
- **默认行为不变**：`hot_reload.enabled` 默认 `false`，关闭时线程模型与当前完全一致，
  SIGHUP 仍走全量重启；热更新是独立能力。

## 3. 关键语义（逐条固定，不再留歧义）

### 3.1 切换瞬间正在匹配的事件：按匹配开始时绑定的快照判完

matcher 在处理一个事件**开始时**读取一次 `snapshot_holder`，取得不可变快照的 `shared_ptr`，
整个 `process_event()` 调用期间不再重读。因此：

- 一个事件的全部规则判定（含 `rule_matching: ALL` 下的多规则命中）自始至终基于同一版本；
- 不可能出现「一半旧规则一半新规则」；
- 每个源的 matcher 单线程串行，切换边界是一条精确的**事件号水位线 W**：
  `event_num ≤ W` 全部按旧版本判定，`> W` 全部按新版本判定，水位线随切换指标一并记录。

### 3.2 切换前缓冲的事件：按「匹配时刻」的快照判，且只判一次

缓冲只是传输环节，事件在被匹配之前没有任何判定结论。因此队列中积压、在指针翻转之后才被
matcher 取到的事件，按**新版本**判定，每个事件恰好匹配一次，不做「先按旧规则补判、再按
新规则判」。明确拒绝「入队时钉住旧版本」的替代方案——那会要求工作项保活旧引擎、拖慢旧
版本回收，并使双版本共存期不可控。

### 3.3 规则删除：在途告警不丢

两层保证：

1. 旧快照被 matcher 持有的 `shared_ptr` 保活，在途匹配所引用的 `falco_rule`、filter、
   formatter 对象不会析构；
2. 一旦命中，`falco_outputs::handle_event()` 在**入队前同步完成全部消息渲染与字段提取**
   （`falco_outputs.cpp:137-162`），进入输出队列的 `ctrl_msg` 是自包含的，此后规则删除
   与该告警的投递完全无关。输出队列及其投递逻辑本次不改变语义。

### 3.4 加载失败：候选整体丢弃，线上指针不动

新规则在**独立的候选引擎实例**上编译。语法错误、未知字段、插件版本不满足等任何失败，
候选引擎直接析构，活动快照指针不发生任何写入，旧版本继续服务。失败信息通过现有
`falco::load_result::as_string()` 取得（含文件与行列位置），记录日志、递增
`rejected_generation` 计数并在 healthz 暴露。由于发布是单指针操作、候选与活动引擎是两个
对象，「半套规则上线」在结构上不可能发生——不存在部分应用的中间状态。

### 3.5 进程在切换中被杀：重启后恢复到某个完整版本

见 §7 的暂存目录 + 清单 + 原子 rename 机制。

## 4. 详细设计

### 4.1 规则快照与持有者

```cpp
// app/rule_snapshot.h（新增）
struct rule_snapshot {
    uint64_t generation;                    // 进程内单调递增
    std::string version_id;                 // "gen-<n>-<sha256前12位>"
    std::map<std::string, std::string> file_sha256;  // 复用现有 sha256 计算
    uint64_t rule_count;
    libsinsp::events::set<ppm_sc_code> required_sc; // 本版本需要的 syscall 集合
    std::shared_ptr<falco_engine> engine;   // 完整、已 complete_rule_loading 的引擎
    // 事件类型 → 该类型可命中规则的最高优先级，用于缓冲驱逐分级
    std::unordered_map<uint16_t, falco_common::priority_type> evt_severity;
};

class snapshot_holder {
public:
    std::shared_ptr<const rule_snapshot> get() const;        // 匹配线程每事件调用一次
    void publish(std::shared_ptr<const rule_snapshot> next); // 仅 coordinator 调用
private:
    // C++17：以 free-function atomic_load/atomic_store 封装，隔离弃用告警
    std::shared_ptr<const rule_snapshot> m_current;
};
```

旧快照的释放时机：matcher 每轮循环末尾释放上一轮持有的 `shared_ptr`；没有任何匹配线程
引用后引用计数归零析构。coordinator 保留最近 N 个历史版本的元数据（不含引擎对象）用于
指标与审计，N 由 `keep_generations` 配置。

### 4.2 热更新协调器（后台线程）

`app/hot_reload_coordinator.*`（新增），触发源复用现有 `restart_handler`（SIGHUP /
inotify / 未来的 HTTP `/-/reload`）。一次更新的状态机：

1. **请求合并**：编译进行中收到的新请求只记 generation 不打断，当前编译结束后若发现
   文件已再次变化则立刻开始下一轮（复用 `reload_state` 的 requested/covered 计数）。
2. **读取与校验**：按 `m_rules_filenames` 读取全部文件，构造**候选引擎**：复用抽出的
   `load_rules_into_engine()`（由现有 `load_rules_files` 动作重构而来，逻辑不变）、
   插件需求检查、rule selection、`complete_rule_loading()`。任一步失败 → §3.4。
3. **采集掩码预检（见 §9）**：候选 `required_sc` 若超出当前已采集集合的并集，本版本
   直接拒绝并给出「需完整重启生效」的明确错误，而不是静默漏采。
4. **持久化暂存（见 §7）**：写暂存 bundle 与清单，fsync 后原子 rename。
5. **发布**：`holder.publish(candidate)`——单次原子指针存储。记录水位线 W（向各源
   matcher 查询当前已匹配到的 event_num 最大值）与发布时刻。
6. **指标落盘**：切换耗时、窗口事件数、队列水位、丢弃/阻塞计数写入 metrics。

SIGHUP 语义随开关变化：`hot_reload.enabled=true` 时 SIGHUP 请求 coordinator；
为 `false` 时保持现有全量重启行为不变。

### 4.3 采集/匹配拆分与有界缓冲

`process_events.cpp` 中的 `do_inspect()` 在热更新开启时拆为两个角色（关闭时维持原样）：

- **collector**：`inspector->next()` 成功后，将事件**深拷贝**为自持有工作项入队。
  scap 事件指针仅在下次 `next()` 前有效，队列项不能持裸引用；深拷贝通过 libsinsp 现有
  的事件复制/转储机制实现（与 capture/replay 同源的能力），封装在 `owned_event` 接口后，
  具体原语在实现期选型并由单测覆盖。
- **matcher**：出队 → `holder.get()` 取快照 → `engine->process_event()` → 结果送
  `s.outputs->handle_event()`（输出链路不改）。每事件读取一次快照，保证 §3.1。

队列与溢出策略（配置见 §8）：

- **双上界**：`capacity_events` 条数 + `capacity_bytes_mb` 字节，任一触顶即视为满。
- **事件分级**：
  - *状态关键事件*（属于 `sinsp_state_sc_set()`，即 libsinsp 状态机维护所依赖的
    clone/exec/exit 等，`app.cpp:33-39` 已引用同一集合）：**不可驱逐**，队列满时
    collector 阻塞等待，阻塞耗时计入直方图；
  - 其余 syscall 事件：按活动快照预计算的 `evt_severity` 分级，溢出时从队中驱逐
    优先级最低者并计数；
  - 插件源事件不可驱逐（无状态机分级依据），满则阻塞。
- **禁止静默丢弃**：每次驱逐递增按原因分类的计数器（`hotreload_buffer_evicted_total{
  reason="priority_eviction"}` 等），并经现有内部消息机制发出限速告警。
- 稳态下队列应接近为空（matcher 跟得上 collector）；缓冲是切换窗口与匹配抖动的安全垫，
  不是稳态堆积区，队列水位本身是关键监控指标。

端到端反压链：内核 ring buffer（有 drop 统计）→ 本设计新增的有界事件队列（有驱逐/阻塞
统计）→ 现有 TBB 输出队列（有 `m_outputs_queue_num_drops`）。三层全部有界、全部计数，
无静默丢点。

### 4.4 并发正确性小结

| 风险 | 对策 |
|---|---|
| 匹配线程读到半新半旧规则集 | 引擎不可变 + 每事件单次取快照指针；规则集从不在活动对象上原地修改 |
| 旧引擎正在用时被析构 | `shared_ptr` 保活，匹配结束才释放 |
| 同一事件被两个版本各判一次 | 每源单 matcher 串行 + FIFO + 每事件恰好一次 `process_event()` 调用 |
| 多源并发 | 现有引擎契约即「不同 source_idx 可并发」，快照内各源 ruleset 仍由各自专属 matcher 访问，契约不变 |
| coordinator 与 matcher 竞争 | 两者只通过原子指针与只读快照交互，无共享可变状态 |

## 5. 版本可追溯

- **版本标识**：`version_id = "gen-<单调序号>-<规则内容 sha256 前12位>"`，内容指纹复用
  `m_loaded_rules_filenames_sha256sum` 的逐文件 sha256 再聚合。
- **写入告警记录**：`rule_result` 在 app 层包装时盖版本号与事件唯一键，
  `falco_outputs::handle_event()` 签名增加版本参数（带默认值，不破坏其他调用方）：
  - JSON 输出新增 `ruleset_version` 与 `event_id` 两个顶层字段；
  - 文本输出在消息尾部追加 `ruleset_version=...`；
  - gRPC/HTTP/file/syslog 各通道随消息持久化，不落进程内存。
- **事件唯一键**：`(source, ev->get_num(), ev->get_ts())`；告警去重键再加 rule 维度：
  `(source, event_num, ts, rule_name)`（`rule_matching: ALL` 下一个事件合法命中多条规则，
  去重检查必须按「事件×规则」而非按告警文本）。
- **审计面**：healthz/metrics 暴露 current、previous、last_rejected 三个 generation 及其
  指纹、切换时间、失败原因与位置；误报排查时凭告警里的 `ruleset_version` 即可回溯到
  对应清单（§7）与全部规则文件内容哈希。

## 6. 失败与降级行为汇总

| 场景 | 行为 |
|---|---|
| 新规则语法/字段/插件依赖错误 | 候选析构，旧版本继续跑；日志含文件+行列+原因；`rejected_generation` 计数；healthz 可见 |
| 缓冲溢出且队头可驱逐 | 驱逐最低优先级事件，按原因计数 + 限速告警，不静默 |
| 缓冲溢出且全为不可驱逐事件 | collector 阻塞，阻塞时长超 `max_collector_block_ms` 触发告警指标；不丢弃状态关键事件（丢弃会污染 sinsp 状态机，后果比背压更严重） |
| 切换中进程被杀 | 重启加载 active 清单指向的完整 bundle；active 损坏则回退 LKG；再失败则 fail-closed 拒绝启动并报错（不允许带半套规则运行） |
| 新规则需要当前未采集的 syscall | 拒绝该版本并明确提示需完整重启（§9） |
| 输出队列满 | 沿用现有 `m_outputs_queue_num_drops` 行为，纳入验收对账 |

## 7. 磁盘状态与崩溃恢复

状态目录（默认 `/var/lib/falco/rulesets/`，可配置）：

```
rulesets/
  manifest.json                 # 原子写；指向 active 与 lkg 的 bundle id
  bundles/
    gen-42-a1b2c3d4e5f6/
      rules/...                 # 该版本规则文件完整副本
      manifest.json             # 逐文件 sha256、规则数、创建时间、状态
```

发布流程：先写 `bundles/gen-N/`（新目录、临时文件名），fsync 目录项后更新
`manifest.json` 临时文件并 `rename(2)` 原子替换；active 指针只在内存指针发布成功后才
切换。因此磁盘上任何时刻只有「完整 bundle」或「完整的上一版 manifest」两种状态，不存在
半个 bundle 被引用的可能。启动时校验 active bundle 的 sha256 与清单，失败自动降级 LKG，
两次都失败则拒绝启动。保留 bundle 数量由 `keep_generations` 限制（默认 2）。

## 8. 配置项（默认关闭）

```yaml
hot_reload:
  enabled: false
  event_buffer:
    capacity_events: 4096        # 每源队列条数上界
    capacity_bytes_mb: 64        # 每源队列字节预算上界
    max_collector_block_ms: 50   # 采集阻塞阈值告警线
  state_dir: /var/lib/falco/rulesets
  keep_generations: 2
```

新增指标（接入现有 `falco_metrics`/stats 框架）：当前 generation、上次切换耗时直方图、
队列水位、驱逐计数（按原因）、collector 阻塞时长直方图、rejected 计数（带原因标签）。

## 9. 采集掩码（interesting sets）问题与取舍

规则只决定「怎么判」，inspector 打开时的 syscall 采集掩码决定「能不能看到」。新规则若
引用了当前掩码外的 syscall，即使热切换成功也收不到对应事件。本设计分两期：

- **v1（本次交付）**：采集集合取「活动版本 ∪ 已暂存候选版本」所需 syscall 的并集，
  coordinator 在编译期即可由 `sc_codes_for_ruleset()` 算出候选集合（与
  `configure_interesting_sets.cpp:277` 同一 API）。代价是少量额外事件量，换来零漏采、
  无需驱动侧热更新能力。若候选规则需要并集之外的 syscall，则拒绝该次热更新并明确返回
  「需完整重启」，不允许静默生效成一条永远不会命中的规则。
- **v2（后续）**：评估 libsinsp/驱动的运行时掩码刷新接口，在 modern eBPF/kmod 上支持
  采集集合的在线收敛与扩展。当前工作区 libs 子模块未初始化，无法核实具体 API，不在本次
  承诺范围内。

## 10. 改动清单

| 文件 | 改动 |
|---|---|
| `app/rule_snapshot.h/.cpp`（新增） | `rule_snapshot`、`snapshot_holder` |
| `app/hot_reload_coordinator.*`（新增） | 后台编译、校验、暂存、发布状态机 |
| `app/actions/load_rules_files.cpp` | 抽出可对指定引擎实例复用的加载函数，原动作改为薄封装 |
| `app/actions/process_events.cpp` | 开关开启时 collector/matcher 拆分；水位线与窗口计数；版本盖戳 |
| `app/restart_handler.cpp`、`app/reload_state.*` | 开关开启时 SIGHUP 路由到 coordinator；补充 applied generation、水位线、丢弃/阻塞计数 |
| `falco_outputs.*` | `handle_event` 增加版本/事件 ID 参数（默认值保持兼容），JSON/文本输出带 `ruleset_version`、`event_id` |
| `configuration.*`、config JSON schema | `hot_reload` 配置段 |
| 启动流程 | active/LKG bundle 校验与恢复 |
| `unit_tests/`、`e2e_tests/` | §11 全部用例 |

引擎侧（`engine/`）业务逻辑零改动：不修改 `process_event()` 语义、不引入第二套规则解析。

## 11. 验收方案

### 11.1 指标定义（先对齐口径）

- **切换发布耗时**：`holder.publish()` 单次原子存储耗时，预期微秒级——这才是真正的
  「切换窗口」；汇报 P50/P99。
- **整次热更新耗时**：请求→编译→校验→发布的端到端时延（含原 800ms 量级的编译），
  在后台线程发生、不阻塞采集，单独汇报，不与切换窗口混淆。
- **切换窗口内事件数**：以水位线 W 为界，统计发布前后各 matcher 实际处理的事件数，
  并与驱动侧 `scap_stats.n_evts` 在同一时段的增量**对账相等**。

### 11.2 确定性回放测试（语义正确性）

固定 scap 抓包（含提权类事件），三种跑法对比：

1. 全程钉住旧版本；
2. 全程钉住新版本；
3. 在指定事件号触发热切换。

要求：跑法 3 的逐事件判定表 = 按水位线 W 对跑法 1/2 结果的分段拼接，逐条事件一致；
窗口内丢弃数 = 0、重复告警数 = 0。

### 11.3 压测与统计指标

生产级 EPS 下持续注入事件，执行 ≥1000 次热更新循环：

- 发布耗时 P50、P99；
- 每轮窗口事件数与驱动 `n_evts` 增量对账；
- 丢弃数为 0（无溢出前提下）、重复告警数为 0；
- collector 阻塞时长 P99 不超过 `max_collector_block_ms`；
- 队列稳态水位接近 0，峰值有界且符合字节预算。

### 11.4 重复告警的专门检查方法

不比较告警文本，从 JSON 输出提取 `(source, event_id, rule_name)` 键：

```bash
jq -c '[.source, .event_id, .rule] | @tsv' alerts.jsonl \
  | sort | uniq -d | wc -l        # 必须为 0
wc -l < alerts.jsonl               # 总行数
jq -c '[.source, .event_id, .rule] | @tsv' alerts.jsonl \
  | sort -u | wc -l                # 去重后行数，两者必须相等
```

### 11.5 故障注入

- 语法错误 / 引用不存在字段 / 插件版本不满足：版本被拒，旧版本持续命中，healthz 与
  日志含失败位置；
- 暂存后、发布前 `kill -9`：重启后恢复到 active 完整版本；手动破坏 active bundle：
  回退 LKG；两者皆坏：拒绝启动；
- 缓冲溢出注入（压低容量上限 + 突发流量）：验证低优先级驱逐计数、状态关键事件不被
  驱逐、阻塞指标与限速告警；
- 规则删除场景：删除一条正处于输出链路中的规则，确认已渲染告警全部投递成功。

### 11.6 一次真实热更新记录的交付格式

| 字段 | 示例 |
|---|---|
| 旧/新 version_id | gen-41-8f31a2c90d7b → gen-42-a1b2c3d4e5f6 |
| 发布耗时 P50 / P99（1000 次循环） | 12µs / 31µs |
| 端到端编译耗时（后台，不阻塞采集） | 783ms |
| 窗口内事件数 / 驱动 n_evts 增量 | 137 / 137 |
| 丢弃数 / 重复告警数 | 0 / 0（含 §11.4 去重命令输出） |
| 水位线 W（各源） | syscall: 902144 |
| 切换前后同批事件判定对比 | 附 §11.2 逐事件比对结果 |
| 告警样例 | 含 `ruleset_version=gen-42-...` 与 `event_id` 字段 |

## 12. 已知取舍与风险

1. **事件深拷贝开销**：拆分流水线后队列项持有事件副本，稳态存在拷贝成本。验收 §11.3
   量化该开销；若不可接受，v2 与仓库内 `20251205-multi-thread-falco-design.md` 的
   驱动侧 ring buffer 分区方案合流，消除拷贝。
2. **规则匹配统计连续性**：`stats_manager` 随引擎实例化，新版本计数从 0 开始；切换时
   旧版本计数做一次快照进 metrics，历史可查但不跨版本累加。
3. **采集掩码并集的冗余事件**：见 §9，v1 以有限冗余换零漏采，v2 再做动态收敛。
4. **输出跨线程时序**：与现有多源架构相同，不保证跨源告警严格时序，安全监控场景可接受
   （与多线程设计提案结论一致）。
