# CyREN 升级方案（FYP2）

> 状态：设计定稿，开始实施。
> 分支：所有升级工作在 `feat/upgrade` 上；`main` 冻结为可跑 baseline，
> 标签 `baseline-pre-upgrade` 指向升级前的最后一个 commit（`f27ce0d`），随时可切回。
> 铁律：**所有攻击必须由真实工具产生真实流量，绝不凭空造假数据。**

## 目标

1. **Part A —— 真实攻击多样性**：现在攻击 pattern 太单一（6 攻击 / 3 IP / 背靠背）。
   引入 Metasploit 真实 exploit、同类攻击多工具变体、更多攻击者 IP、可控时间间隔的
   多阶段攻击链。
2. **Part B —— Investigation 升级为 agent，但不烧 token**：把线性两步的
   Investigation 升级成能自主调用工具、循环推理、主动威胁狩猎的 agent；用
   **三档设计**（baseline / react-lite / react-full）把"agent 化"和"每步都调 LLM"
   解耦，证明 agent 化不必然更贵；三档可在同一批事件上对比，供论文使用。

## 总原则

- **真实流量**：sqlmap/hydra/nmap/masscan/medusa/Metasploit 都打真实靶子，
  ELK 检测真实日志。攻击链的时间间隔靠调度控制，不伪造时间戳。
- **baseline 安全**：`main` = 升级前系统，`investigation.py`（线性 baseline）
  一行不改。升级通过 `INVESTIGATION_MODE` 开关旁路，随时切回。
- **一功能一 commit + devlog**：遵守 `CLAUDE.md` 工作流；改核心流水线先跑
  `pytest` 全绿再提交。

---

## 现状盘点（决定了要改哪里）

| 部件 | 现状 | 与升级的关系 |
|---|---|---|
| `lab/attack_dvwa.sh` | 6 攻击、3 IP（.104/.150/.151），sqlmap/curl/hydra/nmap，背靠背 | Part A 改造主体（保留作基线，不删） |
| 检测规则 | 6 条按 URL 路径匹配；filebeat 直取模式聚合（`INGEST_MODE=filebeat`） | 新攻击类型 = 新 Kibana 规则 + 新 `_FALLBACK_RULES` |
| `investigation.py` | 线性两步：GraphRAG 取 MITRE → 一次 LLM 出 JSON。非 agent | Part B baseline，**不动** |
| `enrich_node`（pipeline） | triage 前一次性跑 threat_intel/asset/vuln（**0 token 确定性函数**） | ReAct 的现成工具；也是"工具预跑"省 token 的基础 |
| `correlation.py` | 按源 IP 关联、NetworkX 建链、kill-chain 排序，窗口 180 天 | 定时攻击链的消费者；新阶段加进 `KILL_CHAIN` |
| 分类器映射 | `RULE_MAP` / `RULE_META` / `ATTACK_TYPE_RULES` / `has_attack_keyword` 硬编码 6 类 | 新攻击类型需同步这几处 |

---

## Part A：真实攻击多样性

### A1. Metasploit 真实 exploit（论文 Ch3）

真实 exploit 需要真正有漏洞的靶子。三条路线，按真实性/成本排序：

| 方案 | 做法 | 真实性 | 成本 | 论文说法 |
|---|---|---|---|---|
| **① web_delivery 链（推荐主线）** | 用 DVWA 已有命令注入当入口，`exploit/multi/script/web_delivery` 投递真实 Meterpreter → 拿到 session → 跑 post 模块/建持久化 | 真 shell、真 C2、真后渗透 | 低（复用 DVWA） | 将 DVWA 命令注入串接 Metasploit web_delivery，获得 Meterpreter 会话并完成后渗透 |
| ② Target VM 加漏洞服务 | 部署 shellshock CGI（`apache_mod_cgi_bash_env_exec`）或老版 vsftpd | 真 exploit | 中（老服务难装） | 服务级 RCE |
| ③ 加一台 Metasploitable2 VM | 现成几十个真实 exploit（vsftpd 后门/samba usermap/tomcat…） | 最真最多样 | 中（多一台 VM + Filebeat + 新规则） | 工业标准脆弱靶机 |

**决定**：待定（见文末）。默认走 ①，如需广度再叠 ③。

**自动化**：`msfconsole -r lab/msf/*.rc` 资源脚本（非交互、可复现、进 git）。
web_delivery 流量 ELK 可见（DVWA exec 请求带一行下载器 → payload 拉取 → 回连 Kali），
可加一条 **"C2 / Payload Delivery Detected"** 规则。

### A2. 同种攻击、不同工具/参数

同一路径规则下打出不同签名/速率，让分类器见到同类攻击的多形态：

| 攻击 | 现有 | 新增变体 |
|---|---|---|
| SQLi | sqlmap `--technique=BEU` | 手写 curl UNION/boolean、sqlmap 时间盲注 `-T`、`wapiti`/`nikto` |
| 暴力破解 | hydra | Metasploit `ssh_login`、`medusa`、`patator`（不同速率/线程） |
| 端口扫描 | nmap `-sT` | `masscan`（高速）、Metasploit `portscan/tcp`、nmap `-sS` / 慢速 `-T2` |
| XSS | curl 4 payload | 换 payload 家族（编码绕过）、不同 UA |

→ 新脚本 `lab/attack_multitool.sh`（`attack_dvwa.sh` 保留不动）。

### A3. 更多攻击者 IP

现 3 个 IP。扩到 6–8 个别名，每个绑一种独特手法
（如 .105=masscan、.152=medusa、.161=metasploit web_delivery）。别名机制现成
（`ip route replace <target> src <alias>`），扩 `ALIASES` 数组 + 每 IP 的 phase。

> 训练标签联动：新攻击 IP 都要加进 `export_training_set.py` 的 `--attack-ips` 默认列表；
> `.160` 仍是唯一 benign。

### A4. 定时多阶段攻击链（真实流量、时间可控）

新脚本 `lab/attack_chain.sh`：从**单一源 IP** 按 kill-chain 顺序跑，阶段间 `--gap N` 秒
（或 `at`/cron 跨小时/跨天）：

```
侦察(nmap -sV 慢速) → 端口扫描 → SSH 暴破(hydra)
  → SQLi(sqlmap) → 命令注入 → web_delivery 拿 Meterpreter → 后渗透/持久化
```

每阶段真实工具流量。同一 IP + correlation 窗口 180 天 → `correlation.py` 会重建成一条链，
时间间隔真实可控。**需在 `KILL_CHAIN` 补 Persistence / C2 阶段。**

### Part A 要动的文件

| 文件 | 动作 |
|---|---|
| `lab/attack_multitool.sh` | 新增：同类攻击多工具变体 |
| `lab/attack_metasploit.sh` + `lab/msf/*.rc` | 新增：msf 资源脚本 |
| `lab/attack_chain.sh` | 新增：定时多阶段 kill chain，`--gap` |
| `lab/target_setup.sh` | 改：放通出站 C2、（选②加 CGI 端点） |
| `lab/metasploitable_setup.md` | 新增（仅选③） |
| `lab/README_lab.md` | 改：新工具/IP/规则/时序 |
| `app/services/siem_service.py` | 改 `_FALLBACK_RULES`：加 "C2/Payload Delivery" 等新规则 |
| `app/agents/triage.py` | 改 `ATTACK_TYPE_RULES` + `has_attack_keyword`（`() {`、`web_delivery`、`meterpreter`、masscan UA）+ `RULE_MAP` 对齐 |
| `scripts/train_triage.py` | 改 `RULE_MAP` 新类目 |
| `scripts/export_training_set.py` | 改 `RULE_META` + 默认 `--attack-ips` 加新 IP |
| `app/agents/correlation.py` | 改 `KILL_CHAIN`：加 Persistence/C2/Post-Exploit |

**工作量**：多工具脚本 0.5–1d；Metasploit 自动化 1–2d；定时链脚本 0.5–1d；
新规则+分类器映射+重新 ingest 验证 1d；（选③ +0.5–1d）；文档 0.5d。**合计约 4–6 天。**

---

## Part B：三档 Agent（保 agent、省 token）

### 核心认识

"agent" 的本质是**自主用工具 + 目标导向推理**，不是"LLM 在循环里被反复问"。
烧 token 的是后者。把两者解耦 → 保住 agent 名分，同时把 token 砍下来。

### 三档设计（`INVESTIGATION_MODE` 开关）

| 档 | 说明 | 每事件 LLM 调用 | 用途 |
|---|---|---|---|
| `baseline` | 现有线性两步，**代码一行不改** | 1 | 论文对照组 |
| `react-lite`（**日常默认**） | 确定性预跑所有工具 → 规则决定是否狩猎 → **1 次** LLM 综合。有完整工具调用和 trace，是真 agent | ~1 | 生产默认 |
| `react-full` | 多步 Thought→Action→Observation 循环，LLM 自主决定调哪个工具、何时停 | 2–~6（有上限） | uncertain / 关键链节点 / 演示 |

三档共存，能在**同一批事件**上 A/B/C，供论文对比。

### 省 token 的四个杠杆（力度从大到小）

1. **分流（gating，最大）**：triage 后加**纯规则路由（0 token）**。清楚的 high/low →
   模板 + 单次 LLM（或纯模板）；只有 uncertain 或多阶段链关键节点 → 才放行进 `react-full`。
   通常砍掉 70–90% 的多步调用。
2. **工具预跑（消灭 reason↔act 往返）**：threat_intel/asset/vuln 本就是 0 token 确定性函数，
   别让 LLM"决定"调它们——预跑好塞进上下文，LLM 对着备齐的证据推理一次。这就是
   `react-lite` 的做法（确定性 agent：控制流由启发式决定，LLM 只做综合）。
3. **硬上限 + 提前退出**：`REACT_MAX_STEPS`=2–3，够了就 early-exit；per-event token 预算。
4. **上下文纪律**：Observation 进上下文前先裁剪/摘要（日志给计数+2 样本，不整段塞）；
   维护紧凑 scratchpad 而非滚动全历史；raw_logs 不重复发。
5. **（补充）已知模式模板化**：6 种已知攻击的 MITRE/危害用确定性模板填，
   LLM 只写需要判断的部分；同源 IP 短期复现走缓存（0 token）。

### 工具集（`app/agents/tools.py`，多为包装现有能力）

| 工具 | 实现 | 状态 |
|---|---|---|
| `get_threat_intel(ip)` | `enrichment.threat_intel.lookup` | 现成，包一层 |
| `get_asset_info(ip)` | `enrichment.asset_assessment.lookup` | 现成 |
| `get_vulnerabilities(ip, type)` | `enrichment.vuln_assessment.assess` | 现成 |
| `query_event_history(ip/type/since)` | Event 表查询 | 新（数据现成，补查询函数） |
| `search_raw_logs(query, ip)` | 复用 `siem_service._query_filebeat` + `_kql_to_lucene` | 新（把内部方法提成公开 `search_logs`） |
| `search_mitre(query)` | `investigation._graphrag_retrieve`（ChromaDB） | 现成（未建 KB 走静态兜底） |
| `hunt_related_activity(indicator)` | 跨 IP/跨时间找同一指标 | 新（威胁狩猎，组合上面几个） |

### ReAct 循环（`react-full`，LangGraph 子图）

```
        ┌──────────────────────────────────────┐
入 ──►  │ reason(LLM: Thought→决定Action/收尾)    │
        │    │           ▲ Observation           │  ──► 出(llm_summary + trace + hunting)
        │    ▼           │                        │
        │ act(执行工具)───┘  (循环至 final 或上限) │
        └──────────────────────────────────────┘
```

- Groq Llama 原生 function-calling；保留文本版 Thought/Action/Observation 解析兜底。
- 完整推理轨迹写进 `investigation_trace`（论文证据 + 报告展示）。
- **威胁狩猎**：反应式分析后（或循环中 agent 主动选择）发起狩猎查询——
  "还有别的 IP 打同一 CVE 吗""窗口内有 low-and-slow 扫描吗"——命中写进 `hunting_findings`。
  这是 baseline 完全没有的能力，是论文对比的关键差异点。

### Part B 要动的文件

| 文件 | 动作 |
|---|---|
| `app/agents/tools.py` | 新增：工具注册表（上面 7 个） |
| `app/agents/investigation_react.py` | 新增：react-lite + react-full（子图/循环/狩猎/trace） |
| `app/agents/investigation.py` | **不动**（baseline） |
| `app/agents/pipeline.py` | 改：按 `INVESTIGATION_MODE` 选节点 + triage 后分流路由 |
| `app/agents/state.py` | 改：加 `investigation_trace` / `hunting_findings` / `tools_used` |
| `config/settings.py` | 改：`INVESTIGATION_MODE` / `REACT_MAX_STEPS` / `GROQ_MODEL_REACT`（建议 70b/llama-4）/ token 上限 |
| `app/services/siem_service.py` | 改：`_query_filebeat` 提成公开 `search_logs()` |
| `app/services/event_service.py` | 改：加 `query_events(...)` |
| `app/models/db.py` | 选改：trace 存哪（塞 `llm_summary` JSON 免迁移，或加 JSON 列） |
| `scripts/compare_investigations.py` | 新增：三档 A/B/C 对比 harness |
| `tests/test_agent_tools.py` / `test_investigation_react.py` | 新增 |
| `app/services/report_service.py` | 选改：PDF 渲染 trace/狩猎 |
| `scripts/build_knowledge_base.py` | 选跑：建 ChromaDB KB 让 `search_mitre` 真 GraphRAG |

**工作量**：tools.py 1–1.5d；investigation_react.py（核心）2–3d；pipeline/settings/state
接线 + 分流 0.5–1d；siem/event_service 重构 0.5–1d；对比脚本+指标 1d；测试 1d；
（选）建 KB 0.5–1d、报告渲染 0.5d。**合计约 6–9 天。**

---

## Baseline 对比方法（论文用）

`scripts/compare_investigations.py`：同一批事件分别过 `baseline` / `react-lite` /
`react-full`，产出 CSV/表格：

| 维度 | 指标 |
|---|---|
| 分析质量 | MITRE 技术覆盖/准确率（对已知攻击类型作 ground truth）、what_happened 正确性、建议可执行性（人评或 LLM-judge 打分） |
| 威胁狩猎 | react 发现而 baseline 漏掉的真实关联数（多阶段链、跨 IP 指标） |
| 深度 | 调用工具数、引用证据数 |
| 成本 | LLM token、耗时、API 调用数（**量化 trade-off 是亮点**） |
| 鲁棒性 | 工具/LLM 失败时的兜底表现 |

**三档对比的论文价值**：不只是"ReAct 更强但更贵"，而是用 react-lite 证明
"agent 化不必然更贵"——这本身是工程贡献点。

**git 策略**：`feat/upgrade` 开发；三档 behind `INVESTIGATION_MODE` flag 共存；
`main` = baseline，标签 `baseline-pre-upgrade` 精确可切回。

---

## 风险与依赖

1. **Metasploit 需要真漏洞靶子**——最大不确定性。选 ① 成本最低但要先在实验环境
   跑通一次 Meterpreter 会话；选 ③ 最多样但多一台 VM + 新规则。
2. **新攻击类型 = 五处联动改动**：检测规则（Kibana + `_FALLBACK_RULES`）、`RULE_MAP`、
   `KILL_CHAIN`、`has_attack_keyword`、`RULE_META`。漏一处新流量就进不了/标错。
3. **ReAct 的 LLM**：当前 `llama-3.1-8b-instant` 多步推理弱，`react-full` 建议上 70b/llama-4，
   Groq 免费额度下 token/延迟上升；对比里如实呈现。真正卡的多半是免费额度限流，
   分流+工具预跑+上下文纪律正好解限流。
4. **数据质量前提**：此前发现 .104 有反复打 `id=1` 的良性循环污染。Part A 重打前先查清
   那个循环、清掉旧脏数据，否则对比数据不干净。

## 待拍板决定

1. **Metasploit 靶子**：① web_delivery 复用 DVWA / ③ 加 Metasploitable VM / 两者都要？
2. **攻击者 IP 规模**：扩到几个？（建议 6，每个一种独特手法）
3. **`react-full` 的 LLM**：是否允许切到更强的 70b/llama-4（更好但更慢更耗额度），
   baseline/lite 保持 8b？

## 推进顺序与里程碑

**先 A 后 B**（A 产出的多样化真实数据是 B 的输入，两版都受益）：

1. **M0（本步，已完成）**：文档 + `feat/upgrade` 分支 + `baseline-pre-upgrade` 标签，
   baseline 确认可跑（pytest 绿）。
2. **M1 — Part A**：多工具脚本 → Metasploit 自动化 → 定时攻击链 → 新规则+分类器映射联动 →
   打一批新数据、验证 ingest/分类器/攻击链。
3. **M2 — Part B 骨架**：`INVESTIGATION_MODE` 开关 + `tools.py` + 分流路由（baseline 仍默认）。
4. **M3 — Part B agent**：react-lite → react-full → 威胁狩猎 → trace。
5. **M4 — 对比**：`compare_investigations.py` 出三档对比表，供论文。

每步一功能一 commit + devlog，改核心流水线先 `pytest` 全绿。
