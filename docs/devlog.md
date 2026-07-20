# CyREN 开发日志 (devlog)

> 约定：每完成一个功能就 git commit 一次，并在这里追加一条记录。
> 每条记录包含：日期、做了什么、遇到的问题、怎么解决。
> （2026-07-19 起项目主目录迁到 C:\cyren，本仓库在此重新 git init；
> 更早的迁移与 dashboard 接线历史见 OneDrive 旧仓库的 docs/devlog.md。）

---

## 2026-07-19 — 独立 Login/Register 页面 + 注册接口 + 登出确认

### 做了什么

1. **独立认证页面**：新增 `app/templates/login.html` 和 `register.html`
   （漫画风格与主界面一致）。index.html 里内嵌的假 Sign In/Register 区块删除，
   `/` 未登录时 302 到 `/login`，已登录访问 `/login`、`/register` 则跳回 `/`。
2. **注册接口** `POST /api/register`（auth.py）：校验必填项、role 白名单
   （analyst|manager，去掉了设计稿里的 Read Only）、密码策略（≥12 位含大小写
   数字特殊字符）、用户名唯一（409）；用现有 `User.set_password()` hash 入库。
3. **登出确认**：侧边栏 Log Out 先弹漫画风格确认框，确认后才调
   `POST /api/logout` 并跳回 /login。
4. **侧边栏用户信息接真**：`window.CURRENT_USER` 由 Jinja 注入
   `current_user.to_dict()`，头像缩写/姓名/角色不再写死。
5. `apiGet()` 遇到 session 过期（拿到重定向 HTML 而非 JSON）自动跳回 /login。
   Buddy 对 `window.login` 的包装移除（登录已不在本页发生）。

### 遇到的问题 & 怎么解决

| 问题 | 解决 |
|---|---|
| C:\cyren 不是 git 仓库（从 OneDrive 拷出来的运行副本） | `git init -b main`，确认 .gitignore 覆盖 .env/db/venv 后做基线提交 |
| 注册表单原有 "Read Only" 角色但 User 模型只有 analyst/manager | 表单与后端都限定为这两种角色 |
| 冒烟脚本 `from app import create_app` 报 ModuleNotFoundError | 运行时设 `PYTHONPATH=C:\cyren`；并用临时 sqlite（DATABASE_URL 环境变量）避免污染真实库 |

### 验证结果

- `pytest` 5 个测试全过。
- Flask test client 冒烟：匿名 `/`→302 /login；/login、/register 200；
  弱密码 400、非法角色 400、注册成功 201、重复用户名 409；
  错密码 401、登录成功 200；登录后 `/` 200 且含 CURRENT_USER 注入、
  /api/dashboard 200；已登录访问 /login→302 /；登出后 `/`→302 /login。

---

## 2026-07-19 — Buddy 真实告警 + 日期筛选真过滤 + 搜索图标可点击

### 做了什么

1. **Buddy 行为重写**：删掉"登录 5 秒后必弹 192.168.56.102/SQL Injection 假告警"
   的 `startBotAlert`。新 `notifyHighRisk(event)` 由 `loadDashboard()` 在拿到
   真实 events 后触发：只有存在未播报过的 high risk 事件（`_buddySeen` 按
   event id 去重，30 秒轮询不重复骚扰）才弹气泡，内容是事件真实的
   source_ip + attack_type；无 high 事件时 Buddy 静静待在右下角
   （默认位置从 left:300px 改到右下）。
2. **日期筛选接真**：后端 `/api/dashboard`、`/api/events` 支持
   `?from=&to=`（按 `Event.last_seen` 过滤，to 含当天整天；格式错或
   from>to 返回 400）。前端日期框默认留空=显示全部（之前写死
   2026-07-12 所以界面永远像 12 号），Apply 校验 from≤to 且输入框
   min/max 联动禁止选出倒序区间，新增 Clear 按钮清空过滤；
   30 秒自动刷新沿用当前所选范围。Attack Chain / All Events 页写死的
   日期默认值一并清空（那两页的过滤逻辑随 3b 再接）。
3. **搜索图标可点击**:顶部搜索框的放大镜从装饰 span 改成按钮，点击
   与回车同效（跳到 All Events 并过滤）。

### 遇到的问题 & 怎么解决

| 问题 | 解决 |
|---|---|
| "19 号没数据"的错觉 | 根因是日期框写死 2026-07-12 且不起作用；现在默认空=全部数据，选范围才过滤 |
| to 参数按天过滤会漏掉当天事件 | 后端把 end 解析为次日 0 点做排他上界（`last_seen < end`） |
| 连点 Buddy 几次后整个页面变黑 | 每次点击都 `new bootstrap.Modal(...)` 新建实例，各带一层 backdrop 遮罩，关闭只关最后一个，孤儿遮罩越叠越黑；logoutModal 同病。全部改用 `bootstrap.Modal.getOrCreateInstance()` 复用单实例 |

### 验证结果

- `pytest` 5 个全过。
- test client 冒烟（两个不同日期的种子事件）：无参=2 条；只选 19 号=1 条；
  只选 12 号=1 条；from=13 号=只剩 19 号那条；from>to 返回 400；
  非法日期返回 400。

---

## 2026-07-19 — 全部页面接真：Events/Approval/Detail/Chain/Blocked/Reports/Users/Profile

### 做了什么

**新后端接口**（routes.py / auth.py）：

- `GET /api/reports/<id>/download`（附件下载）与 `/preview`（inline，浏览器直接渲染 PDF）；
  file_path 相对路径按项目根解析，文件不存在返回 404。
- `POST /api/change-password`（验证当前密码 + 密码策略）、
  `POST /api/verify-password`（敏感操作前二次验证）、
  `POST /api/profile`（改姓名/邮箱）。
- `POST /api/users`（manager 专用建号）、`PATCH /api/users/<id>`
  （改名/改角色/启停用，禁止停用自己）。
- `POST /api/blocked`（手动封 IP：IPv4 校验、去重 409、联动 response_agent）。
- `GET /api/me/activity`（当前用户的决策统计 + 最近决策，带事件 IP）。

**前端全部接真**（index.html，静态假行全部删除）：

- All Events：真数据表格 + 风险 chips 计数 + 攻击类型下拉（按数据生成）+
  risk/status/IP/日期过滤（调 API）+ 客户端分页（Rows 选择器 + 页码）+
  Export CSV（真导出当前结果）+ 行点击进详情。
- Event Detail：按事件 id 拉取渲染全部字段（信息卡、置信度条、MITRE、
  LLM 三段分析、raw log 样本）；Response 区按状态渲染真按钮——
  awaiting 可 Block/Dismiss（POST decision）、blocked 可 Unblock/标记误报；
  Export PDF 按钮找到该事件的报告才可用，点击真下载。
- Human Approval：真 awaiting 列表 + 等待时长 + 行内 View/Block/Dismiss。
- Attack Chain：链列表接 /api/chains；链视图动态生成 SVG 节点图
  （按 stage 交错布局、绿→黄→红渐进、预测节点虚线）+ 时间线表。
- Firewall Blocks：真封禁列表 + Unblock + Add Block（prompt 输 IP）+
  Active blocks 表和 iptables 原始输出按数据生成 + 搜索。
- Incident Reports：改成和其他 tab 一致的表格（Report#/攻击/风险/处置/时间），
  每行 Preview（iframe 内嵌浏览器原生 PDF 预览）+ Download；
  假的"Generate Report"按钮和写死的纸质预览删除。
- User Management：真用户表（manager 可见，analyst 显示提示）；
  Add User / Edit（改名改角色）/ Disable/Enable 全部接 API，不能停用自己。
- My Profile：资料回填 + Save 真保存；Change Password 真改密码
  （前后端双重策略校验）；Your Activity 接 /api/me/activity；
  Login History 显示真实 last_login。
- Settings：阈值解锁的身份验证改为真调 /api/verify-password
  （写死的 password123 删除）；Buddy 气泡点击跳转到触发它的真实事件详情。

### 遇到的问题 & 怎么解决

| 问题 | 解决 |
|---|---|
| Report.file_path 生成时是相对路径，直接 send_file 会因工作目录不同 404 | 下载/预览前按项目根目录解析为绝对路径再校验存在 |
| 旧 openEvent(fake) 被 Buddy 和多处静态行引用 | 统一换成 openEventDetail(id)；Buddy 记录触发事件 id，点气泡直达该事件 |
| manager 停用自己会把自己锁死 | PATCH is_active 时后端拒绝 self-disable（400），前端也不渲染按钮 |

### 验证结果

- `pytest` 5 个全过。
- 全量 test client 冒烟：报告下载（Content-Disposition attachment）与预览
  （application/pdf）200；verify-password 错 401 对 200；改密码错当前密码/弱
  密码 400、成功后旧密码失效新密码可登录；profile 更新生效；analyst 访问
  /api/users 403；手动封禁 201、重复 409、非法 IP 400、解封 200；approve
  决策后事件变 blocked；activity 计数与 IP 正确；manager 建号 201、改角色、
  停用、self-disable 400。

### 遗留

- Settings 页的阈值数值、Email 通知、模型重训、Agent 开关仍是演示 UI，
  没有后端持久化（需要新增配置表并接入 triage 路由，另开任务）。
- All Events 的批量勾选框无批量操作；报告无批量导出。

---

## 2026-07-19 — 每个 event 都有自己的报告 + 日期时间搜索（并修好 PDF 生成）

### 做了什么

1. **报告按需生成，覆盖所有事件**（之前只有 high risk 自动封禁时才有）：
   - `_state_from_event(event)`：从 Event 行（含关联 AttackChain、BlockedIP）
     还原出 report_service 需要的 state dict。
   - `_ensure_report(event)`：已有且文件在磁盘上就复用，否则生成 PDF 并
     upsert Report 行。
   - 新接口 `POST /api/events/<id>/report`、
     `GET /api/events/<id>/report/preview`、`/download`。
     详情页 Export PDF 改用后者，不再需要报告事先存在。
2. **Reports 页改成事件表格**：列出每个事件的 Event# / Date / Time /
   Attack Type / Source IP / Risk / Status / Report（Ready 或 On demand）
   + View / Download 两个按钮；点 View 高亮该行并在下方 iframe 内嵌预览，
   点 Download 直接下载。
3. **日期 + 时间搜索**：`_parse_bound` 支持 `YYYY-MM-DD` 与
   `YYYY-MM-DD HH:MM`（末端分别滚到次日零点 / 该分钟末尾）；Reports 页
   提供 From/To 各一组 date + time 输入，配 Apply / Clear，并有 min/max
   联动防止选出倒序区间。

### 遇到的问题 & 怎么解决

| 问题 | 解决 |
|---|---|
| **下载到的"PDF"其实是 42 字节的 .txt 占位文件** | 根因是 venv 里 Pillow 12.3.0 的 `_imaging` C 扩展坏了（`cannot import name '_imaging' from 'PIL'`），reportlab 导入失败后 report_service 静默走 `_canvas is None` 的占位分支。`pip install --force-reinstall --no-cache-dir pillow==11.3.0` 修复，现在产出真 PDF（application/pdf，约 2.2 KB） |
| 表格显示 first_seen，过滤却按 last_seen，按表里看到的时间搜反而搜不到 | `_apply_date_range` 改为**区间重叠**语义：`last_seen >= start AND first_seen < end`（用 coalesce 兜空值），无论按事件的开始还是结束时刻搜都能命中 |

### 验证结果

- `pytest` 5 个全过。
- 冒烟（3 个不同日期时间、不同风险等级的事件，初始 0 份报告）：
  三个事件的 preview 都返回 `application/pdf`（2176–2218 字节）；
  download 带 attachment 头；生成后 reports 表恰好 3 条（每事件一份）；
  重复 preview 复用不重复生成；日期时间过滤 6 种组合全部命中预期
  （含 09:30–09:30 这种精确到分钟、落在事件窗口内的查询）；
  from>to 400、非法时间 400、不存在的事件 404。

---

## 2026-07-20 — PDF 报告重排版：品牌化页头、表格化、内容补全

### 做了什么

`report_service.py` 从"纯文本 drawString 堆叠"重写成一套排版原语，
配色沿用系统的 navy `#0d2c50` / yellow `#ffd60a`。

**排版**

- 每页顶部 navy 色带：黄色圆角方块内嵌 navy "C" 作为 logo 标记 +
  "CyREN" 字标 + "SOC INCIDENT RESPONSE" 小字；右侧风险色块
  （high 红 / uncertain 黄 / low 绿）。首页色带下方是报告标题和
  `Incident #42 · IP · Generated ... UTC` 元信息行。
- 区块标题统一为 navy 圆角横条 + 黄色大写字，8 个区块层次分明。
- 新增布局原语（都自带分页）：`section()` 标题条、`kv_table()`
  左标签右值两列表（标签列浅底、斑马纹）、`data_table()` navy 表头多列表、
  `para_box()` 浅底段落框、`code_box()` 等宽代码框、`_pill()` 彩色药丸、
  `confidence_bar()` 大号百分比 + 按风险上色的进度条。
- 每页页脚：细分隔线 + "CyREN SOC Incident Response" + "Page N of M"。
  总页数靠**两遍渲染**取得：先渲到 `io.BytesIO()` 数页数，再正式输出。

**内容**

- AI Analysis 完整展开成四个框：What Happened / Potential Impact /
  Recommended Action / Urgency（urgency 带彩色药丸）。
- 新增 MITRE ATT&CK 三列表格（ID / 技术名 / 战术）。战术是新加的：
  知识库只存 `"T1190 Exploit Public-Facing Application"` 这种字符串没有战术，
  报告里用 `MITRE_TACTICS` 静态映射解析，子技术回退到父 ID。
- 新增攻击链区块：链风险药丸 + 评估 + 阶段时间线表 + 预测下一阶段。
- 新增原始日志样本区块（Courier 等宽、浅灰底、超长行截断、最多 12 行并
  注明还有多少条）。
- Response Actions 扩充为：Action Taken / Source IP Blocked / Blocked At /
  Decided By / Decision Time / Notification。
- `_state_from_event()` 相应补充 event_id、first_seen/last_seen、
  raw_log_sample、chain_assessment，以及查 Decision→User 得到的
  decided_by / decided_at 和 BlockedIP 的 blocked_at / blocked_by。

### 遇到的问题 & 怎么解决

| 问题 | 解决 |
|---|---|
| 首页元信息行被第一个区块标题条压住 | `_start_page()` 对第 1 页多留 52pt（标题 + 元信息），其余页 16pt |
| 区块标题条孤零零留在页尾、内容翻到下一页 | `section()` 预留 92pt（标题条 + 首几行）再决定是否分页 |
| 无法直接肉眼检查生成结果 | 装 `pypdfium2` 把 PDF 渲染成 PNG 自查，确认色块、表格、页脚、跨页都正常 |

### 验证结果

- `pytest` 5 个全过；报告 API 冒烟全过（三种风险等级都是 application/pdf，
  体积从 2.2 KB 增到约 6 KB）。
- 逐页肉眼验收两种极端样本：
  - 完整样本（high risk、4 阶段攻击链、3 条 MITRE、5 行原始日志、
    长篇 LLM 分析）→ 2 页，排版正确，样张存于
    `docs/sample/sample_incident_report.pdf`。
  - 稀疏样本（low risk、无 MITRE、无攻击链、无日志、无 LLM 分析）→
    优雅降级：绿色 LOW RISK 标、"Not available." 占位、
    MITRE 表显示 "None recorded."、攻击链区块自动省略、缺失值显示 "—"。

### 遗留

- `MITRE_TACTICS` 是手写的静态映射，只覆盖 fallback 用到的技术；
  等 ChromaDB 知识库建起来后应改为从知识库取战术。
- 报告中文/非 ASCII 字符会因 Helvetica 内置字体缺字形而显示异常，
  真要支持需注册 CJK TTF 字体（当前系统输出均为英文，暂不影响）。

---

## 2026-07-20 — 修旧报告不更新 + 报告内容与详情页对齐 + 分页保持

### 做了什么

用户反馈 Reports 页里第 1、3 条打开还是旧版排版，只有第 2 条是新版。

1. **报告格式版本号**：`report_service.REPORT_FORMAT_VERSION = "v2"`，
   写进生成的文件名（`..._v2.pdf`）。`_ensure_report()` 改为
   "文件在磁盘上**且**文件名带当前版本号"才复用，否则重新生成。
   以后再改版式只要 bump 这个常量，所有旧报告自动重出。
2. **内容与 Incident Details 页对齐**（用户要求报告内容和详情页一致）：
   - 置信度条下方补上详情页那句
     `The XGBoost classifier scored this event at X% confidence, which falls in the "Y" tier.`
   - Raw Log Sample 上方补 `Showing N of M aggregated log lines.`
   - Response Actions 上方补详情页的状态说明（IP blocked / Waiting for an
     analyst decision / Dismissed as a false positive / Logged）。
   - 新增 `caption()` 排版原语承载这些说明文字。
3. **分页保持**：新增 `keep_together(height)` 与 `kv_height(rows)`，
   `section(title, keep=...)` 可预知后续内容高度。短表格、代码框不再被
   拆到两页，区块标题也不会与内容分离。

### 遇到的问题 & 怎么解决

| 问题 | 解决 |
|---|---|
| 旧报告文件还在磁盘上就被复用，改了版式也不生效 | 文件名带格式版本号，`_ensure_report()` 比对版本，不符就重新生成 |
| Response Actions 6 行表格被拆成"页 2 四行 + 页 3 两行"，页 3 几乎全空 | `kv_table()` 先算总高，放不下且能放进新页就整体挪过去 |
| 修完上一条后变成"标题条留在页 2、表格跑到页 3" | `section()` 增加 `keep` 参数接收后续内容高度估算，标题与内容一起搬；上限取单页可用高度，避免超长内容反而空一页 |

### 验证结果

- `pytest` 5 个全过；报告 API 冒烟全过；日期时间过滤 6 种组合仍全部正确。
- 新增陈旧报告冒烟：预置一个无版本号的旧文件 → 访问 preview 后
  `file_path` 变成 `..._v2.pdf`（已重新生成），再次访问复用不重复生成，
  Report 行数保持 1。
- 逐页肉眼复核：完整样本 3 页，三处新增说明文字就位，
  Response Actions 标题+说明+6 行表格完整同页；稀疏样本仍优雅降级。
- 样张已更新：`docs/sample/sample_incident_report.pdf`。

---

## 2026-07-20 — 修好 Groq LLM 调用：报告里终于是真实 AI 分析

### 查到的原因（三个串联的问题）

用户反馈 .env 里的 GROQ_API_KEY 是有效真 key，但报告 AI Analysis 仍是
"Placeholder analysis. Connect the Groq API..."。逐层排查后发现**与
chromadb/GraphRAG 无关**（那块只影响 MITRE 检索，静态 fallback 一直正常），
真正原因是三个问题串在一起：

1. **`import groq` 失败**：`ModuleNotFoundError: No module named
   'pydantic_core._pydantic_core'` —— venv 里 pydantic-core 的编译扩展是坏的
   （与之前 Pillow `_imaging` 同一类问题）。investigation.py 顶部的
   `except ImportError: Groq = None` 把它静默吞掉，于是 `self.groq is None`，
   直接走占位符分支。key 本身完全正常（gsk_ 开头、56 字符、正确读入 settings）。
2. 修好 pydantic 后暴露第二层：**groq 0.11.0 与 httpx 0.28.1 不兼容**
   （`Client.__init__() got an unexpected keyword argument 'proxies'`）。
   而且这个错误发生在模块级 `_investigation = InvestigationAgent()`，
   会直接让整个 app 导入失败。
3. 升级 groq 后暴露第三层：**配置的模型已下架**——
   `meta-llama/llama-4-scout-17b-16e-instruct` 返回 404 model_not_found。
   查该 key 可用模型，选定 `llama-3.3-70b-versatile`（仍是 Llama 系，70B 质量最好）。

### 做了什么

1. `pip install --force-reinstall pydantic==2.13.4`（修复 pydantic-core）、
   `pip install --upgrade groq` → 1.5.0；requirements.txt 相应更新并注明原因，
   同时补上 `pillow==11.3.0`（上次口头修复没落进依赖文件）。
2. `.env` / `.env.example` / `settings.py` 的 GROQ_MODEL 改为
   `llama-3.3-70b-versatile`。
3. **让这类失败不再静默**（这是本 bug 拖到现在的根本原因）：
   - import 失败记录具体异常而非丢弃，`_init_groq()` 把不可用原因写进
     `agent.llm_status` 并打 WARNING 日志。
   - 客户端构造失败不再让整个模块导入崩溃。
   - API 调用加 try/except：失败不再中断流水线，但会打 ERROR 日志，
     并把原因写进 `llm_summary.llm_error`，报告里显示
     "AI analysis unavailable: <原因>" 而不是含糊的 "Placeholder"。
4. 新增 `scripts/check_llm.py`：逐项检查 groq 包 / key / 客户端 /
   可用模型列表 / 配置的模型是否在列 / 真实调用，一键定位问题。
5. 新增 `scripts/reanalyse_events.py`：对库中已有事件重跑 investigation，
   替换占位符分析，并删除据其生成的旧 PDF 报告（下次查看时自动重生成）。
   支持 `--dry-run` 和 `--all`；LLM 不可用时拒绝运行，避免用占位符覆盖占位符。

### 验证结果

- `scripts/check_llm.py` 六项全 OK，`RESULT: LLM analysis is working.`
- `reanalyse_events.py` 处理了库里全部 3 个事件，均成功并各删除 1 份旧报告。
- 抽查数据库：三个事件的 what_happened / what_could_go_wrong /
  what_should_be_done / urgency 都是针对该事件的真实内容
  （例如 SSH Brute Force 那条提到 189 条日志、建议启用 MFA 和限速）。
- 重新生成报告并逐页看图确认：AI ANALYSIS 区块四个框都是真实分析文本，
  urgency 药丸显示 LOW，MITRE 表格正常。
- `pytest` 5 个全过。

### 遗留

- 事件 #1 的 source_ip 存的是字面量 "unknown"，说明 siem_service 从那条
  Kibana 告警里没提取出源 IP，需要回头看该规则的日志格式（与本次无关）。
- chromadb 仍不可用，MITRE 走静态 fallback 映射；GraphRAG 仍是 FYP2 增量。
