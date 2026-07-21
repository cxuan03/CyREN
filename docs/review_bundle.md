# CyREN — Review Bundle

> 自动导出，供代码审查用。包含 `devlog.md`、`README.md`，以及流水线核心
> （siem_service / triage / investigation / pipeline / correlation / response /
> scheduler / event_service）。Markdown 文档内联呈现，Python 源码用代码块。

---

## git log --oneline

```
fa33fcc feat: header/hamburger/responsive, richer alert email with link, cleaner data
b5ece24 feat: source-IP blacklist, Enter-to-search on approval, live 'last updated' indicator
4ae3c0b feat(ui): faster refresh (15s poll, 10s auto-fetch) and unified event filters
ab38ad5 feat(lab): real-tool DVWA attack simulation (sqlmap/hydra/nmap/curl)
a1631f9 fix(siem): recover attacker IPs from source logs, widen window, fix poll dedup
8b105bb fix(investigation): restore real Groq analysis; stop failures degrading silently
0198551 fix(reports): regenerate outdated PDFs, match the detail page, keep blocks intact
445cc36 feat(reports): redesign the incident PDF - branded layout, tables, fuller content
8635c69 feat(reports): per-event on-demand PDF reports with date and time search
c4b7f4b fix(ui): triage modal shows real low-risk groups instead of mock rows
b6c5437 feat(app): wire every remaining page to live APIs; reports preview/download
f1bd245 fix(ui): reuse Bootstrap modal instances to stop backdrop stacking blackout
7d8969e feat(dashboard): real Buddy alerts, working date filter, clickable search icon
b70059f feat(auth): standalone login/register pages, register API, logout confirm
27f95e4 chore: baseline import of CyREN app at C:\cyren (migrated from OneDrive working copy)
```

---

# ===== FILE: docs/devlog.md =====

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

---

## 2026-07-20 — SIEM 抓取三个问题：只有 3 种攻击 / 不再更新 / source_ip 是 unknown

### 查到的原因

直连实验环境的 ES 逐层排查，三个问题根因各不相同：

**① 只有 3 种攻击类型 —— 不是 CyREN 的问题，是实验数据本身没有。**

ES 里总共就只有 3 条规则产生过告警（SSH Brute Force 189 + Command Injection 66
+ File Inclusion 66 = 321，正好是 Kibana 里看到的 321 条）。CyREN 把存在的
全部抓到了。六条规则都启用且运行正常（status=ok），但另外三条的 query
与真实日志对不上：

| 规则 | query 找的字符串 | filebeat 里的实际情况 |
|---|---|---|
| SQL Injection | `message: "UNION SELECT"` | 0 条。实际 SQLi 请求是 `GET /dvwa/vulnerabilities/sqli/?id=1&Submit=Submit` —— **只访问了页面，没发真实注入 payload** |
| XSS Attack | `message: "script"` | 0 条。实际是 `GET /dvwa/vulnerabilities/xss_r/?name=John` —— **payload 是 "John" 不是 `<script>`** |
| Port Scan | `message: "PORTSCAN"` | 0 条。filebeat 里没有任何 PORTSCAN / nmap / iptables / DPT= 日志 —— **端口扫描根本没有被记录** |

而 Command Injection / File Inclusion 查的是 URL 路径（`vulnerabilities/exec`、
`vulnerabilities/fi`），日志里有，所以能匹配；SSH 查 `Failed password`，
auth.log 里有 5380 条。

**② scheduler 抓一次后不再更新 —— 时间窗口滑过去了。**

`FETCH_WINDOW_HOURS=24`，但所有告警都是 2026-07-18 的，当前是 07-20，
全部超出窗口 → 每次查询返回 0 条。scheduler 线程一直在跑，只是查不到东西，
且没有任何日志说明"这轮查到 0 条"，所以看起来像卡死了。

**③ SSH Brute Force 的 source_ip 是 unknown —— threshold 规则不带原始字段。**

SSH 规则是 **threshold 类型**，聚合字段是 `host.name`。这类告警只保留聚合键，
文档里只有 `host.name: target-server`，**没有 message、没有 source.ip**，
所以原来的两条提取路径（读 source.ip / 从 message 正则抠）都失败。
而 Command Injection / File Inclusion 是 query 类型规则，告警会复制原始文档，
带 message，正则兜底才成功。另外 filebeat 里 **0 条文档有 source.ip 字段**，
日志没被解析成 ECS 字段，只有原始 message 文本。

### 做了什么（CyREN 侧能修的两个半）

1. **回查原始日志恢复攻击者 IP**（`_enrich_from_source_logs`）：告警没有源 IP 时，
   用该规则自己的 query（`kibana.alert.rule.parameters.query`）到它自己的索引
   （`filebeat*`）里、按告警的时间窗（`threshold_result.from` → `@timestamp`）
   回查原始日志，取出现次数最多的 IP。按 (索引, query, 时间窗) 缓存，
   每条规则每轮只查一次。
   - 新增 `_FROM_IP_RE`：sshd 日志形如 `Failed password ... from 192.168.56.104 port 22`，
     优先取 "from" 后面的地址，避免误取同行其他 IP。
   - 回查到的真实日志同时作为事件的 `raw_logs`，报告里的 Raw Log Sample
     从此有真实内容（之前 threshold 告警这里是空的）。
2. **抓取窗口**：`FETCH_WINDOW_HOURS` 默认 24 → **168（7 天）**，实验数据不会
   在两次实验之间静默滑出窗口。新增 `scripts/backfill_events.py --hours N`
   回填更早的历史告警（支持 --dry-run / --force）。
3. **scheduler 去重逻辑**（`_is_new_activity`）：原来只比较 `log_count` 是否增长。
   滑动窗口下老告警会滑出、新告警滑入，log_count 可能持平甚至减少，
   于是新活动被漏掉。现在 **log_count 增长 或 last_seen 时间推进** 都会重新分析。
4. **让空转可见**：siem_service 每轮打印抓到多少告警、覆盖几条规则、
   聚合成几个事件、有多少条恢复了 IP、还有多少条仍是 unknown；
   ES 连不上或查询失败打 ERROR 日志（之前是 print 或静默）。

### 遇到的问题 & 怎么解决

| 问题 | 解决 |
|---|---|
| 告警的 `kibana.alert.ancestors[].id` 查不到原始文档（返回 0 条） | 那是 threshold 规则合成的 ID 不是真实 _id；改用"规则 query + 时间窗"回查，实测能准确命中 auth.log 里的 5 条 Failed password |
| 修好 IP 提取后，库里出现新旧两条 SSH 事件（unknown 一条、正确 IP 一条） | 写脚本删除 source_ip="unknown" 且已有正确替代的事件，连带清理其报告/决策/封禁记录 |

### 验证结果

- `pytest` 5 个全过。
- backfill dry-run：SSH Brute Force 的 source_ip 从 `unknown` 变成
  **192.168.56.104**（与真实攻击者一致）。
- 数据库现在 3 个事件，**IP 全部正确**：
  File Inclusion / Command Injection / SSH Brute Force 均为 192.168.56.104。
- scheduler 连续两轮 `_process_once` 均正常执行并正确跳过未变化的聚合
  （输出 "3 aggregate(s) unchanged, skipped"），证明轮询没有卡死。
- `_is_new_activity` 单元验证 5 种情况全部正确，包括原逻辑漏掉的
  "日志数持平但 last_seen 推进" 和 "日志数减少但有新活动"。

### 遗留（需要在实验环境侧处理，CyREN 无法凭空生成告警）

要让六种攻击都进库（训练分类器需要），必须让那三条规则真正产生告警，二选一：

- **改规则 query 匹配现有日志**（最快）：
  - SQL Injection → `host.name: "target-server" AND message: "vulnerabilities/sqli"`
  - XSS Attack → `host.name: "target-server" AND message: "vulnerabilities/xss_r"`
  - 注意：这样只是"访问了漏洞页面"，不是真实注入，作为训练数据标签偏弱。
- **重放带真实 payload 的攻击**（更符合 FYP 论述，推荐）：
  从 Kali 发真正的注入请求（URL 编码的 `' UNION SELECT ...`、`<script>alert(1)</script>`），
  并保持规则 query 不变或改为匹配编码后的特征。
- **Port Scan** 两种做法都需要先让扫描留下日志：在 target 上配 iptables
  LOG 规则加 `--log-prefix "PORTSCAN "`，再用 nmap 扫描。
- 规则的 `from: now-90s` 意味着只对新日志告警，历史日志不会补告警，
  所以改完规则后需要**重新发起攻击**才会产生告警。

---

## 2026-07-20 — 用真实工具打 DVWA 的攻击脚本（替代手写假 payload）

### 做了什么

新增 `lab/` 目录，用业界标准工具对隔离靶场 DVWA 产生六种真实攻击流量，
让 ELK 检测规则命中真攻击而非手写假 payload：

- `lab/attack_dvwa.sh`（Kali 端）：SQLi=sqlmap（真实 boolean/error/UNION 注入）、
  XSS/CmdInj/FI=curl 发 DVWA 各模块真实 payload、SSH=hydra 爆破、Scan=nmap。
  保留三攻击者 IP 的 aliasing（.104 SQLi+FI / .150 XSS+CmdInj / .151 SSH+Scan），
  用单条 `ip route replace <target> src <alias>` 统一控制每一阶段所有工具的源 IP
  （sqlmap/hydra/nmap -sT 都走 OS socket，无需各自的 source-bind 参数）。
  含 DVWA 登录+降 security 到 low、私网地址安全校验、`--only`/`--yes` 参数、
  退出时清理别名与路由。
- `lab/target_setup.sh`（Target 端，跑一次）：加 iptables recent 模块规则，
  对扫描式的 SYN 突发打 `--log-prefix "PORTSCAN "`，让 nmap 留痕；含持久化和
  filebeat 采集 kern.log 的说明。
- `lab/README_lab.md`：部署步骤 + 六条检测规则的推荐 KQL query。

### 关键决策：规则匹配 URL 路径而非 payload 关键词

Apache 访问日志里的 payload 是 URL 编码的，`UNION SELECT` 记为 `UNION%20SELECT`，
ES 标准分词器在 `%20` 处断词，`match_phrase "UNION SELECT"` 匹配不上。改为匹配
`vulnerabilities/sqli` 等 URL 路径（日志里永远明文），配合 sqlmap 的真实注入流量，
既稳定命中又不失真（此时匹配路径命中的确实是真攻击，不是页面访问）。

### 验证

- `bash -n` 两个脚本语法均通过。
- 实际攻击需在 Kali/Target VM 上跑（本机无靶场，无法端到端执行）。

---

## 2026-07-20 — 数据刷新加速 + 全站事件筛选栏统一

### 做了什么

1. **scheduler 轮询 60s → 15s**（settings.py 默认值 + .env + .env.example）。
2. **Dashboard 前端自动刷新 30s → 10s，且刷新当前所在页**：新 `refreshActive()`
   每 10 秒按 `window._activePage` 重新拉取当前页数据（dashboard 的 KPI/列表，
   或 All Events / Approval / Chains 等列表页），不用手动刷新。导航 `go()` 记录
   当前页并暴露 `window._pageLoaders` 供定时器复用。
3. **删掉 Reports 页那句** "Every event has its own incident report..."。
4. **Human Approval 加筛选栏**：Search（IP/攻击类型/事件ID，客户端过滤）+
   From/To（日期+时间）+ Apply/Clear，与 Reports 页一致。
5. **全站"事件筛选 Apply"统一**：抽出共享辅助
   `dtBound()`/`dtSync()`/`dtRangeParts()`（读日期+时间 → API 边界、min/max 联动、
   构造 ?from=&to= 并校验 from≤to）。Dashboard 顶栏、All Events、Human Approval、
   Attack Chain、Reports 五处筛选栏全部改成同一套"Search + From(date&time) +
   To(date&time) + Apply + Clear"结构与行为；All Events 的 Reset 改名 Clear，
   日期框由 date 升级为 date+time；Attack Chain 的 From/To 从死控件变为客户端
   按时间区间重叠过滤链。

### 遇到的问题 & 怎么解决

| 问题 | 解决 |
|---|---|
| 各页筛选栏结构/行为不一致（date-only vs date+time、Reset vs Clear、Approval 无筛选） | 统一到共享 `dt*` 辅助 + 同一套 HTML 结构，五页一致 |
| `/api/chains` 无日期参数 | Attack Chain 的日期区间改为客户端按 first_seen/last_seen 与所选区间重叠判断 |
| 自动刷新只刷 dashboard，切到别的页就不动 | 定时器改为刷新 `window._activePage` 对应的 loader |

### 验证结果

- `pytest` 5 个全过。
- 带会话的结构化验证脚本全绿：10s 刷新已接（refreshActive/10000，旧 30000 已移除、
  _pageLoaders 暴露）；Reports 说明已删；三个共享 dt 辅助就位；Human Approval /
  All Events / Attack Chain / Dashboard 五处新筛选 id 全部存在、旧 id（alertsFrom/
  dateFrom 等）已消失、Reset 已改 Clear；自动刷新命中的 /api/dashboard、/api/events、
  /api/events?status=awaiting、/api/chains 认证后均 200。

### 如何验证自动刷新生效（交给用户）

见下方回复。

---

## 2026-07-20 — 源IP黑名单过滤噪音 + 回车搜索 + "最后更新"实时指示器

### 做了什么

1. **源IP黑名单**（要求：过滤主机/本机噪音，可配置，blacklist 非 whitelist）：
   - settings 新增 `SOURCE_IP_BLACKLIST`，默认 `127.0.0.0/8,::1,192.168.56.1`
     （loopback + VirtualBox host-only 网关＝主机自己）。逗号分隔，支持单个 IP
     或 CIDR 段。
   - `siem_service` 用 `ipaddress` 解析黑名单，`_is_blacklisted(ip)` 判定；
     在 `_query_alerts` 里**提取源IP之后、聚合成事件之前**丢弃黑名单告警
     （threshold 告警回查恢复出的 IP 若命中黑名单也一并丢），并打日志
     "dropped N blacklisted-source alert(s)"。scheduler 之后不会再生成这些噪音。
   - 新增 `scripts/purge_blacklisted_events.py` 清理黑名单生效前已入库的噪音事件
     （连同其报告/决策/封禁），支持 `--dry-run`。
2. **Human Approval 搜索框支持回车**：`apprSearch` 加 `onkeydown` Enter→filterApprove
   （原有 oninput 实时过滤保留）。
3. **"最后更新于 HH:MM:SS" 实时指示器**：header 右侧加黄色 LIVE 药丸 + 脉冲绿点 +
   `updated HH:MM:SS`，每次自动刷新（10s）跳一次并闪一下；导航切页、初始加载也更新。
   `markRefreshed()` 由 `refreshActive()`、`go()`、初始 DOMContentLoaded 调用。

### 遇到的问题 & 怎么解决

| 问题 | 解决 |
|---|---|
| 图里 CyREN 把 192.168.56.1（主机网关）和 127.0.0.1（localhost）的 Port Scanning 当成攻击事件 | 加源IP黑名单在聚合前丢弃；清理脚本删掉已入库的 7 个噪音事件（127.0.0.1×1、192.168.56.1×6） |
| Kibana ~9417 告警 vs CyREN 21/14 事件的疑虑 | 正常：CyREN 按 (source_ip, rule) 聚合 + 有抓取窗口 + 现在过滤噪音，不是一告警一事件 |

### 验证结果

- `pytest` 5 个全过。
- `_is_blacklisted` 单测：127.0.0.1 / 192.168.56.1 → True；.104/.150/.151 / 空 / unknown → False。
- purge 脚本删掉 7 个噪音事件，剩 14 个全部来自真实攻击者。
- 起真实 app 认证后验证：`/api/events` 的源IP只剩 192.168.56.104/150/151，
  无 127.0.0.1 / 192.168.56.1；header live 指示器 + markRefreshed 接线到位；
  apprSearch 回车已接。

---

## 2026-07-20 — 一批 UI/数据修复：header 布局、汉堡菜单、响应式、邮件带链接、清噪音

回应用户 9 点反馈（含几个"是什么意思"的提问）。

### 做了什么

1. **Header 布局（#1）**：把搜索框和 LIVE 指示器包进 `.header-right` 右对齐组，
   搜索紧挨在 LIVE 药丸左边；汉堡按钮放最左。
2. **汉堡菜单开关侧栏（#8）**：header 左侧加汉堡按钮，`toggleSidebar()` 切换
   `body.sidebar-hidden`（桌面直接收起侧栏，移动端为抽屉滑入 + 半透明遮罩）。
3. **响应式设计（#9）**：加媒体查询——≤1100px header 紧凑、搜索自适应；
   ≤900px 侧栏变固定抽屉（默认收起，汉堡打开，点菜单项/遮罩关闭），header 换行；
   ≤560px LIVE 只显示时间。表格本就有 `.table-responsive` 横向滚动，KPI 卡片
   Bootstrap 栅格自动堆叠。
4. **All Events 去掉没用的勾选框列（#3）**：那列原是"批量操作"的占位，从未接线，
   删掉表头/行/colspan（避免误导；需要批量操作可另提）。
5. **分页可翻（#4）**：Rows 选择器加 `10`。原因是当前仅 14 个事件，25/页只有 1 页
   所以"翻不了"，选 10/页即有 2 页；分页逻辑本身没问题。
6. **邮件真发 + 带直达链接（#7）**：`email_service` 重写为 HTML 邮件，含
   "Open this incident in CyREN →" 按钮（链接 `APP_BASE_URL/#ip=<ip>`）；
   `build_alert_email(state)` 生成主题/正文；SMTP 未配置时把完整邮件（含链接）
   打到日志，配置后真发。ResponseAgent 高风险封禁后总会触发（不再因缺配置静默跳过）。
   前端加 `#ip=` 深链处理：邮件点进来自动跳到该源 IP 的事件。新增 `APP_BASE_URL` 配置。
7. **清噪音 + 减少 unknown（#2/#5）**：拓宽 threshold 告警的源日志回查窗口
   （`since||-10m` ~ `until||+2m`），减少 SSH 这类归因失败的 unknown；purge 脚本
   扩展为同时清理黑名单/unknown 的**事件和攻击链**。已清掉 unknown 事件 #23 和
   192.168.56.1 的噪音链，现为 14 事件 / 2 条真实链（.104、.151）。

### 回答用户的三个提问

- **#3 勾选框**：All Events 第一列的勾选框是"批量选择"占位，从没接功能——已删除。
- **#5 Unknown**：那条是 SSH 暴力破解（threshold 规则不带源 IP），回查原始日志时
  时间窗太窄没命中而归因失败。已拓宽窗口降低复发，并删掉那条无源事件。
- **#6 攻击链图**：SVG 里每个圆点是攻击链的一个阶段（按时间从左到右、颜色随风险
  绿→黄→红），圆点上方是攻击类型、下方是 kill-chain 阶段名（Recon/Initial Access/
  Execution…），虚线圆点是"预测的下一阶段"。连线表示同一源 IP 的攻击按时间推进。

### 验证结果

- `pytest` 5 个全过。
- 起真实 app 认证后结构校验全绿：header-right 分组且搜索在 LIVE 左侧、汉堡+overlay+
  toggleSidebar 就位、900px 抽屉媒体查询存在、勾选框已删、10 行选项在、`#ip=` 深链
  处理在；`/api/events` 源 IP 只剩 .104/.150/.151（无 unknown/噪音），链无噪音。
- `build_alert_email` 生成的邮件含 `/#ip=<ip>` 链接；SMTP 未配置时 `send_alert_email`
  记录完整内容并返回 False。

### 遗留 / 需用户侧配合

- **邮件真实投递**需在 `.env` 填 `SMTP_HOST/USER/PASSWORD/ALERT_EMAIL_TO`；未填时
  只在控制台记录邮件内容（含链接）。`APP_BASE_URL` 默认 localhost:5000，部署到 VM 时
  改成可访问的地址，邮件链接才对外可用。
- 响应式需人工在浏览器缩放/DevTools 设备模式下核验（in-app 浏览器禁访问 localhost）。
- 多数真实攻击事件被分类为 low（triage 置信度低），属模型问题，待用更多标注数据重训。

---

# ===== FILE: README.md =====

# CyREN

**Automating SOC Incident Response with Multi-Agent AI**

CyREN is an open-source multi-agent system that automates SOC incident response
for small and medium enterprises, as an affordable alternative to commercial
SOAR platforms. It reads alerts from an ELK Stack, triages them with an XGBoost
classifier, investigates them with an LLM grounded in the MITRE ATT&CK knowledge
base, reconstructs multi-stage attacks, and responds according to risk tier,
with a human-in-the-loop for uncertain cases.

---

## What is in this repository

The core pipeline is **implemented**: the validated FYP1 prototype logic
(Elasticsearch alert fetching, XGBoost triage, LLM investigation, kill-chain
correlation, iptables response) has been migrated into this architecture.
Remaining `TODO (FYP2 implementation)` markers cover the increments: the full
MITRE ATT&CK corpus with Gemini embeddings, GraphRAG traversal, and the
external threat-intel providers. The original prototype is archived in
`../legacy/` for reference.

```
cyren/
├── run.py                     # start the web app
├── requirements.txt
├── .env.example               # copy to .env and fill in
├── config/
│   └── settings.py            # reads all config from .env
├── app/
│   ├── __init__.py            # Flask app factory
│   ├── agents/
│   │   ├── state.py           # shared pipeline state
│   │   ├── triage.py          # TriageAgent (XGBoost)
│   │   ├── investigation.py   # InvestigationAgent (Groq + GraphRAG/ChromaDB)
│   │   ├── correlation.py     # CorrelationAgent (NetworkX)
│   │   ├── response.py        # ResponseAgent (iptables + email + report)
│   │   └── pipeline.py        # LangGraph orchestration
│   ├── api/
│   │   ├── routes.py          # REST API the dashboard calls
│   │   └── auth.py            # login / logout
│   ├── models/
│   │   └── db.py              # database schema
│   ├── services/
│   │   ├── siem_service.py    # reads + aggregates alerts from Elasticsearch
│   │   ├── event_service.py   # persists pipeline results (Event/Chain/Block/Report)
│   │   ├── scheduler.py       # background polling loop (replaces legacy backend.py)
│   │   ├── report_service.py  # PDF incident reports
│   │   └── email_service.py   # notification email
│   └── templates/
│       └── index.html         # the dashboard frontend
├── scripts/
│   ├── seed.py                # create demo users + data
│   ├── train_triage.py        # train the XGBoost model
│   └── build_knowledge_base.py# build the MITRE ATT&CK ChromaDB
└── tests/
    └── test_pipeline.py       # pipeline smoke tests
```

---

## Quick start (runs with placeholder logic, no API keys needed)

```bash
# 1. create a virtual environment
python -m venv venv
source venv/bin/activate           # Windows: venv\Scripts\activate

# 2. install dependencies
pip install -r requirements.txt

# 3. configure
cp .env.example .env               # the defaults are fine for a first run

# 4. seed demo users and data
python scripts/seed.py

# 5. run
python run.py
```

Open <http://localhost:5000> and log in:

| Username    | Password        | Role    |
|-------------|-----------------|---------|
| `analyst01` | `Analyst@2026`  | Analyst |
| `manager01` | `Manager@2026`  | Manager |

At this point the dashboard is live and talking to the database. The four agents
run with fallback logic, so events route through the three tiers correctly even
before the real models are connected.

---

## Connecting the real components (FYP2)

Do these in any order. Each is independent; the app keeps working as you enable
them one at a time.

### 1. Elasticsearch (SIEM input) -- IMPLEMENTED

The query in `app/services/siem_service.py` targets the Kibana security alert
index (migrated from the validated FYP1 prototype). Just set
`ELASTICSEARCH_URL`, `ELASTICSEARCH_USER`, `ELASTICSEARCH_PASSWORD` and
`ELASTIC_ALERT_INDEX` in `.env`. Set `ENABLE_SCHEDULER=true` to poll and run
the pipeline automatically every `POLL_INTERVAL_SECONDS`.

### 2. XGBoost (triage) -- IMPLEMENTED

```bash
python scripts/train_triage.py     # trains + saves to data/models/triage_xgb.json
```

The script trains on the labelled attack / false-positive patterns from the
FYP1 lab (five features: rule, risk score, severity, payload keywords, log
volume), matching `app/agents/triage.py::_extract_features`. Once the model
file exists, `TriageAgent` loads it automatically; grow the dataset with the
Decision table labels as analysts approve / dismiss events.

> **Note on metrics:** report classification accuracy, not R². R² is a
> regression metric and does not apply to a classifier.

### 3. Groq + GraphRAG (investigation) -- LLM WIRED, GraphRAG PENDING

1. Put your `GROQ_API_KEY` in `.env` and the LLM analysis works end to end
   (grounded in a static rule -> MITRE technique map until the knowledge base
   is built).
2. Build the knowledge base (seeded with the six lab techniques):
   ```bash
   python scripts/build_knowledge_base.py
   ```
   FYP2 increment: load the full MITRE ATT&CK corpus and embed it with Gemini
   embeddings (`GEMINI_API_KEY`).
3. FYP2 increment: implement the GraphRAG traversal in
   `app/agents/investigation.py::_graphrag_retrieve` (currently plain vector
   search).

### 4. NetworkX (correlation) -- IMPLEMENTED

`CorrelationAgent` queries the `Event` table for earlier events from the same
source IP within the correlation window (default 180 days), orders them along
the kill chain, grades the chain (>=3 phases = CRITICAL), and predicts the
next stage. Chains are persisted to the `AttackChain` table.

### 5. iptables + email (response) -- IMPLEMENTED

On the **SIEM Server VM only**, set `ENABLE_IPTABLES=true` and configure the
`CYREN_BLOCK` chain. Blocks are idempotent (checked with `iptables -C` first)
and the dashboard unblock removes the rule again. Fill in the SMTP settings
for email notifications. Keep `ENABLE_IPTABLES=false` on your development
machine so it only simulates blocks.

### 6. Enrichment: threat intel, asset, vulnerability

These three add context that turns a raw classification into a prioritised
decision. They run **before** triage, so the risk tier already reflects them.

    danger = attack severity x asset criticality x exploitability x attacker reputation

**Threat Intelligence** (`app/enrichment/threat_intel.py`)
Dual-mode by design:
  - **Public IPs** query AbuseIPDB / VirusTotal / OTX. Put the keys in `.env`.
  - **Private IPs** (192.168.x / 10.x / 172.16-31.x) skip the external APIs,
    because those have no data on internal addresses and it wastes quota. They
    query the local feed instead: `data/threat_feed/blocklist.txt` plus an
    optional MISP instance. For the lab, add the internal IPs you want treated
    as known-bad to that file (the seed script pre-loads `.102` and `.107`).

**Asset Assessment** (`app/enrichment/asset_assessment.py`)
A simple asset inventory (IP -> name, criticality, owner, services). An attack
on a `critical` asset is escalated; an attack on a `low` spare box is not. This
is the capability SMEs most often lack. Populate it via the seed script or the
`/api/assets` endpoint.

**Vulnerability Assessment** (`app/enrichment/vuln_assessment.py`)
Holds the results of periodic scans (OpenVAS/Greenbone or `nmap --script
vulners`) keyed by IP. For each event it checks whether the target has a CVE
matching the attack type. Import scan results with:

    python scripts/import_vuln_scan.py <scan.xml>

**Enrichment API endpoints:**

| Method | Endpoint                     | Purpose                     |
|--------|------------------------------|-----------------------------|
| GET    | `/api/assets`                | Asset inventory             |
| GET    | `/api/vulnerabilities?ip=`   | Known vulnerabilities       |
| GET    | `/api/threat-intel/<ip>`     | Live reputation lookup      |

---

## The pipeline

```
ELK event (aggregated by source IP + rule)
        │
        ▼
   ┌─────────┐  low risk
   │ Triage  │ ──────────────┐
   │ XGBoost │               │
   └────┬────┘               │
        │ high | uncertain   │
        ▼                    │
 ┌───────────────┐           │
 │ Investigation │           │
 │ Groq+GraphRAG │           │
 └───────┬───────┘           │
         ▼                   │
   ┌─────────────┐           │
   │ Correlation │           │
   │  NetworkX   │           │
   └──────┬──────┘           │
          ▼                  ▼
      ┌──────────────────────────┐
      │        Response          │
      │  high      → block + email + report
      │  uncertain → human approval queue
      │  low       → log only
      └──────────────────────────┘
```

---

## API reference

All endpoints require a login session (cookie based).

| Method | Endpoint                        | Purpose                          |
|--------|---------------------------------|----------------------------------|
| POST   | `/api/login`                    | Log in                           |
| POST   | `/api/logout`                   | Log out                          |
| GET    | `/api/dashboard`                | Dashboard summary                |
| GET    | `/api/events`                   | List events (`?risk=&status=&ip=`)|
| GET    | `/api/events/<id>`              | Event detail                     |
| POST   | `/api/events/<id>/decision`     | Approve / dismiss                |
| GET    | `/api/chains`                   | Attack chains                    |
| GET    | `/api/chains/<id>`              | One chain                        |
| GET    | `/api/blocked`                  | Firewall blocks                  |
| POST   | `/api/blocked/<id>/unblock`     | Unblock an IP                    |
| GET    | `/api/reports`                  | Incident reports                 |
| GET    | `/api/users`                    | User management (manager only)   |
| POST   | `/api/ingest`                   | Run one event through the pipeline|

---

## Testing

```bash
python -m pytest
```

The smoke tests confirm that events route into the correct tier and that the
response actions match. They pass before the real models are connected, so you
can use them as a regression check as you build.

---

## Lab environment

Three VirtualBox VMs, matching the project design:

| VM            | OS             | Role                                          |
|---------------|----------------|-----------------------------------------------|
| SIEM Server   | Ubuntu 22.04   | Docker ELK stack, runs CyREN, iptables enabled|
| Target Server | Ubuntu         | Apache / MySQL / SSH / DVWA (the victim)      |
| Kali Linux    | Kali           | Attacker, IP aliases to simulate many sources |

---

# ===== FILE: app/services/siem_service.py =====

```python
"""
SIEM service: reads alerts from Elasticsearch and aggregates them into events.

Aggregation rule (matches Chapter 3): raw logs sharing the same source IP and
the same detection rule become one event, with log_count recording how many
raw entries were folded in.

The query targets the Kibana security alert index (default
`.alerts-security.alerts-default`), filtering on documents that carry
`kibana.alert.rule.name` -- the same query the validated prototype used.
"""
import ipaddress
import logging
import re
from collections import Counter, defaultdict

from config.settings import settings

try:
    from elasticsearch import Elasticsearch
except ImportError:
    Elasticsearch = None

log = logging.getLogger(__name__)

# fallback source-IP extraction from the log message, for alert documents that
# do not carry a parsed source.ip field (e.g. custom Filebeat log rules)
_IP_RE = re.compile(r"\b(\d{1,3}(?:\.\d{1,3}){3})\b")
# "Failed password for invalid user x from 192.168.56.104 port 22" -> the
# attacker is the address after "from", not any other address on the line
_FROM_IP_RE = re.compile(r"\bfrom (\d{1,3}(?:\.\d{1,3}){3})\b")

_SEVERITY_RANK = {"low": 1, "medium": 2, "high": 3, "critical": 4}


def _parse_blacklist(raw: str):
    """Parse SOURCE_IP_BLACKLIST into (exact_ips, networks)."""
    exact, nets = set(), []
    for item in (raw or "").split(","):
        item = item.strip()
        if not item:
            continue
        if "/" in item:
            try:
                nets.append(ipaddress.ip_network(item, strict=False))
            except ValueError:
                log.warning("[siem] ignoring invalid blacklist CIDR: %r", item)
        else:
            exact.add(item)
    return exact, nets


_BL_EXACT, _BL_NETS = _parse_blacklist(getattr(settings, "SOURCE_IP_BLACKLIST", ""))


def _is_blacklisted(ip: str) -> bool:
    """True if this source IP is noise (loopback, host gateway, ...)."""
    if not ip or ip == "unknown":
        return False
    if ip in _BL_EXACT:
        return True
    if _BL_NETS:
        try:
            addr = ipaddress.ip_address(ip)
            return any(addr in net for net in _BL_NETS)
        except ValueError:
            return False
    return False


def _get(source: dict, dotted: str, default=None):
    """Read a field that may be stored flat ('kibana.alert.rule.name') or
    nested ({'kibana': {'alert': {'rule': {'name': ...}}}})."""
    if dotted in source:
        return source[dotted]
    node = source
    for part in dotted.split("."):
        if not isinstance(node, dict) or part not in node:
            return default
        node = node[part]
    return node


def _ip_from_message(message: str, host_ips: set) -> str:
    """Pull the attacker address out of a raw log line."""
    if not message:
        return ""
    # sshd lines name the attacker after "from"; prefer that over any other
    # address on the line (the target's own IP can appear too)
    match = _FROM_IP_RE.search(message)
    if match and match.group(1) not in host_ips:
        return match.group(1)
    for candidate in _IP_RE.findall(message):
        if candidate not in host_ips:
            return candidate
    return ""


def _extract_source_ip(source: dict, message: str) -> str:
    ip = _get(source, "source.ip") or _get(source, "kibana.alert.original_event.source.ip")
    if ip:
        return ip
    host_ip = _get(source, "host.ip")
    host_ips = set(host_ip if isinstance(host_ip, list) else [host_ip] if host_ip else [])
    return _ip_from_message(message, host_ips) or "unknown"


class SiemService:
    def __init__(self):
        self.es = None
        self._source_cache = {}
        if Elasticsearch is None:
            log.warning("[siem] elasticsearch package unavailable; running without a SIEM.")
            return
        try:
            self.es = Elasticsearch(
                settings.ELASTICSEARCH_URL,
                basic_auth=(settings.ELASTICSEARCH_USER, settings.ELASTICSEARCH_PASSWORD),
            )
        except Exception as exc:
            log.error("[siem] could not connect to %s: %s", settings.ELASTICSEARCH_URL, exc)
            self.es = None

    def _source_docs_for_rule(self, alert_source: dict, since: str, until: str) -> list:
        """Fetch the raw log documents a rule fired on.

        Threshold rules aggregate on a field (here host.name) and the alert
        they emit carries only that aggregation key -- no message, no
        source.ip. To recover the attacker address we re-run the rule's own
        query against its own index over the alert's time window and read the
        originating log lines.
        """
        params = _get(alert_source, "kibana.alert.rule.parameters") or {}
        query = params.get("query")
        index = params.get("index") or _get(alert_source, "kibana.alert.rule.indices")
        if not query or not index:
            return []
        if isinstance(index, str):
            index = [index]

        cache_key = (",".join(index), query, since, until)
        if cache_key in self._source_cache:
            return self._source_cache[cache_key]

        try:
            resp = self.es.search(
                index=",".join(index),
                size=200,
                sort=[{"@timestamp": {"order": "asc"}}],
                query={"bool": {"filter": [
                    {"query_string": {"query": query}},
                    {"range": {"@timestamp": {"gte": since, "lte": until}}},
                ]}},
            )
            docs = [h["_source"] for h in resp["hits"]["hits"]]
        except Exception as exc:
            log.warning("[siem] could not read source logs for rule query %r: %s", query, exc)
            docs = []

        self._source_cache[cache_key] = docs
        return docs

    def _enrich_from_source_logs(self, alert_source: dict) -> tuple:
        """Return (source_ip, sample_messages) recovered from the raw logs."""
        threshold = _get(alert_source, "kibana.alert.threshold_result") or {}
        since = threshold.get("from") or _get(alert_source, "kibana.alert.original_time")
        until = _get(alert_source, "@timestamp")
        if not since or not until:
            return "", []

        # Widen the window with Elasticsearch date math: a threshold rule's
        # window can be just a few seconds, and the originating log lines may
        # sit slightly outside it, which used to leave the source IP "unknown".
        docs = self._source_docs_for_rule(alert_source, since + "||-10m", until + "||+2m")
        if not docs:
            return "", []

        host_ip = _get(alert_source, "host.ip")
        host_ips = set(host_ip if isinstance(host_ip, list) else [host_ip] if host_ip else [])

        messages, ips = [], Counter()
        for doc in docs:
            msg = (_get(doc, "message") or "")[:500]
            if msg:
                messages.append(msg)
            ip = _get(doc, "source.ip") or _ip_from_message(msg, host_ips)
            if ip:
                ips[ip] += 1
        # the address responsible for most of the lines in the window
        return (ips.most_common(1)[0][0] if ips else ""), messages[:50]

    def _query_alerts(self, size: int = 5000, hours: int = None) -> list:
        """
        Query the Kibana security alert index and normalise each hit into
        {id, source_ip, dest_ip, rule, severity, risk_score, message, timestamp}.
        """
        if self.es is None:
            return []   # skeleton mode
        hours = hours or settings.FETCH_WINDOW_HOURS
        self._source_cache = {}
        try:
            resp = self.es.search(
                index=settings.ELASTIC_ALERT_INDEX,
                size=size,
                sort=[{"@timestamp": {"order": "desc"}}],
                query={"bool": {"filter": [
                    {"range": {"@timestamp": {"gte": f"now-{hours}h", "lte": "now"}}},
                    {"exists": {"field": "kibana.alert.rule.name"}},
                ]}},
            )
        except Exception as exc:
            log.error("[siem] Elasticsearch query failed: %s", exc)
            return []

        alerts = []
        enriched = 0
        dropped = Counter()
        for hit in resp["hits"]["hits"]:
            source = hit["_source"]
            message = (_get(source, "message") or "")[:500]
            source_ip = _extract_source_ip(source, message)
            extra_logs = []

            # threshold alerts arrive without the original document: go back to
            # the raw logs for the attacker address and a real log sample
            if source_ip == "unknown":
                recovered_ip, sample = self._enrich_from_source_logs(source)
                if recovered_ip:
                    source_ip = recovered_ip
                    enriched += 1
                if sample:
                    extra_logs = sample
                    if not message:
                        message = sample[0][:500]

            # drop noise from loopback / the host-only gateway before it ever
            # becomes an event (configurable via SOURCE_IP_BLACKLIST)
            if _is_blacklisted(source_ip):
                dropped[source_ip] += 1
                continue

            alerts.append({
                "id": hit["_id"],
                "timestamp": _get(source, "@timestamp", ""),
                "rule": _get(source, "kibana.alert.rule.name", ""),
                "severity": _get(source, "kibana.alert.severity", "") or "",
                "risk_score": _get(source, "kibana.alert.risk_score", 0) or 0,
                "source_ip": source_ip,
                "dest_ip": _get(source, "destination.ip") or _get(source, "host.name", ""),
                "message": message,
                "source_logs": extra_logs,
            })

        by_rule = Counter(a["rule"] for a in alerts)
        log.info("[siem] fetched %d alert(s) from the last %dh across %d rule(s): %s",
                 len(alerts), hours, len(by_rule), dict(by_rule))
        if enriched:
            log.info("[siem] recovered the source IP from raw logs for %d alert(s)", enriched)
        if dropped:
            log.info("[siem] dropped %d blacklisted-source alert(s): %s",
                     sum(dropped.values()), dict(dropped))
        unresolved = sum(1 for a in alerts if a["source_ip"] == "unknown")
        if unresolved:
            log.warning("[siem] %d alert(s) still have no source IP; the rule emits no "
                        "message and its source logs could not be read", unresolved)
        return alerts

    def fetch_aggregated_events(self, hours: int = None) -> list:
        """Group raw alerts by (source_ip, rule) into events ready for triage."""
        raw = self._query_alerts(hours=hours)
        buckets = defaultdict(list)
        for alert in raw:
            key = (alert.get("source_ip", "unknown"), alert.get("rule", "unknown"))
            buckets[key].append(alert)

        events = []
        for (source_ip, rule), alerts in buckets.items():
            severity = max((a.get("severity") or "" for a in alerts),
                           key=lambda s: _SEVERITY_RANK.get(s.lower(), 0))
            timestamps = sorted(a.get("timestamp", "") for a in alerts if a.get("timestamp"))

            # prefer the real log lines recovered from the source index; fall
            # back to the alert messages for rules that carry them
            samples, seen = [], set()
            for alert in alerts:
                for line in (alert.get("source_logs") or []) or [alert.get("message", "")]:
                    if line and line not in seen:
                        seen.add(line)
                        samples.append(line)
                if len(samples) >= 50:
                    break

            events.append({
                "source_ip": source_ip,
                "dest_ip": alerts[0].get("dest_ip"),
                "rule": rule,
                "log_count": len(alerts),
                "raw_logs": samples[:50],
                "severity": severity,
                "risk_score": max(a.get("risk_score", 0) or 0 for a in alerts),
                "first_seen": timestamps[0] if timestamps else "",
                "last_seen": timestamps[-1] if timestamps else "",
            })

        log.info("[siem] aggregated into %d event(s): %s", len(events),
                 [(e["source_ip"], e["rule"], e["log_count"]) for e in events])
        return events


siem_service = SiemService()
```

---

# ===== FILE: app/agents/triage.py =====

```python
"""
TriageAgent
===========
Role in the pipeline: the first agent. It takes an aggregated event (many raw
logs already grouped by source IP + detection rule) and produces a confidence
score with the XGBoost classifier, then routes the event into one of three
tiers using the thresholds from settings.

    confidence >= HIGH_RISK_THRESHOLD  -> "high"       (auto response downstream)
    confidence <= LOW_RISK_THRESHOLD   -> "low"        (log only)
    otherwise                          -> "uncertain"  (human approval)

Feature vector (must match scripts/train_triage.py):
    [rule_encoded, risk_score, severity_num, has_keyword, request_count]

The model is trained with binary:logistic, so Booster.predict() returns the
true-positive probability directly; that is the confidence routed on. Until
the model file exists the agent falls back to a log-volume heuristic so the
skeleton stays runnable.
"""
import json
import os
import numpy as np

from config.settings import settings
from app.agents.state import AgentState

try:
    import xgboost as xgb
except ImportError:      # allows the skeleton to run before xgboost is installed
    xgb = None


# payload keywords that indicate a genuine attack string in the raw logs
# (same indicator set the FYP1 prototype validated)
ATTACK_KEYWORDS = [
    "union select", "or 1=1", "' or '", "<script", "onerror=",
    "whoami", "etc/passwd", "/bin/bash", "nmap", "masscan",
    "failed password", "authentication failure",
]

SEVERITY_NUM = {"low": 1, "medium": 2, "high": 3, "critical": 4}

# must match the training columns in scripts/train_triage.py
FEATURE_NAMES = ["rule_encoded", "risk_score", "severity_num", "has_keyword", "request_count"]

# substring -> attack type; checked in order, so put the most specific first
ATTACK_TYPE_RULES = [
    ("sql injection", "SQL Injection"),
    ("sqli", "SQL Injection"),
    ("xss", "Cross-Site Scripting"),
    ("command injection", "Command Injection"),
    ("cmd", "Command Injection"),
    ("file inclusion", "File Inclusion"),
    ("lfi", "File Inclusion"),
    ("port scan", "Port Scanning"),
    ("scan", "Port Scanning"),
    ("brute force", "SSH Brute Force"),
    ("ssh", "SSH Brute Force"),
]


class TriageAgent:
    def __init__(self):
        self.model = None
        self.rule_map = {}
        self._load_model()

    def _load_model(self):
        path = settings.XGBOOST_MODEL_PATH
        if xgb is not None and os.path.exists(path):
            self.model = xgb.Booster()
            self.model.load_model(path)
        if os.path.exists(settings.RULE_MAP_PATH):
            try:
                with open(settings.RULE_MAP_PATH) as fh:
                    self.rule_map = json.load(fh)
            except (json.JSONDecodeError, OSError):
                self.rule_map = {}

    # ------------------------------------------------------------------
    def _extract_features(self, state: AgentState) -> np.ndarray:
        """Build the 5-feature vector the model was trained on."""
        rule_encoded = self.rule_map.get(state.get("rule", ""), 0)
        risk_score = float(state.get("risk_score", 0) or 0)
        severity_num = SEVERITY_NUM.get((state.get("severity") or "").lower(), 1)

        haystack = " ".join(state.get("raw_logs", [])).lower()
        has_keyword = 1 if any(kw in haystack for kw in ATTACK_KEYWORDS) else 0

        request_count = state.get("log_count", 0)

        return np.array(
            [[rule_encoded, risk_score, severity_num, has_keyword, request_count]],
            dtype=float,
        )

    def _classify_attack_type(self, state: AgentState) -> str:
        """Derive the attack type from the detection rule that fired."""
        rule = (state.get("rule") or "").lower()
        for key, name in ATTACK_TYPE_RULES:
            if key in rule:
                return name
        return "Unclassified"

    def _route(self, confidence: float) -> str:
        if confidence >= settings.HIGH_RISK_THRESHOLD:
            return "high"
        if confidence <= settings.LOW_RISK_THRESHOLD:
            return "low"
        return "uncertain"

    def _adjust_for_context(self, state: AgentState, risk: str) -> str:
        """
        Nudge the risk tier using enrichment signals available at triage time.
        A critical asset or a known-bad source escalates; nothing de-escalates
        an already-high verdict.

        The enrichment is optional here: if it has not run yet (e.g. asset
        table empty), the signals are neutral and risk is unchanged.
        """
        order = ["low", "uncertain", "high"]
        idx = order.index(risk)

        # asset criticality: read lightweight signal without a full lookup
        asset = state.get("asset") or {}
        idx += asset.get("risk_adjustment", 0)

        # known-bad source escalates by one tier
        ti = state.get("threat_intel") or {}
        if ti.get("known_bad"):
            idx += 1

        idx = max(0, min(len(order) - 1, idx))
        return order[idx]

    # ------------------------------------------------------------------
    def run(self, state: AgentState) -> AgentState:
        features = self._extract_features(state)

        if self.model is not None:
            dmatrix = xgb.DMatrix(features, feature_names=FEATURE_NAMES)
            confidence = float(self.model.predict(dmatrix)[0])
        else:
            # PLACEHOLDER verdict so the pipeline works before the model exists.
            # Simple heuristic on log volume; replace once the model is trained.
            lc = state.get("log_count", 0)
            confidence = min(0.99, 0.30 + lc / 500.0)

        state["confidence"] = round(confidence, 2)
        state["attack_type"] = self._classify_attack_type(state)
        base_risk = self._route(confidence)
        state["risk"] = self._adjust_for_context(state, base_risk)
        return state


# LangGraph node wrapper
_triage = TriageAgent()
def triage_node(state: AgentState) -> AgentState:
    return _triage.run(state)
```

---

# ===== FILE: app/agents/investigation.py =====

```python
"""
InvestigationAgent
==================
Role in the pipeline: the second agent. For an event that is not clearly low
risk, it (1) retrieves the most relevant MITRE ATT&CK techniques from ChromaDB
using GraphRAG, then (2) asks Llama 4 Scout (via Groq) to explain the event in
natural language, grounded in those retrieved techniques.

Output written to state:
    mitre_techniques : list[str]
    llm_summary      : {"what_happened", "what_could_go_wrong", "what_should_be_done"}

TODO (FYP2 implementation):
    1. Build the ChromaDB knowledge base with scripts/build_knowledge_base.py
       (embed the MITRE ATT&CK corpus with Gemini embeddings).
    2. Implement the graph traversal in `_graphrag_retrieve` (your GraphRAG
       logic over the technique/tactic graph). The stub below does a plain
       vector similarity search as a fallback.
    3. Tune the prompt in `_build_prompt`.
"""
import json
import logging

from config.settings import settings
from app.agents.state import AgentState

log = logging.getLogger(__name__)

# Import failures are recorded rather than swallowed: a broken dependency used
# to silently degrade every report to placeholder text with nothing in the logs
# to explain why.
try:
    from groq import Groq
    _GROQ_IMPORT_ERROR = None
except Exception as exc:                       # noqa: BLE001 - report any cause
    Groq = None
    _GROQ_IMPORT_ERROR = f"{type(exc).__name__}: {exc}"

try:
    import chromadb
    _CHROMA_IMPORT_ERROR = None
except Exception as exc:                       # noqa: BLE001
    chromadb = None
    _CHROMA_IMPORT_ERROR = f"{type(exc).__name__}: {exc}"


class InvestigationAgent:
    def __init__(self):
        self.groq = None
        self.llm_status = "not initialised"
        self._init_groq()
        self.collection = None
        self._load_collection()

    def _init_groq(self):
        """Build the Groq client, explaining loudly if we cannot."""
        if Groq is None:
            self.llm_status = f"groq package unavailable ({_GROQ_IMPORT_ERROR})"
        elif not settings.GROQ_API_KEY:
            self.llm_status = "GROQ_API_KEY is not set in .env"
        else:
            try:
                self.groq = Groq(api_key=settings.GROQ_API_KEY)
                self.llm_status = f"ready (model {settings.GROQ_MODEL})"
                log.info("InvestigationAgent: Groq client %s", self.llm_status)
                return
            except Exception as exc:           # noqa: BLE001
                self.llm_status = f"Groq client failed to start: {type(exc).__name__}: {exc}"
        log.warning("InvestigationAgent: LLM analysis disabled - %s. "
                    "Reports will contain placeholder text.", self.llm_status)

    def _load_collection(self):
        if chromadb is None:
            log.info("InvestigationAgent: chromadb unavailable (%s); using the static "
                     "MITRE fallback map.", _CHROMA_IMPORT_ERROR)
            return
        try:
            client = chromadb.PersistentClient(path=settings.CHROMA_PERSIST_DIR)
            self.collection = client.get_collection(settings.CHROMA_COLLECTION)
        except Exception as exc:               # noqa: BLE001
            self.collection = None   # knowledge base not built yet
            log.info("InvestigationAgent: MITRE knowledge base not available (%s); "
                     "using the static fallback map.", exc)

    # ------------------------------------------------------------------
    def _graphrag_retrieve(self, state: AgentState, k: int = 5) -> list:
        """
        TODO: real GraphRAG retrieval.
        Retrieve techniques related to this event, then expand along the
        technique -> tactic -> related-technique graph edges to gather context
        that a plain vector search would miss.

        The stub below does a plain similarity query as a fallback so the
        pipeline runs before GraphRAG is implemented.
        """
        if self.collection is None:
            # Fallback: static rule -> technique map validated in the FYP1
            # prototype, used until the ChromaDB knowledge base is built.
            fallback = {
                "SQL Injection": ["T1190 Exploit Public-Facing Application",
                                  "T1213 Data from Information Repositories"],
                "SSH Brute Force": ["T1110.001 Brute Force: Password Guessing",
                                    "T1078 Valid Accounts"],
                "Cross-Site Scripting": ["T1059.007 Command and Scripting Interpreter: JavaScript"],
                "Command Injection": ["T1059 Command and Scripting Interpreter"],
                "File Inclusion": ["T1005 Data from Local System"],
                "Port Scanning": ["T1046 Network Service Discovery"],
            }
            return fallback.get(state.get("attack_type", ""), [])

        query = f"{state.get('attack_type','')} {state.get('rule','')}"
        res = self.collection.query(query_texts=[query], n_results=k)
        docs = res.get("documents", [[]])[0]
        return docs

    def _build_prompt(self, state: AgentState, techniques: list) -> str:
        ti = state.get("threat_intel", {})
        asset = state.get("asset", {})
        vuln = state.get("vulnerability", {})
        return (
            "You are a SOC analyst assistant. Analyse the security event below "
            "using the provided context. Give particular weight to whether the "
            "target is a critical asset and whether it has a matching unpatched "
            "vulnerability, because those decide how urgent this is. Respond as "
            'strict JSON with keys "what_happened", "what_could_go_wrong", '
            '"what_should_be_done", and "urgency" (one of IMMEDIATE, HIGH, '
            "MEDIUM, LOW).\n\n"
            f"Event:\n"
            f"- Source IP: {state.get('source_ip')}\n"
            f"- Attack type: {state.get('attack_type')}\n"
            f"- Rule: {state.get('rule')}\n"
            f"- Log count: {state.get('log_count')}\n"
            f"- Sample logs: {json.dumps(state.get('raw_logs', [])[:5])}\n\n"
            f"MITRE ATT&CK context:\n{json.dumps(techniques)}\n\n"
            f"Threat intelligence on the source:\n"
            f"- Scope: {ti.get('scope')}, known bad: {ti.get('known_bad')}, "
            f"score: {ti.get('score')}, sources: {ti.get('sources')}\n\n"
            f"Target asset:\n"
            f"- Name: {asset.get('name')}, criticality: {asset.get('criticality')}, "
            f"owner: {asset.get('owner')}, services: {asset.get('services')}\n\n"
            f"Target vulnerabilities:\n"
            f"- Exploitable by this attack: {vuln.get('exploitable')}, "
            f"matching CVEs: {vuln.get('matching_cves')}, "
            f"total known: {vuln.get('vuln_count')}\n"
        )

    @staticmethod
    def _placeholder(reason: str) -> dict:
        """Used only when the LLM is genuinely unavailable. The reason is
        carried into the summary so the report and the logs say why."""
        return {
            "what_happened": f"AI analysis unavailable: {reason}",
            "what_could_go_wrong": "",
            "what_should_be_done": "",
            "urgency": "MEDIUM",
            "llm_error": reason,
        }

    def _ask_llm(self, prompt: str) -> dict:
        if self.groq is None:
            return self._placeholder(self.llm_status)

        try:
            resp = self.groq.chat.completions.create(
                model=settings.GROQ_MODEL,
                messages=[{"role": "user", "content": prompt}],
                temperature=0.2,
                response_format={"type": "json_object"},
            )
        except Exception as exc:               # noqa: BLE001
            # A failing API call must not take down the pipeline, but it must
            # be visible rather than looking like a normal empty analysis.
            reason = f"{type(exc).__name__}: {exc}"
            log.error("InvestigationAgent: Groq call failed - %s", reason)
            return self._placeholder(reason)

        content = ""
        try:
            content = resp.choices[0].message.content
            return json.loads(content)
        except (json.JSONDecodeError, AttributeError, IndexError):
            log.warning("InvestigationAgent: model did not return valid JSON; "
                        "storing the raw text.")
            return {"what_happened": content or "Model returned an empty response.",
                    "what_could_go_wrong": "", "what_should_be_done": "",
                    "urgency": "MEDIUM"}

    # ------------------------------------------------------------------
    def run(self, state: AgentState) -> AgentState:
        # low-risk events skip investigation to save LLM calls
        if state.get("risk") == "low":
            state["mitre_techniques"] = []
            state["llm_summary"] = {}
            return state

        techniques = self._graphrag_retrieve(state)
        prompt = self._build_prompt(state, techniques)
        summary = self._ask_llm(prompt)

        state["mitre_techniques"] = techniques
        state["llm_summary"] = summary
        return state


_investigation = InvestigationAgent()
def investigation_node(state: AgentState) -> AgentState:
    return _investigation.run(state)
```

---

# ===== FILE: app/agents/pipeline.py =====

```python
"""
The CyREN multi-agent pipeline, orchestrated with LangGraph.

Flow:

    ELK event
        |
        v
    [triage] --low--> [response] --> END     (log only, skip investigation)
        |
        | (high | uncertain)
        v
    [investigation]
        |
        v
    [correlation]
        |
        v
    [response] --> END

Usage:
    from app.agents.pipeline import run_pipeline
    final_state = run_pipeline(event_dict)
"""
from app.agents.state import AgentState
from app.agents.triage import triage_node
from app.agents.investigation import investigation_node
from app.agents.correlation import correlation_node
from app.agents.response import response_node

try:
    from langgraph.graph import StateGraph, END
    _HAS_LANGGRAPH = True
except ImportError:
    _HAS_LANGGRAPH = False


def enrich_node(state: AgentState) -> AgentState:
    """
    Run threat-intel / asset / vulnerability enrichment first, so Triage can use
    asset criticality and source reputation when it sets the risk tier, and so
    Investigation has the full context for the LLM. Enrichment must never break
    the pipeline, so failures fall through silently.
    """
    try:
        from app.enrichment import enrich_event
        return enrich_event(state)
    except Exception as exc:
        print(f"[pipeline] enrichment skipped: {exc}")
        return state


def _route_after_triage(state: AgentState) -> str:
    """Low-risk events skip investigation and correlation."""
    return "response" if state.get("risk") == "low" else "investigation"


def _build_graph():
    graph = StateGraph(AgentState)
    graph.add_node("enrich", enrich_node)
    graph.add_node("triage", triage_node)
    graph.add_node("investigation", investigation_node)
    graph.add_node("correlation", correlation_node)
    graph.add_node("response", response_node)

    graph.set_entry_point("enrich")
    graph.add_edge("enrich", "triage")
    graph.add_conditional_edges("triage", _route_after_triage,
                                {"investigation": "investigation", "response": "response"})
    graph.add_edge("investigation", "correlation")
    graph.add_edge("correlation", "response")
    graph.add_edge("response", END)
    return graph.compile()


_compiled = _build_graph() if _HAS_LANGGRAPH else None


def run_pipeline(event: dict) -> AgentState:
    """
    Run one event through the full pipeline and return the final state.

    `event` should contain at least: source_ip, dest_ip, rule, log_count, raw_logs
    """
    state: AgentState = dict(event)   # type: ignore

    if _compiled is not None:
        return _compiled.invoke(state)

    # Fallback if LangGraph is not installed: run the nodes in sequence.
    state = enrich_node(state)
    state = triage_node(state)
    if state.get("risk") != "low":
        state = investigation_node(state)
        state = correlation_node(state)
    state = response_node(state)
    return state
```

---

# ===== FILE: app/agents/correlation.py =====

```python
"""
CorrelationAgent
================
Role in the pipeline: the third agent. It decides whether this event is part of
a larger multi-stage attack from the same source, by linking it to earlier
events from the same IP and reconstructing the sequence as a graph with
NetworkX.

Output written to state:
    chain_id         : id of the attack chain this event belongs to (or None,
                       assigned by the persistence layer when the event is saved)
    is_multistage    : True if the chain now has more than one stage
    chain_stages     : ordered [{attack_type, phase, timestamp}, ...]
    chain_risk       : CRITICAL (>=3 phases) | HIGH (2) | MEDIUM (1)
    chain_assessment : human-readable summary
    predicted_next   : the next kill-chain stage to watch for (or None)
"""
from datetime import datetime, timedelta

from app.agents.state import AgentState

try:
    import networkx as nx
except ImportError:
    nx = None

# how far back to look when correlating (a slow attacker may span months)
CORRELATION_WINDOW_DAYS = 180

# kill-chain ordering + phase names (as validated in the FYP1 prototype)
KILL_CHAIN = {
    "Port Scanning":        (0, "Reconnaissance"),
    "SSH Brute Force":      (1, "Credential Access"),
    "SQL Injection":        (2, "Initial Access"),
    "Cross-Site Scripting": (2, "Initial Access"),
    "Command Injection":    (3, "Execution"),
    "File Inclusion":       (3, "Execution"),
    "Web Shell":            (4, "Persistence"),
}

# representative next stage for each kill-chain order, used for prediction
_NEXT_STAGE = {
    0: "Credential Access (e.g. SSH brute force)",
    1: "Initial Access (e.g. SQL injection / XSS)",
    2: "Execution (e.g. command injection / file inclusion)",
    3: "Persistence (e.g. web shell)",
}


def _order(attack_type: str) -> int:
    return KILL_CHAIN.get(attack_type, (99, "Unknown"))[0]


def _phase(attack_type: str) -> str:
    return KILL_CHAIN.get(attack_type, (99, "Unknown"))[1]


class CorrelationAgent:
    def __init__(self, event_repo=None):
        # event_repo lets tests inject a fake DB layer; by default the agent
        # queries the Event table directly (requires an app context).
        self.event_repo = event_repo

    def _fetch_prior_events(self, source_ip: str) -> list:
        """Prior events from this IP within the correlation window."""
        since = datetime.utcnow() - timedelta(days=CORRELATION_WINDOW_DAYS)
        if self.event_repo is not None:
            return self.event_repo.get_events_by_ip(source_ip, since=since)
        try:
            from app.models.db import Event
            rows = (Event.query
                    .filter(Event.source_ip == source_ip,
                            Event.last_seen >= since,
                            Event.status != "dismissed")
                    .all())
            return [{"attack_type": r.attack_type,
                     "timestamp": r.last_seen.isoformat() if r.last_seen else ""}
                    for r in rows]
        except Exception:
            return []   # no DB / no app context (e.g. unit tests)

    def _order_stages(self, events: list) -> list:
        return sorted(
            events,
            key=lambda e: (_order(e.get("attack_type")), e.get("timestamp") or ""),
        )

    def _build_graph(self, stages: list):
        if nx is None:
            return None
        g = nx.DiGraph()
        for i, stage in enumerate(stages):
            g.add_node(i, **stage)
            if i > 0:
                g.add_edge(i - 1, i)
        return g

    def _assess(self, phase_count: int) -> str:
        if phase_count >= 3:
            return ("Multi-stage attack detected. Attacker progressed through "
                    "multiple kill chain phases, indicating a sophisticated and "
                    "targeted attack campaign.")
        if phase_count >= 2:
            return ("Attack chain detected. Attacker used multiple techniques, "
                    "suggesting an active intrusion attempt.")
        return "Single-phase attack detected. Limited attack scope observed."

    # ------------------------------------------------------------------
    def run(self, state: AgentState) -> AgentState:
        source_ip = state.get("source_ip")
        prior = self._fetch_prior_events(source_ip)

        # include the current event as the newest stage
        current = {"attack_type": state.get("attack_type"),
                   "timestamp": state.get("last_seen") or datetime.utcnow().isoformat()}
        # de-duplicate: one stage per attack type
        by_type = {}
        for e in self._order_stages(prior + [current]):
            by_type.setdefault(e.get("attack_type"), e)
        stages = list(by_type.values())

        chain_stages = [{"attack_type": s.get("attack_type"),
                         "phase": _phase(s.get("attack_type")),
                         "timestamp": s.get("timestamp", "")}
                        for s in stages]
        phases = {s["phase"] for s in chain_stages}

        graph = self._build_graph(chain_stages)   # noqa: F841 (used when persisting)

        max_order = max((_order(s.get("attack_type")) for s in stages), default=99)
        state["chain_stages"] = chain_stages
        state["chain_risk"] = ("CRITICAL" if len(phases) >= 3
                               else "HIGH" if len(phases) >= 2 else "MEDIUM")
        state["chain_assessment"] = self._assess(len(phases))
        state["predicted_next"] = _NEXT_STAGE.get(max_order)
        state["is_multistage"] = len(chain_stages) > 1
        # chain_id is assigned by the persistence layer when the event is saved
        state["chain_id"] = None
        return state


_correlation = CorrelationAgent()
def correlation_node(state: AgentState) -> AgentState:
    return _correlation.run(state)
```

---

# ===== FILE: app/agents/response.py =====

```python
"""
ResponseAgent
=============
Role in the pipeline: the final agent. It acts on the event according to its
risk tier, which is the tiered response at the heart of CyREN:

    high      -> block the source IP (iptables) + email the analyst
    uncertain -> route to the Human Approval queue, take no action yet
    low       -> log only

Output written to state:
    action_taken : "blocked" | "awaiting_approval" | "logged"
    blocked      : bool
    report_path  : path to the generated PDF report (for high-risk events)

`ENABLE_IPTABLES` must stay false on the dev machine (blocks are simulated);
enable it only on the SIEM Server VM where the CYREN_BLOCK chain exists.
"""
import subprocess

from config.settings import settings
from app.agents.state import AgentState
from app.services.report_service import generate_report
from app.services.email_service import send_alert_email, build_alert_email


class ResponseAgent:
    def _rule_exists(self, ip: str) -> bool:
        """Check for an existing DROP rule so repeated blocks don't stack."""
        result = subprocess.run(
            ["iptables", "-C", settings.IPTABLES_CHAIN, "-s", ip, "-j", "DROP"],
            capture_output=True,
        )
        return result.returncode == 0

    def block_ip(self, ip: str) -> bool:
        """Add an iptables DROP rule for the source IP (idempotent)."""
        if not settings.ENABLE_IPTABLES:
            # dev/skeleton mode: pretend the rule was added
            print(f"[ResponseAgent] (simulated) would block {ip}")
            return True
        try:
            if self._rule_exists(ip):
                return True
            subprocess.run(
                ["iptables", "-A", settings.IPTABLES_CHAIN, "-s", ip, "-j", "DROP"],
                check=True, capture_output=True,
            )
            return True
        except (subprocess.CalledProcessError, FileNotFoundError) as exc:
            print(f"[ResponseAgent] iptables failed: {exc}")
            return False

    def unblock_ip(self, ip: str) -> bool:
        """Remove the DROP rule for an IP (used by the dashboard unblock)."""
        if not settings.ENABLE_IPTABLES:
            print(f"[ResponseAgent] (simulated) would unblock {ip}")
            return True
        try:
            subprocess.run(
                ["iptables", "-D", settings.IPTABLES_CHAIN, "-s", ip, "-j", "DROP"],
                check=True, capture_output=True,
            )
            return True
        except (subprocess.CalledProcessError, FileNotFoundError) as exc:
            print(f"[ResponseAgent] iptables unblock failed: {exc}")
            return False

    def _send_email(self, state: AgentState):
        # Build the HTML alert (with the direct "open in CyREN" link) and hand
        # it off. send_alert_email logs the full content when SMTP is unset, so
        # the notification is always visible even before SMTP is configured.
        subject, html = build_alert_email(state)
        to = settings.ALERT_EMAIL_TO or "soc-team@localhost"
        sent = send_alert_email(to=to, subject=subject, html_body=html)
        state["email_sent"] = sent

    # ------------------------------------------------------------------
    def run(self, state: AgentState) -> AgentState:
        risk = state.get("risk", "low")

        if risk == "high":
            blocked = self.block_ip(state.get("source_ip"))
            state["blocked"] = blocked
            state["action_taken"] = "blocked"
            self._send_email(state)
            # generate the report last so it reflects the actions taken
            state["report_path"] = generate_report(state)

        elif risk == "uncertain":
            state["blocked"] = False
            state["action_taken"] = "awaiting_approval"

        else:  # low
            state["blocked"] = False
            state["action_taken"] = "logged"

        return state


response_agent = ResponseAgent()
def response_node(state: AgentState) -> AgentState:
    return response_agent.run(state)
```

---

# ===== FILE: app/services/scheduler.py =====

```python
"""
Background scheduler: the automation loop that replaces the prototype's
standalone backend.py.

Every POLL_INTERVAL_SECONDS it:
    1. pulls aggregated events from Elasticsearch (siem_service),
    2. skips events whose (source_ip, rule) pair has no new raw logs since
       the last run (the DB is the dedup memory, replacing the prototype's
       analyzed_ids list),
    3. runs each new/updated event through the multi-agent pipeline,
    4. persists the result via event_service.

Enable with ENABLE_SCHEDULER=true. Runs as a daemon thread inside the Flask
process, so `python run.py` starts the whole system.
"""
import threading
import time
from datetime import datetime

from config.settings import settings


def _is_new_activity(existing, event) -> bool:
    """Should this aggregate be (re)analysed?

    Reprocess when more raw logs folded in *or* when the aggregate now
    extends past what we last saw. Comparing log_count alone is not enough:
    the fetch window slides, so old alerts age out as new ones arrive and the
    count can stay flat or even shrink while genuinely new activity happened.
    """
    if existing is None:
        return True
    if (event.get("log_count") or 0) > (existing.log_count or 0):
        return True
    last_seen = (event.get("last_seen") or "").replace("T", " ")[:19]
    known = existing.last_seen.isoformat().replace("T", " ")[:19] if existing.last_seen else ""
    return bool(last_seen and last_seen > known)


def _process_once(app) -> int:
    """One polling cycle; returns how many events were (re)analysed."""
    from app.agents.pipeline import run_pipeline
    from app.models.db import Event
    from app.services.event_service import persist_pipeline_result
    from app.services.siem_service import siem_service

    processed = 0
    with app.app_context():
        events = siem_service.fetch_aggregated_events()
        skipped = 0
        for event in events:
            existing = (Event.query
                        .filter_by(source_ip=event.get("source_ip"), rule=event.get("rule"))
                        .filter(Event.status != "dismissed")
                        .order_by(Event.id.desc())
                        .first())
            if not _is_new_activity(existing, event):
                skipped += 1
                continue

            print(f"[scheduler] analysing {event.get('rule')} from "
                  f"{event.get('source_ip')} ({event.get('log_count')} logs)")
            state = run_pipeline(event)
            persist_pipeline_result(state)
            processed += 1
        if skipped:
            print(f"[scheduler] {skipped} aggregate(s) unchanged, skipped")
    return processed


def _loop(app):
    print(f"[scheduler] started, polling every {settings.POLL_INTERVAL_SECONDS}s")
    while True:
        try:
            n = _process_once(app)
            if n:
                print(f"[scheduler] {datetime.now().strftime('%H:%M:%S')} "
                      f"processed {n} event(s)")
        except Exception as exc:
            print(f"[scheduler] cycle failed: {exc}")
        time.sleep(settings.POLL_INTERVAL_SECONDS)


def start_scheduler(app):
    """Start the polling loop in a daemon thread (call once per process)."""
    thread = threading.Thread(target=_loop, args=(app,), daemon=True,
                              name="cyren-scheduler")
    thread.start()
    return thread
```

---

# ===== FILE: app/services/event_service.py =====

```python
"""
Event service: persists a pipeline result to the database.

This is the single place where a finished AgentState becomes rows in the
Event / AttackChain / BlockedIP / Report tables. Both the /api/ingest endpoint
and the background scheduler call it, so the two paths cannot drift apart.

Dedup rule: an aggregated event is identified by (source_ip, rule). If an
open event for that pair already exists, it is merged (log_count and analysis
updated, last_seen refreshed) instead of duplicated.
"""
from datetime import datetime

from app.models.db import db, Event, AttackChain, BlockedIP, Report

_STATUS_MAP = {"blocked": "blocked", "awaiting_approval": "awaiting", "logged": "logged"}


def _parse_ts(value, default=None):
    if isinstance(value, datetime):
        return value
    if isinstance(value, str) and value:
        try:
            return datetime.fromisoformat(value.replace("Z", "+00:00")).replace(tzinfo=None)
        except ValueError:
            pass
    return default or datetime.utcnow()


def _upsert_chain(state: dict, now: datetime) -> AttackChain:
    """Create or update the attack chain for this source IP."""
    chain = (AttackChain.query
             .filter_by(source_ip=state.get("source_ip"))
             .order_by(AttackChain.id.desc())
             .first())
    if chain is None:
        chain = AttackChain(source_ip=state.get("source_ip"), first_seen=now)
        db.session.add(chain)

    stages = state.get("chain_stages") or []
    chain.stages = stages
    chain.stage_count = len(stages)
    chain.highest_risk = state.get("chain_risk")
    chain.predicted_next = state.get("predicted_next")
    chain.last_seen = now
    if chain.first_seen is None:
        chain.first_seen = now
    return chain


def persist_pipeline_result(state: dict) -> Event:
    """Save one finished pipeline state; returns the (new or merged) Event."""
    now = datetime.utcnow()
    status = _STATUS_MAP.get(state.get("action_taken"), "new")

    event = (Event.query
             .filter_by(source_ip=state.get("source_ip"), rule=state.get("rule"))
             .filter(Event.status != "dismissed")
             .order_by(Event.id.desc())
             .first())
    if event is None:
        event = Event(
            source_ip=state.get("source_ip"),
            rule=state.get("rule"),
            first_seen=_parse_ts(state.get("first_seen"), now),
        )
        db.session.add(event)

    event.dest_ip = state.get("dest_ip")
    event.attack_type = state.get("attack_type")
    event.log_count = max(event.log_count or 0, state.get("log_count", 0))
    event.confidence = state.get("confidence")
    event.risk = state.get("risk")
    event.status = status
    event.mitre_techniques = state.get("mitre_techniques")
    event.llm_summary = state.get("llm_summary")
    event.raw_log_sample = (state.get("raw_logs") or [])[:20]
    event.threat_intel = state.get("threat_intel")
    event.asset_info = state.get("asset")
    event.vuln_info = state.get("vulnerability")
    event.last_seen = _parse_ts(state.get("last_seen"), now)

    if state.get("is_multistage"):
        event.chain = _upsert_chain(state, now)

    db.session.flush()   # assign event.id before the rows below reference it

    if state.get("blocked"):
        already = BlockedIP.query.filter_by(ip=event.source_ip, active=True).first()
        if already is None:
            db.session.add(BlockedIP(ip=event.source_ip, attack_type=event.attack_type,
                                     blocked_by="auto", event_id=event.id))

    if state.get("report_path"):
        db.session.add(Report(
            event_id=event.id,
            title=f"{event.attack_type} from {event.source_ip}",
            risk=event.risk,
            resolution="auto_blocked" if state.get("blocked") else "logged",
            file_path=state.get("report_path"),
        ))

    db.session.commit()
    return event
```

