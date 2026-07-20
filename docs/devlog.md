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
