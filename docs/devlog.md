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
