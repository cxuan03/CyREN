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
