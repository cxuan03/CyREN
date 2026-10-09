# CyREN 真封锁落地：靶机 ipset 拉取代理

架构：CyREN（Windows, 192.168.56.1:5000）维护封锁名单 → 靶机（Ubuntu,
192.168.56.101）每 10 秒拉取一次，用 ipset + 一条 iptables DROP 规则本地执行。
名单驱动、原子生效、断线保持最后名单、白名单永不误封。

## 第 0 步：Windows 侧（一次性，两件事）

1. 放行 CyREN 端口给 host-only 网段（管理员 PowerShell 执行）：

```powershell
New-NetFirewallRule -DisplayName "CyREN blocklist feed" -Direction Inbound -Protocol TCP -LocalPort 5000 -RemoteAddress 192.168.56.0/24 -Action Allow
```

2. 确认 CyREN 正在运行，且 `.env` 里已有 `BLOCKLIST_TOKEN=...`（已生成）。
   重启过 CyREN 后端点才会生效。

## 第 1 步：把本目录 5 个文件拷到靶机

任选方式（scp 示例，在 Windows 上执行，用户名换成你的）：

```powershell
scp -r C:\cyren_ui\deploy\target-agent youruser@192.168.56.101:/tmp/
```

## 第 2 步：靶机上安装（逐条执行，或整段粘贴）

```bash
sudo apt-get update && sudo apt-get install -y ipset curl

sudo mkdir -p /etc/cyren

# 配置文件：填入 token
sudo cp /tmp/target-agent/blocklist.conf.example /etc/cyren/blocklist.conf
sudo nano /etc/cyren/blocklist.conf     # 把 TOKEN= 换成 CyREN .env 里的 BLOCKLIST_TOKEN
sudo chmod 600 /etc/cyren/blocklist.conf

# 白名单：确认包含 127.0.0.1 / 192.168.56.1 / 192.168.56.101，
# 并把你的管理 IP 加进去（每行一个纯 IPv4）
sudo cp /tmp/target-agent/whitelist.txt /etc/cyren/whitelist.txt
sudo nano /etc/cyren/whitelist.txt

# 同步脚本
sudo cp /tmp/target-agent/cyren-blocklist-sync.sh /usr/local/sbin/
sudo chmod 755 /usr/local/sbin/cyren-blocklist-sync.sh

# systemd 单元
sudo cp /tmp/target-agent/cyren-blocklist.service /etc/systemd/system/
sudo cp /tmp/target-agent/cyren-blocklist.timer   /etc/systemd/system/
sudo systemctl daemon-reload
sudo systemctl enable --now cyren-blocklist.timer
```

## 第 3 步：验证

```bash
# 1) 网络+token 通不通（应打印 IP 列表，每行一个）
source /etc/cyren/blocklist.conf
curl -sS -H "X-CyREN-Token: $TOKEN" "$CYREN_URL"

# 2) 手跑一次同步（无输出=成功）
sudo /usr/local/sbin/cyren-blocklist-sync.sh

# 3) 看集合内容（应与 CyREN Firewall Blocks 页的 Active 一致）
sudo ipset list cyren_block

# 4) 确认那条唯一的 DROP 规则在
sudo iptables -L INPUT -n --line-numbers | head -5

# 5) 定时器在跑
systemctl status cyren-blocklist.timer
```

端到端测试：在攻击机打一轮（触发高危自动封锁，或在界面审批 Block）→
10 秒内 `ipset list cyren_block` 出现攻击机 IP → 攻击机再 ping/curl 靶机应不通。
界面点 Unblock → 下一轮同步自动解封。

## 说明

- 重启靶机后：timer 15 秒内首跑，集合与规则自动重建，无需持久化配置。
- CyREN 关机时：靶机维持最后一份名单继续封锁（fail-safe）。
- 空名单：集合被换成空，全部解封——这是正确语义（名单即事实）。
- 拉取失败（网络断/403）：保持现有集合不动。

## 卸载

```bash
sudo systemctl disable --now cyren-blocklist.timer
sudo rm /etc/systemd/system/cyren-blocklist.{service,timer}
sudo systemctl daemon-reload
sudo iptables -D INPUT -m set --match-set cyren_block src -j DROP
sudo ipset destroy cyren_block; sudo ipset destroy cyren_block_tmp
sudo rm -rf /etc/cyren /usr/local/sbin/cyren-blocklist-sync.sh
```
