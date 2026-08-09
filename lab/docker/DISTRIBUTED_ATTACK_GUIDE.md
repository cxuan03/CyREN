# 分布式容器攻击操作手册（4 容器版）

> 目标：4 个 Docker 容器，每个是 Host-Only 网段上的**独立源 IP**，各用一种工具攻击
> DVWA Target（192.168.56.101），实现真正的多源分布式攻击。ipvlan L2 无 NAT，
> Target 日志里 client IP 就是各容器 IP，CyREN 因此看到 4 个独立源事件。
>
> 前提：ipvlan 连通性已验证通过（`verify_ipvlan.sh` 的 .120 独立 IP 打通）。
> 全程在 **Kali VM** 上做。每步含：命令 + 做什么 + 为什么 + 预期结果 + 报错排查。

## 0. 总览与 IP 规划

| 容器 | 源 IP | 工具 | 攻击类型 | 限速（gentle，非 DDoS） |
|---|---|---|---|---|
| atk-sqlmap | 192.168.56.120 | sqlmap | SQL 注入 | `--delay 1 --threads 1 --level 1 --risk 1` |
| atk-hydra | 192.168.56.122 | hydra | SSH 暴破 | `-t 2`（2 并发） |
| atk-nmap | 192.168.56.123 | nmap | 端口扫描 | `-sT --max-rate 200` |
| atk-masscan | 192.168.56.124 | masscan | 端口扫描（高速） | `--rate 300` + `--router-mac` |

- ipvlan 网络：`--subnet 192.168.56.0/24 --gateway 192.168.56.1 --ip-range 192.168.56.112/28`，
  parent = **eth1**（Kali 的 Host-Only 网卡）。`.112/28` = .112–.127，四个容器 IP 都在其中。
- 涉及的文件（本目录）：`Dockerfile`、`attack.sh`（入口分发）、`passlist.txt`、
  `docker-compose.yml`、`run_distributed.sh`。

**⚠️ 先确认两件事**

```bash
# 做什么: 确认 eth1 确实是 Kali 的 Host-Only 网卡 (192.168.56.x)
# 为什么: ipvlan parent 必须是能打到 target 的那块网卡, 否则容器发不出去
# 预期: 看到 eth1 带一个 192.168.56.x 地址; 若你的 Host-Only 是别的名字(如 eth0), 后面 parent= 改成它
ip -br addr
```

```bash
# 做什么: 查 VirtualBox Host-Only 的 DHCP 地址池
# 为什么: 容器静态 IP .120/.122/.123/.124 必须避开 DHCP 池, 否则可能撞已分配地址
# 预期: 记下 LowerIP/UpperIP; 若池覆盖了 .112-.127, 在 Host Network Manager 里缩小池或改用池外的容器 IP
VBoxManage list dhcpservers        # 在 Windows 主机上跑 (装了 VirtualBox 的机器)
```

---

## 1. 构建 cyren-attacker 镜像

```bash
# 做什么: 在 lab/docker/ 目录用 Dockerfile 构建镜像 cyren-attacker
# 为什么: 一个镜像装齐 6 个工具 + 入口脚本, 4 个容器复用它, 只用 -e ATTACK= 区分
# 预期: 最后一行 "naming to docker.io/library/cyren-attacker" / "Successfully tagged"
cd lab/docker
docker build -t cyren-attacker .
```

验证镜像：
```bash
# 做什么: 确认镜像存在, 且工具都在
# 预期: docker images 有 cyren-attacker; 三条 version 正常打印
docker images cyren-attacker
docker run --rm --entrypoint sh cyren-attacker -c "sqlmap --version; hydra -h 2>&1 | head -1; nmap --version | head -1; masscan --version 2>&1 | head -1"
```

**报错排查**
- `apt-get ... 404 / Could not resolve`：构建时容器要能上网（走 Kali 的 NAT），确认 Kali
  能上网、Docker 的 DNS 正常（`docker run --rm debian:12-slim apt-get update` 能过）。
- 构建慢：sqlmap/nmap 依赖较多，首次几分钟正常；之后有层缓存会快。
- `permission denied` 连 docker：`sudo docker build ...` 或把用户加进 docker 组
  （`sudo usermod -aG docker $USER` 后重登）。

---

## 2. 创建 ipvlan L2 网络

如果连通性验证阶段已建过 `hostonly_attackers`（当时用的是 .120/28 + 可能不同 parent），
**先删掉再按本手册参数重建**：

```bash
# 做什么: 删除旧的同名网络 (若存在); 为什么: 参数(ip-range/parent)要与本手册一致
# 预期: 打印网络名或 "No such network" (都可继续)
docker network rm hostonly_attackers 2>/dev/null || true
```

```bash
# 做什么: 建 ipvlan L2 网络, 父接口 eth1
# 为什么: ipvlan L2 让每个容器有独立 IP、共用 Kali MAC -> 无 NAT 且 VirtualBox 不需混杂模式
# 预期: 打印一串网络 ID (64 位十六进制)
docker network create -d ipvlan \
  --subnet 192.168.56.0/24 \
  --gateway 192.168.56.1 \
  --ip-range 192.168.56.112/28 \
  -o parent=eth1 \
  -o ipvlan_mode=l2 \
  hostonly_attackers
```

参数解释：
- `--subnet 192.168.56.0/24`：Host-Only 网段（与 Target 同网段）。
- `--gateway 192.168.56.1`：Host-Only 网关（主机）。同网段 L2 直达 target 不经它，但 Docker 需要。
- `--ip-range 192.168.56.112/28`：**只在 .112–.127 里分配**，容器 IP 固定在此范围，不乱抢。
- `-o parent=eth1`：绑定到 Kali 的 Host-Only 物理网卡。
- `-o ipvlan_mode=l2`：二层模式（这是 ipvlan 默认；显式写清楚）。

验证：
```bash
# 预期: Driver=ipvlan, ipvlan_mode=l2, Parent=eth1, IPRange=192.168.56.112/28
docker network inspect hostonly_attackers | grep -Ei 'driver|parent|ipvlan_mode|subnet|iprange'
```

**报错排查**
- `network with name hostonly_attackers already exists`：先 `docker network rm hostonly_attackers`
  （若有容器在用，先 `docker compose down` 或 `docker rm -f` 那些容器）。
- `parent interface eth1 does not exist`：`ip -br addr` 看真实网卡名，把 `parent=` 改成
  你的 Host-Only 网卡（可能是 `eth0`/`enp0s8`）。
- 建好后容器 ping 不通（见步骤 5 排查）：多半 parent 选错（选成了 NAT 网卡）。

---

## 3. 启动 4 容器

两种方式，任选其一。**方式 A（显式 docker run）** 每个参数看得清楚，适合理解；
**方式 B（compose）** 一条命令起全部。

### 方式 A：逐个 docker run

```bash
# --- SQLi 源 .120 (sqlmap) ---
# 做什么: 起一个固定 IP .120 的容器, 入口按 ATTACK=sqli 跑 sqlmap
# 为什么: --ip 固定源 IP; --cpus/--memory 限资源; -e 选工具与目标
# 预期: 打印容器 ID; docker logs atk-sqlmap 里能看到 DVWA 登录 + sqlmap 输出
docker run -d --name atk-sqlmap \
  --network hostonly_attackers --ip 192.168.56.120 \
  --cpus 0.5 --memory 256m \
  -e ATTACK=sqli -e TARGET=192.168.56.101 \
  cyren-attacker
```

```bash
# --- SSH 暴破 源 .122 (hydra) ---
docker run -d --name atk-hydra \
  --network hostonly_attackers --ip 192.168.56.122 \
  --cpus 0.5 --memory 256m \
  -e ATTACK=hydra -e TARGET=192.168.56.101 \
  cyren-attacker
```

```bash
# --- 端口扫描 源 .123 (nmap, 慢) ---
docker run -d --name atk-nmap \
  --network hostonly_attackers --ip 192.168.56.123 \
  --cpus 0.5 --memory 256m \
  -e ATTACK=nmap -e TARGET=192.168.56.101 \
  cyren-attacker
```

```bash
# --- 端口扫描 源 .124 (masscan, 高速, 需要 NET_ADMIN/NET_RAW) ---
# 为什么加 cap: masscan 自己造原始包, 需要这两个能力; 入口会自动解析 target MAC 作 --router-mac
docker run -d --name atk-masscan \
  --network hostonly_attackers --ip 192.168.56.124 \
  --cpus 0.5 --memory 256m \
  --cap-add NET_ADMIN --cap-add NET_RAW \
  -e ATTACK=masscan -e TARGET=192.168.56.101 \
  cyren-attacker
```

看某个容器的运行输出：
```bash
docker logs -f atk-masscan     # Ctrl-C 退出跟随; 容器攻击完会自行退出 (Exited)
```

### 方式 B：docker compose（一次起全部）

```bash
# 做什么: 按 docker-compose.yml 起 4 个服务 (网络用外部的 hostonly_attackers)
# 为什么: 一条命令; 每个服务的 IP/工具/限速已写在 yml 里
# 预期: 4 个容器 Created/Started
cd lab/docker
docker compose up -d
docker compose ps          # 看 4 个容器状态
```

> 注：容器是**一次性**的——工具跑完就退出（`Exited (0)`），这是正常的，不是报错。
> 要再打一轮就重新 `docker compose up -d` 或重跑 `docker run`。

**报错排查**
- `Address already in use` / IP 冲突：该容器 IP 被占（旧容器没删、或撞了 DHCP/别名）。
  `docker rm -f <name>` 清旧容器；确认 .120/.122/.123/.124 没被别的东西占用（步骤 0 的 DHCP 检查）。
- 容器起来立刻 `Exited (2)`：多半没传 `-e ATTACK=`，或值拼错（看 `docker logs <name>`）。
- `docker: Error response ... could not find an available IP`：`--ip` 不在 `--ip-range` 内，
  或范围满了；确认用的是 .112–.127。

---

## 4. 错峰启动 + 限速（别做成 DDoS）

4 个容器不必同时开打。`run_distributed.sh` 逐个启动、每个间隔 `GAP` 秒：

```bash
# 做什么: 依次启动 atk-sqlmap -> atk-nmap -> atk-masscan -> atk-hydra, 每个间隔 60s
# 为什么: 错峰更像真实分布式攻击, 且避免瞬时并发; 配合每个工具自带的低速率, 不会打垮靶机
# 预期: 逐行打印 "starting xxx" + "waiting 60s", 最后 "all 4 sources launched"
cd lab/docker
./run_distributed.sh up

# 更宽的间隔:
GAP=120 ./run_distributed.sh up

# 跟随全部日志 / 停止:
./run_distributed.sh logs
./run_distributed.sh stop
```

**限速是怎么保证的（写进 attack.sh 的默认值）**
- sqlmap：`--delay 1`（每请求间隔 1 秒）`--threads 1`，`--level 1 --risk 1`（少量 payload）。
- hydra：`-t 2`（仅 2 并发登录）。
- nmap：`-sT --max-rate 200`（每秒最多 200 包，几秒扫完）。
- masscan：`--rate 300`（每秒 300 包，远低于它默认的爆发能力）。

都可用 `-e` 覆盖（如 `-e MASSCAN_RATE=100`、`-e NMAP_MAX_RATE=100`）进一步放慢。
**不要**把这些调到极高——目的是"多源、真实、可控"，不是压测。

---

## 5. 验证：4 个独立源 → Target 日志 → CyREN 4 事件

### 5.1 在 Target（192.168.56.101）上确认 4 个源 IP 都留痕

```bash
# .120 sqlmap -> apache 访问日志里 client 是 .120 (无 NAT 的证明)
sudo grep 192.168.56.120 /var/log/apache2/access.log | tail
```
```bash
# .122 hydra -> auth.log 出 "Failed password ... from 192.168.56.122"
sudo grep 'Failed password' /var/log/auth.log | grep 192.168.56.122 | tail
```
```bash
# .123 nmap + .124 masscan -> kern.log 出各自 SRC 的 PORTSCAN
sudo grep PORTSCAN /var/log/kern.log | grep -E 'SRC=192.168.56.12[34]' | tail
```
预期：四个 IP 各自出现在对应日志里，说明 4 个容器是**独立源**、且无 NAT。

### 5.2 在 CyREN 主机上确认 4 个独立源事件

```bash
# 做什么: 干跑回填最近 1 小时, 看 CyREN 会摄取哪些事件
# 为什么: 快速确认 4 个源都进了 (不写库); 预期: 列出 .120/.122/.123/.124 的事件
venv\Scripts\python.exe scripts\backfill_events.py --hours 1 --dry-run
```
预期看到 4 个独立源：
- `192.168.56.120  SQL Injection`
- `192.168.56.122  SSH Brute Force`
- `192.168.56.123  Port Scanning`
- `192.168.56.124  Port Scanning`

再到 Dashboard（`http://localhost:5000`，`analyst01 / Analyst@2026`）→ All Events，
应看到这 4 个源的事件（两个 Port Scanning 来自不同 IP）。

**报错排查（没看到事件）**
- Target 日志里有、CyREN 没有：确认 CyREN 的 scheduler 在跑（`ENABLE_SCHEDULER=true`）、
  `INGEST_MODE=filebeat`、`FETCH_WINDOW_HOURS` 够大；或直接跑 `backfill_events.py --hours 1`。
- Target 日志里都没有：Filebeat 没 ship，或容器根本没打到 target（回到步骤 5.1 的 grep 为空 →
  看步骤 3/2 的排查，多半 parent 网卡选错）。
- masscan 的 PORTSCAN 里 SRC 不是 .124：`--router-mac` 没解析到 → 手动传
  `-e MASSCAN_ROUTER_MAC=<target-mac>`（target 上 `ip link` 或 Kali 上 `ip neigh show 192.168.56.101`）。
- 少了 nmap/masscan 之一的 Port Scan：两者都触发同一条 PORTSCAN 规则，但 CyREN 按
  `(source_ip, rule)` 聚合，不同 SRC 是两条独立事件——若只有一条，检查另一个容器是否真发了
  （`docker logs atk-nmap` / `atk-masscan`）。

---

## 6. 停止 / 清理

```bash
# 停止并删除 4 个容器 (compose 方式起的)
cd lab/docker && docker compose down
# 或 run_distributed.sh:
./run_distributed.sh stop
```
```bash
# 若是方式 A 的 docker run 起的, 逐个删:
docker rm -f atk-sqlmap atk-hydra atk-nmap atk-masscan 2>/dev/null || true
```
```bash
# 需要时删网络 (下次实验再建); 镜像可保留复用
docker network rm hostonly_attackers
```

**报错排查**
- `network hostonly_attackers has active endpoints`：还有容器连着，先删容器再删网络。
- 容器删不掉：`docker rm -f <name>`（`-f` 强制）。

---

## 7. 报错排查汇总表

| 现象 | 可能原因 | 处理 |
|---|---|---|
| 容器 ping 不通 target | parent 选成了 NAT 网卡 / 不是 Host-Only | `ip -br addr` 找 192.168.56.x 的网卡，重建网络改 `parent=` |
| Apache 日志里是 Kali 的 IP 不是容器 IP | 没走 ipvlan（走了 bridge）发生了 NAT | `docker network inspect` 确认 Driver=ipvlan、mode=l2 |
| `Address already in use` / 找不到可用 IP | 容器 IP 撞了 DHCP 池/旧容器/别名 | 删旧容器；确认 .112–.127 不在 Host-Only DHCP 池 |
| masscan 无 PORTSCAN 或 SRC 不对 | 缺 NET_ADMIN/NET_RAW；MAC 没解析 | 加 `--cap-add NET_ADMIN --cap-add NET_RAW`；传 `-e MASSCAN_ROUTER_MAC=` |
| sqlmap "no session"/一直跳登录 | DVWA 不在 `http://target/dvwa/` 或账号错 | 确认 DVWA 可访问、`-e DVWA_USER/DVWA_PASS` |
| hydra 无 Failed password | target SSH 没开 / 账号名不对 / 次数不够 | 确认 22 端口开；`-e SSH_USER=`；阈值规则要 ≥5 次失败 |
| 容器立刻 Exited | 没传 `-e ATTACK=` 或值错 | `docker logs <name>` 看原因 |
| CyREN 没事件但 Target 有日志 | scheduler 没跑 / 窗口太短 / INGEST_MODE | 跑 `backfill_events.py --hours 1`；查 `.env` |

---

## 与 IP 别名 fallback 的关系

本方案是**新增并列**，不替换 `../attack_dvwa.sh` / `../attack_multitool.sh`（IP 别名）。
容器网络若出问题、或想快速对照，随时退回别名脚本跑，实验不中断。
