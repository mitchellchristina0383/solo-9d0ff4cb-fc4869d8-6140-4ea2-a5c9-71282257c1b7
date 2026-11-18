# lab.test 主从权威 DNS（Python / FastAPI / SQLite）

网络管理员批量更新 `lab.test` 仪器地址的最小可用主从权威 DNS：

- **主节点**（`dnslab/master_app.py`）：通过 HTTP API（Swagger UI 在 `/docs`）维护 A 记录全集；
  每次发布（单条增删改或整体批量替换）在**一个 SQLite 事务**内完成记录变更、
  SOA 序列号递增（从 1 开始每次 +1）、并落一份带 SHA-256 校验和的**不可变快照**。
- **从节点**（`dnslab/slave_app.py`）：经 HTTP 从主节点拉取整份快照，校验通过且序列号
  严格更新后才生效；以 UDP 回答 `A` / `SOA` 查询，对域内不存在的名字回答 `NXDOMAIN`
  （authority 带本版 SOA），域外查询 `REFUSED`。

## 一致性保证

| 场景 | 行为 |
|---|---|
| 发布与拉取交错 | 快照是主节点单事务读出的不可变版本；从节点要么整体应用某版本，要么不应用 |
| 并发同步 | 从节点同步串行化；应用前在锁内复查序列号，最终版本一定是见过的最大序列号 |
| 中途断流 / 数据被改 | 传输中断 → 拉取报错；SHA-256 校验失败 → 拒绝；现役版本不受影响 |
| 迟到旧版 | 序列号 ≤ 现役版本的一律拒绝（`applied: false`），不会覆盖新版 |
| 记录与 SOA 同版 | 每条应答都由同一个不可变 `ZoneData` 对象生成，SOA 序列号与记录同属一版 |
| 主节点失联 | 从节点继续用最后一次成功同步的版本应答；`/sync` 报 502 但不影响应答 |
| 从节点重启 | 启动时从 SQLite 恢复最后成功版本，无需先同步即可应答 |
| 初次同步失败 | 没有任何版本时回答 `SERVFAIL`（不可用），绝不凭空应答 |

## 运行

### Docker Compose（推荐）

```bash
docker compose up --build
```

- 主节点 API / 文档： http://localhost:8000/docs
- 从节点 API / 文档： http://localhost:8001/docs
- 从节点 DNS： `dig @127.0.0.1 -p 5353 host1.lab.test A` ／ `dig @127.0.0.1 -p 5353 lab.test SOA`

从节点数据在命名卷 `slave-data` 中，`docker compose restart slave` 后仍用最后版本应答。

### 本地（无 Docker）

```bash
pip install -r requirements.txt
MASTER_DB=/tmp/master.db uvicorn dnslab.master_app:app --port 8000 &
SLAVE_DB=/tmp/slave.db MASTER_URL=http://127.0.0.1:8000 DNS_PORT=5353 \
  uvicorn dnslab.slave_app:app --port 8001 &
```

## 使用（均可在 `/docs` 中操作）

```bash
# 批量发布仪器地址（一次事务、一个新序列号）
curl -X POST http://localhost:8000/records/bulk -H 'Content-Type: application/json' -d '{
  "records": [
    {"name": "host1.lab.test", "ip": "10.0.0.1"},
    {"name": "host2.lab.test", "ip": "10.0.0.2", "ttl": 60}
  ]}'

# 单条增改 / 删除
curl -X PUT  http://localhost:8000/records/host3.lab.test -H 'Content-Type: application/json' -d '{"ip": "10.0.0.3"}'
curl -X DELETE http://localhost:8000/records/host2.lab.test

# 查看主节点现役序列号 / 完整快照
curl http://localhost:8000/zone/serial
curl http://localhost:8000/zone/snapshot

# 从节点：发起同步、查看现役序列号
curl -X POST http://localhost:8001/sync -H 'Content-Type: application/json' -d '{}'
curl http://localhost:8001/status
```

`POST /sync` 可选参数：`{"serial": N}` 拉取指定历史版本（主节点保留最近
`KEEP_VERSIONS=100` 版，主要用于测试迟到旧版）；`{"url": ...}` 覆盖快照来源。
设 `SYNC_INTERVAL=秒数` 可让从节点周期自动同步（默认 0，仅手动）。

## 自测

```bash
python tests/selftest.py    # 需要已安装 requirements.txt
```

脚本拉起真实主从进程，覆盖：初次同步失败报不可用、发布/同步/应答、批量更新原子切换、
迟到旧版拒绝、断流与校验和损坏、并发发布+同步交错（序列号单调、最终内容逐条一致）、
主节点失联、从节点重启、新从节点+主失联、`/docs` 可用性与主恢复后的同步。

## 目录

```
dnslab/dnsproto.py    最小 DNS 线格式编解码与应答逻辑（仅标准库）
dnslab/master_app.py  主节点 FastAPI 应用
dnslab/slave_app.py   从节点 FastAPI 应用 + UDP DNS 服务
tests/selftest.py     端到端自测
Dockerfile / docker-compose.yml
```

## 已知限制

- 仅 UDP、仅 `A`/`SOA`/`ANY` 查询；不支持 TCP、EDNS、IXFR/AXFR、DNSSEC、NOTIFY。
- 序列号比较用简单“严格大于”（本系统序列号从 1 单调 +1，未实现 RFC 1982 回绕比较）。
- 快照为全量传输，适合 lab 规模；超大区域需增量机制。
- 从节点应用快照时的 SQLite 写入在事件循环内完成，记录数极大时会短暂阻塞循环（lab 规模无感）。
- 主节点 `/debug/snapshot/truncated`、`/debug/snapshot/corrupt` 仅用于故障注入测试，生产应移除。
