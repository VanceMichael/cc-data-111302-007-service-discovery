# 来源协议

本地DNS-SD发送器提供POST /emit，参数port指定127.0.0.1上的UDP接收端。包中有PTR、SRV、TXT、A和AAAA，TTL可变，goodbye设为零。名称含压缩指针的另一样本由 compressedName 导出。来源interface是本地捕获层附加元数据，不是DNS线上的字段。只需支持源码生成的记录类型和规范的压缩名称边界，不要求网络发现公网设备。

## 通用控制

`GET /inventory` 返回本来源当前目录，`GET /health` 检查存活，`GET /state` 查看来源状态。`POST /control` 接收JSON对象，仅在来源支持的字段范围内操作。每次创建服务重新读取 fixtures/source.json；控制用于复现来源演进，不是采集业务的实现接口。

服务使用随机本地端口，测试启动与关闭均由代码负责。没有真实个人资料、凭据或付费调用。

## 接收与目录

`npm start` 同时启动 HTTP 控制面和 UDP 接收端。接收端只用 `socket.on('message')` 收集报文，不发送查询、不做端口探测。`POST /emit` 的 `port` 省略时默认发给本次运行的接收端。

- `GET /receiver`：本次接收端的 UDP 地址和端口。
- `GET /directory`：DNS-SD 服务目录快照；`?includeWithdrawn=1` 也列出已撤回的实例。
- `GET /events?since=<ms>`：变化事件；缺省返回全部保留事件。
- `POST /advance {"ms":30000}`：推进回放时钟并结算过期。返回 `{now, clock, events}`；`ms` 必须是非负有限数。
- `POST /receive {"hex"|"base64", "interfaceId", "capturedAt"}`：把一段原始报文直接交给目录，用于离线回放和坏包复现。
- `GET /snapshot` / `POST /save`：导出，或在配置了 `STATE_PATH` 时写入状态文件。

`CLOCK=real` 使用真实时间；默认 `replay` 从 `fixtures/source.json` 的 `clock.start`（缺省 0）开始，只由 `/advance` 推进。`STATE_PATH` 指定的状态包含绝对过期时间；重启后不会给旧观察重新计算完整寿命。

## 目录含义

身份分为三层，互相不会合并：

- 服务实例 = 接口 + 服务类型 + 实例名；同一实例名在不同接口各自成条。PTR 的 owner 是服务类型，RDATA 指向实例。
- 目标主机 = 接口 + 主机名。SRV 的目标主机只在同一接口上查找 A/AAAA。
- 地址 = 接口 + 主机名 + 地址族 + 地址。

每条实例输出 `state`（`ready` / `incomplete` / `withdrawn`）、`missing`（缺少哪种依赖及原因）、`endpoints`（`address:port` 与可连接性）和 `evidence`。`endpoints[].basis` 记录 SRV 与地址各自来自哪个 `packetId`、报文摘要、区段与字节偏移，以及接口范围。`withdrawn` 实例的端点一律 `connectable: false`，缓存的地址不会因为 PTR 告别而变成可用连接信息。

PTR、SRV、TXT、A、AAAA 各自按收到的 TTL 计算绝对过期时间：

- 记录级 TTL 到期只删除该记录。地址全部过期时实例变为 `incomplete`，但仍被通告；迟到的新地址可以补齐同一实例。
- PTR 的 TTL 为零或 PTR 到期视为实例撤出目录（告别）；地址缓存与主机记录保留。
- A/AAAA 的 TTL 为零只删除该地址，不撤回实例。
- cache-flush 位只替换同一 owner、同一类型的 RRset；同包其他区段的记录照常处理。
- 刷新只延长被刷新记录的寿命。

`rejects` 保留损坏或越过边界的记录/报文：`scope`、`sectionIndex`、`code`、`reason`、`offset`，并带 `packetId` 与接口。坏记录不会中断同一报文后续记录，也不会中断后续报文；只有不足 12 字节或问题段损坏的报文会整包拒收。

名称压缩指针只能指向更早的报文内位置；指针不得指向 DNS 头、超出报文范围或形成循环，标签与 RDATA 不得越过当前记录边界。实现位于 `src/dns.mjs`，目录实现位于 `src/directory.mjs`。
