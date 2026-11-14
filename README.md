# 局域网服务发现目录采集

这是用于内部数据接入的 Node.js 项目。现有接收链路从“逐包列 mDNS 报文”扩展为 DNS-SD 服务目录采集：从本地发送器收到的 PTR、SRV、TXT、A、AAAA 按各自 TTL 组织成“现在能连到哪台设备”的目录。接收端只监听已收到的包，不主动扫描或探测端口。

## 环境与命令

Node.js 22.22.1 或更新的 22.x。依赖由 package-lock.json 锁定。

```sh
npm ci --ignore-scripts
npm run build
npm test
npm start
npm run demo
```

`npm start` 在标准输出报告 HTTP 控制面和 UDP 接收地址。默认绑定本机回环地址并使用动态端口；可通过 `HOST` 与 `PORT` 指定监听地址和端口，`STATE_PATH` 指定状态文件，`CLOCK=real` 改用真实时间（默认是可推进的回放时钟）。

```sh
HOST=127.0.0.1 PORT=8080 STATE_PATH=.local/state.json npm start
docker build -t service-discovery:local .
docker run --rm --network none service-discovery:local
docker run --rm --network none service-discovery:local npm run demo
```

依赖在镜像构建阶段安装，运行阶段不需要公网。完整测试和演示通常数秒即可结束。

## 目录

- `src/source.mjs`：本地来源、UDP 接收、HTTP 入口（`/directory`、`/events`、`/advance`、`/receive`、`/save`）。
- `src/receiver.mjs`：UDP 接收与接口归属；同时提供构包辅助函数。
- `src/dns.mjs`：DNS 报文解析，含名称压缩与边界/循环校验。
- `src/directory.mjs`：DNS-SD 缓存、实例/主机/地址三层身份、TTL 结算与变化事件。
- `src/clock.mjs`：可推进时钟；离线回放不等待真实时间。
- `src/persist.mjs`：绝对过期时间的状态保存与恢复。
- `fixtures/source.json`：来源初始状态（两个接口上的同名网关）。
- `docs/source-contract.md`：来源协议、目录语义与 CLI/HTTP 范围。
- `test/`：报文解析、目录语义、来源集成与启动测试。

`npm run demo` 依次展示双接口重名、设备改目标主机、地址先到期后补齐、正常离网的目录变化，全程使用回放时钟推进。`npm start` 本身是持续接收的服务。

运行时状态仅用于来源模拟，重启来源会回到 fixtures 中的值；配置了 `STATE_PATH` 时会载入绝对过期时间，旧观察不会获得新的完整寿命。接入业务自己的持久状态请使用 `.local/` 或明确的外部路径。来源管理入口 `/state` 和 `/control` 是本地操作设施，不能作为绕过浏览器页面的业务写入捷径。
