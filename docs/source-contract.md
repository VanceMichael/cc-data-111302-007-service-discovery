# 来源协议

本地DNS-SD发送器提供POST /emit，参数port指定127.0.0.1上的UDP接收端。包中有PTR、SRV、TXT、A和AAAA，TTL可变，goodbye设为零。名称含压缩指针的另一样本由 compressedName 导出。来源interface是本地捕获层附加元数据，不是DNS线上的字段。只需支持源码生成的记录类型和规范的压缩名称边界，不要求网络发现公网设备。

## 通用控制

`GET /inventory` 返回本来源当前目录，`GET /health` 检查存活，`GET /state` 查看来源状态。`POST /control` 接收JSON对象，仅在来源支持的字段范围内操作。每次创建服务重新读取 fixtures/source.json；控制用于复现来源演进，不是采集业务的实现接口。

服务使用随机本地端口，测试启动与关闭均由代码负责。没有真实个人资料、凭据或付费调用。
