# 架构说明

## 设计边界

新架构以源码可审查、离线可编译、运行容器最少、外部工具可替换为优先级。业务源码只负责调度、存储和结果展示；体积大、许可证独立或更新频繁的工具与数据库放在外部基础镜像中。

前端在构建阶段生成静态文件，由 `app` 镜像内的 Go 网关提供。网关把 `/api` 反向代理到同容器的 API 进程，因此不再需要 Nginx、独立前端容器或独立维护容器。

## 服务关系

```text
Browser -> app:8080 -> web gateway -> API:8081 -> MySQL
                              |                |
                              +-> shared data <-+
scanner -> scan/image/trivy workers -> MySQL + shared data
java    -> bytecode worker         -> MySQL + shared data
ghidra  -> native worker           -> MySQL + shared data
```

`app` 使用轻量 supervisor 管理 API、维护循环和静态网关。`scanner` 使用同一 supervisor 管理 scan、image、trivy 三个 worker。任一必要子进程退出时容器退出，由 Compose 重启。

## 数据库策略

本仓库只支持新建数据库。`db/migrations/00001_initial.sql` 直接创建 `trivy_database_bundles`，漏洞记录只引用 Bundle ID。旧表、旧数据迁移、兼容视图和回滚脚本不进入新基线。

Trivy Bundle 在首次发布扫描结果时登记到 MySQL，用于报告溯源。真正数据库文件始终只存在于只读 `scanner` 镜像层，不上传到应用、不写入 MySQL、不挂载外部数据库卷。

## 安全与隔离

- 产品容器使用 UID/GID `10001`、只读根文件系统、`no-new-privileges` 和 `cap_drop: ALL`。
- 业务数据只写入 `binaryscan-data`，MySQL 只写入 `mysql-data`。
- Compose 网络设置为 internal，扫描器无法直接访问互联网。
- Trivy 强制离线参数，不允许更新数据库或版本检查。
- `binaryscan-bundle-check` 在构建和验收时逐文件计算 SHA-256，并校验主库与 Java 库均存在。
- MySQL 和管理员密码只生成在 `runtime/secrets`，该目录不会进入 Git 或源码 ZIP。

取消独立归档沙箱容器是减少容器数量的明确取舍。压缩包边界、展开大小、深度、文件数量和执行超时仍由应用控制；如果甲方要求进程级沙箱，应把它作为可选增强而不是默认第 6 个长期运行容器。
