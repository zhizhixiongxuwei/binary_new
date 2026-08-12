# 架构说明

## 设计边界

新架构以源码可审查、离线可编译、运行容器最少、外部工具可替换为优先级。业务源码只负责调度、存储和结果展示；体积大、许可证独立或更新频繁的工具与数据库放在外部基础镜像中。

前端在构建阶段生成静态文件，由 `app` 镜像内的 Go 网关提供。网关把 `/api` 反向代理到同容器的 API 进程，因此不再需要 Nginx、独立前端容器或独立维护容器。

## 服务关系

```text
Browser -> app:8080 -> web gateway -> API:8081 -> MySQL
                              |                |
                              +-> shared data <-+
scanner -> scan/image/trivy/archive-import workers -> MySQL + shared data
java    -> bytecode worker         -> MySQL + shared data
ghidra  -> native worker           -> MySQL + shared data
c-checker <- c_analysis worker HTTP stream (internal network only)
java-checker <- java_analysis worker HTTP bundle (internal network only)
```

`app` 使用轻量 supervisor 管理 API、维护循环和静态网关。`scanner` 使用同一 supervisor 管理 scan、image、trivy、archive-import、c_analysis 和 java_analysis worker。`c-checker` 与 `java-checker` 都是无状态 Spring Boot 内部 HTTP 引擎，不连接数据库或共享数据卷。某个 checker 故障只暂停对应语言的新检测，不影响 scanner 内其他 worker 的健康状态。任一容器内必要子进程退出时容器退出，由 Compose 重启。

## 新建任务输入

所有新上传都必须声明 `binary`、`archive` 或 `container`，但声明值不参与内容识别。浏览器只读取有限文件头/尾做高置信预检，服务端仍使用 `internal/filetype` 的结构化检测器给出权威格式。类别不匹配、未知格式和新入口明确排除的磁盘/文件系统镜像都不会创建 Task 或 Scan Job。

`binary` 和 `container` 在上传完成且服务端校验通过后继续执行一文件一任务流程。`archive` 只创建独立的 archive-import 操作，不为外层压缩包创建任务。archive-import 与普通任务队列分离，但使用相同的数据库时间、租约、heartbeat、fencing 和 maintenance 恢复原则；它作为 scanner supervisor 的子 worker 运行，因此不增加 Compose 容器。

归档导入只穿透外层逻辑包固有的包装，例如 TAR.GZ 或 DEB/RPM payload。实际成员中的普通压缩包不再递归；识别为二进制或 Docker/OCI 镜像的成员进入预览。候选文件先以 SHA-256 内容寻址方式保存，用户每次最多选择 20 项创建独立 Upload、Task 和 Scan Job。删除外层压缩包只释放未创建条目的引用，已经创建的任务继续拥有自己的 Blob 引用和来源路径快照。完整格式与 API 合同见 `docs/TASK-INPUT-CATEGORIES.md`。

## C 分析编排

每个 C 检测用户版本由 `analyzer_runs`、`c_analysis_runs` 和一个 `jobs.kind=c_analysis` 共同标识。创建事务锁定源码项目并快照 canonical SHA-256、大小、Ghidra 引擎版本和函数范围；任务已经终态以及原样本已过期都不阻止创建。队列 claim/start/heartbeat/publish 全部使用数据库时间、owner 和 fencing token，迟到 worker 不能覆盖新租约的结果。c_analysis 使用现有 global heavy slot，默认同一时刻全局只执行一个，并与 Ghidra/Trivy 重任务互斥。

worker 只读打开 `source-projects/<id>/src/decompiled.c` 并复核普通文件、大小和摘要，复制到 fenced task workspace 后以 multipart 流式提交。结果在同一发布事务内复核 job 租约和源码项目代际；成功发布但 queue finish 中断时，自动 delivery 只补齐 finish，不重复插入发现。C findings 有独立表和 UI，不写 `vulnerability_findings`，也不参与 `tasks.risk_level`。

## Java 分析编排

Java 检测使用独立、只增不改的 `java_analysis_runs` / `java_analysis_findings` 域和 `jobs.kind=java_analysis`，不修改已在生产执行的 C 分析迁移。创建事务锁定 Java 源码项目，快照 manifest 摘要和规范输入清单摘要；Begin 阶段再逐文件校验并记录 bundle 摘要。claim、start、heartbeat、publish 和恢复与 C 检测使用相同的数据库时间、租约和 fencing 规则。

worker 只从 manifest allowlist 中取完整 Java 源文件，将验证后的原始字节按逻辑路径排序连续拷贝到 fenced workspace，metadata 为每个文件记录 result ID、逻辑路径、offset、length 和 SHA-256。checker 不解包 ZIP，因此不引入新的 archive traversal 边界。`java-checker` 使用 JavaParser Core 完成 AST 分析，每个请求交由可强制终止的子 JVM；服务本身保持无状态。父/子 JVM 分别限制为 384/1024 MiB，Compose 再施加 2 GiB 内存和 256 PID 上限；checker readiness 也是领取队列任务的门禁，短暂宕机不会消耗 job attempt。

Java findings 同样不写 `vulnerability_findings`、不参与 `tasks.risk_level`。C 与 Java 分析共享当前 global heavy slot，默认同时只执行一个重任务，避免 Ghidra、Trivy 和两个 JVM checker 同时挤压内存。

## 数据库策略

新部署使用空数据库；已有本项目数据库按 `db/migrations` 的连续版本升级。迁移 `28` 只为既有反编译结果回填 `legacy-v1` 项目元数据，不搬迁 `decompile/<result-id>/` 文件；新 run 使用 `project-v1` 独立目录。更早的外部产品数据库不在支持范围内。

Trivy Bundle 在首次发布扫描结果时登记到 MySQL，用于报告溯源。真正数据库文件始终只存在于只读 `scanner` 镜像层，不上传到应用、不写入 MySQL、不挂载外部数据库卷。

## 源码项目存储

每个 analyzer run 对应 `source-projects/<run-id>/`。Ghidra 把全部函数写入唯一 `src/decompiled.c`，结果行只保存该函数的字节/行号范围；字节码 worker 保存 `src/main/java|kotlin|python` 或 `artifacts/bytecode`。manifest 和文件摘要共同约束导出 allowlist，ZIP 不会收集未声明文件。

源码项目独立于原始样本保留策略：样本到期仍可用于后续静态分析；任务删除时按项目根目录清理。单版本删除分为数据库 soft delete、C/Java 活动分析取消、衍生报告和分析证据删除、文件系统删除及数据库完成标记。maintenance 会重试中断的级联删除和独立检测运行删除，并回收未发布孤儿目录。

## 安全与隔离

- 产品容器使用 UID/GID `10001`、只读根文件系统、`no-new-privileges` 和 `cap_drop: ALL`。
- 业务数据只写入 `${BINARYSCAN_DATA_ROOT}/application`，MySQL 只写入 `${BINARYSCAN_DATA_ROOT}/mysql`；两者以宿主机绑定目录挂载，互不混用。
- Compose 网络设置为 internal，扫描器无法直接访问互联网。
- Trivy 强制离线参数，不允许更新数据库或版本检查。
- `binaryscan-bundle-check` 在构建和验收时逐文件计算 SHA-256，并校验主库与 Java 库均存在。
- MySQL 随机密码和固定管理员初始密码只保存在 `runtime/secrets`，该目录不会进入 Git 或源码 ZIP。默认管理员凭据为 `admin / admin123456789`，重复部署不会自动轮换。

取消独立归档沙箱容器是减少容器数量的明确取舍。压缩包边界、展开大小、深度、文件数量和执行超时仍由应用控制；如果甲方要求进程级沙箱，应把它作为可选增强，而不是再增加默认长期运行容器。
