# BinaryScan 自主可控验收版

本仓库是面向离线编译、部署和源码封存的基线。当前发行统一从 `BINARYSCAN_DATA_ROOT` 指定的绑定目录启动；同一绑定目录内的数据库会按迁移版本升级并保留任务和源码文件。旧版 Docker 命名卷不自动搬迁，也不属于本发行的原地升级路径。源码仓库不包含 Docker 镜像、Trivy 数据库或运行时缓存。

## 最终运行形态

`compose.yaml` 只定义 7 个长期运行容器：

| 服务 | 职责 |
| --- | --- |
| `app` | Vue 前端、Go API、数据库迁移和维护任务 |
| `mysql` | MySQL 数据库；新绑定目录建空库，同一绑定目录内的数据库按迁移版本升级 |
| `scanner` | 文件扫描、容器镜像解析、Trivy 扫描；一个镜像内固定主库和 Java 库 |
| `java` | JAR、WAR、EAR、APK、DEX、PYC 等字节码反编译 |
| `ghidra` | C/C++ 等原生二进制反编译 |
| `c-checker` | Spring Boot 3/JDK 17/ANTLR4 类 C 静态检测引擎；无状态内部 HTTP 服务 |
| `java-checker` | Spring Boot 3/JDK 17/JavaParser Java 静态检测引擎；无状态内部 HTTP 服务 |

系统没有 Trivy 数据库上传、签名、激活、回滚或安装标识流程。数据库更新方式只有一种：更换经过封存的新 `scanner` 基础镜像并重新构建。

项目不实现 license key、授权服务器、有效期、机器码或功能解锁检查。`licenses/` 只保存第三方开源组件的法律告知文件，不参与启动、登录、扫描或反编译流程。

## 新建任务与归档导入

所有“新建任务”入口统一先选择 `01 二进制格式`、`02 压缩包格式` 或 `03 容器镜像格式`。浏览器只对能够高置信识别的文件头做提前拦截，服务端仍按文件内容执行最终格式校验；扩展名、MIME 和用户声明都不能覆盖检测结果。类别不匹配或不支持的文件不会创建任务，并可从上传队列直接删除。压缩包入口接受 ISO 9660 光盘镜像，只解第一层并对其中二进制成员批量创建检测任务。容器入口除 Docker/OCI 归档外，还接受 EXT2/3/4 文件系统映像与 MBR/GPT 磁盘映像，由 Trivy 的 `vm` 子命令离线扫描漏洞。

`01` 支持 PE、ELF、Mach-O、CLASS、JAR、WAR、EAR、DEX、APK 和 PYC。PYC 上传后由离线 pycdc 反编译为 Python 源码（失败时降级为字节码结构索引），保存的 Python 源码项目可发起 `python-checker` 静态检测（动态代码执行、命令注入、反序列化、弱摘要、证书校验等规则）。`03` 支持 Docker Save TAR、OCI Image Layout TAR、EXT2/3/4 文件系统映像和 MBR/GPT 磁盘映像。两类都允许同类别多文件上传，校验通过后每个文件分别创建一个任务；MBR/GPT 磁盘映像在文件树中展示分区内容，同时由 Trivy `vm` 整盘扫描。SquashFS、UDF 等 Trivy 不支持的文件系统映像不属于新建任务支持范围。

`02` 支持 ZIP、7Z、RAR、TAR、GZIP、BZIP2、XZ、ZSTD、CAB、CPIO、AR、DEB、RPM 和 ISO 9660。每个外层压缩包作为独立导入批次异步解析，先展示内部候选文件，再由用户每次最多选择 20 项创建任务。TAR.GZ 和 DEB/RPM 可以展开格式固有包装，但成员中的普通嵌套压缩包不会递归；成员若识别为 JAR/APK 等二进制或 Docker/OCI 镜像，仍可创建对应任务。加密包、分卷包和无有效成员的压缩包不会创建任务，并提供删除入口。

归档任务名采用 `<压缩包名> :: <内部相对路径>`。删除外层压缩包只清理尚未创建的候选，已经创建的任务、样本 Blob 和扫描结果不受影响。完整格式、限制和 API 合同见 `docs/TASK-INPUT-CATEGORIES.md`。

## 反编译源码项目

每次反编译 run 都以 analyzer run UUID 作为唯一项目 ID，独立保存在 `application/repository/source-projects/<project-id>/`。同一个文件重复反编译会产生互不覆盖的版本，任务详情的“任务信息”中会列出项目 ID、目标路径、引擎、状态、文件/符号数量、大小和完成时间。

Ghidra 项目固定只保存一份规范 C 入口：

```text
source-projects/<project-id>/
├── manifest.json
├── src/
│   └── decompiled.c              # 该 run 的全部函数，且只有这一个 .c 文件
└── metadata/
    ├── functions.json            # 函数在 canonical C 中的字节和行号范围
    ├── callgraph.json
    └── diagnostics.json
```

Java/Kotlin/Python/字节码项目按语言保存到 `src/main/<language>/`，只有无法生成源码的条目才放到 `artifacts/bytecode/`。`manifest.json` 记录每个文件的逻辑路径、SHA-256、大小和结果 ID，可直接作为后续静态分析的项目入口。

reader、operator 和 administrator 都可以下载项目 ZIP；operator 和 administrator 可在列表旁删除指定版本，reader 不显示删除操作。源码删除会先展示影响范围，要求勾选级联删除、输入项目 ID 后 8 位并提交服务器一次性确认令牌；确认后由维护任务异步取消活动检测，并删除源码目录、全部 C/Java 检测历史及引用它们的报告。只保留不含 CWE、符号名或源码片段的操作审计。样本到期不会删除源码项目，删除整个任务会一并删除。旧的 `decompile/<result-id>/` 文件不搬迁，会以 `legacy-v1` 项目继续展示和下载，但不能执行 C 或 Java 检测。

接口为 `GET /api/v1/tasks/<task-id>/decompile-projects`、`GET .../<project-id>.zip`、删除预览/确认和删除 operation 查询接口。

## C 源码检测

只有 `project-v1 + ghidra-pseudoc + language=c` 且状态为完整或部分完成的项目可以发起检测。原始样本过期或已清理不影响已保存源码项目的检测。每次主动检测都会创建独立、不可变的历史版本；同一项目最多有一个排队中或运行中的版本。Go worker 使用现有数据库租约、心跳、fencing token 和全局重任务槽异步编排，把经过 SHA-256/大小校验的 `src/decompiled.c` 流式提交到内部 `c-checker`，后者不连接 MySQL、不挂载 `/data`、不暴露宿主机端口。

固定规则集包含 15 类简单 AST/局部语义规则：危险输入、无界字符串操作、格式串、命令执行、明显越界读写、返回栈地址、非法或偏移指针释放、常量除零、不安全临时文件、未检查关键返回值、明显缓冲区大小计算错误、弱加密/哈希 API 和过宽文件权限。结果只展示 `LOW/MEDIUM/HIGH/CRITICAL`、CWE、规则、函数、位置、检测结论及命中行上下文源码片段（最多 1024 字节）；点击结果行或代码图标即可打开片段，并可继续跳转到完整反编译函数。不展示置信度、修复建议或人工复核状态，也不会改变任务总风险等级。

单次输入最多 128 MiB/3000 个函数，最长 10 分钟，最多保存 10000 条发现，并接收、校验和统计最多 1000 条解析诊断；终态展示诊断数量，检测失败时保留首条失败原因，不额外维护复杂的诊断明细。解析缺失或达到上限会产生 `partial`，而不是伪造完整覆盖。任务详情的“C 源码检测”页支持项目/历史版本选择、覆盖率、四级计数、CWE/严重度/函数筛选、取消活动运行、删除终态运行和跳转到对应反编译函数。报告 JSON 收录所选最新有效版本的全部发现，HTML 明细最多 1000 条并明确标记截断。

`c-checker` 采用 Spring Boot 3、JDK 17 和仓库内固定版本的 ANTLR4 C grammar。容器运行时网络为 internal，不调用外部 API、遥测、许可证服务器或 license 检查；第三方 NOTICE/许可证文件只用于法律告知，不参与任何启动或功能判断。检测器不可用时只会令 C 检测创建接口返回暂不可用，其他扫描、反编译和 Java 检测功能不受影响。

## Java 源码检测

Java 检测只接受 `project-v1 + source_kind=java` 且状态为完整或部分完成的反编译项目。worker 从项目 manifest 中按路径排序选取 `src/main/java/**/*.java` 的完整条目，逐文件验证普通文件、大小和 SHA-256，再生成有明确 offset/length 边界的连续源码 bundle。Kotlin、Python 和仅字节码条目不会被伪装成 Java 输入。原始样本过期后，只要源码项目仍保留，仍可以新建 Java 检测。

固定 `java-rules-v1` 包含 13 类偏 AST 的简单规则：弱消息摘要、弱加密算法、旧 TLS、硬编码密钥、信任所有主机名、信任所有 X.509 证书、XXE、不安全反序列化、SQL 注入、命令注入、动态代码执行、过宽文件权限和不安全 Cookie。结果仅展示四级严重度、CWE、规则、Java 文件/类/可调用符号、位置、结论和代码片段；不显示置信度、修复建议或人工审查，也不改变任务总风险等级。

单次最多分析 3000 个 Java 文件、总计 128 MiB，单文件超过 8 MiB 时跳过并将结果标为 `partial`；最长 10 分钟，最多 10000 条发现和 1000 条诊断。任务详情中可选择源码项目和历史运行，查看覆盖、四级计数、筛选结果和源码片段，也可取消活动运行或删除终态运行。JSON/HTML 报告使用独立 Java 章节，与 C 检测证据分开展示。

`java-checker` 采用 Spring Boot 3、JDK 17 和固定版本的 JavaParser Core，不启用 symbol solver。它不连接 MySQL、不挂载 `/data`、不暴露宿主机端口；每次分析在可终止的子 JVM 内运行，取消和超时会终止子进程。Compose 将父 JVM 固定为 384 MiB、子 JVM 固定为 1024 MiB，并把容器限制为 2 GiB、最多 256 个 PID；checker 不健康时 worker 暂停领取新检测而不会耗尽重试次数。它同样没有遥测、外部 API 或 license 检查；不可用时只暂停 Java 检测创建。

## 制备机生成依赖镜像包

有网络的制备机先加载固定的 Java/Ghidra 工具源镜像，然后运行：

```sh
./scripts/prepare-dependency-images.sh release/dependency-images
```

若已有审核过的 Trivy 主库和 Java 库缓存，可避免重复下载：

```sh
./scripts/prepare-dependency-images.sh \
  release/dependency-images /path/to/trivy-cache
```

脚本会准备 Go 1.25/Node 22 离线 builder、MySQL、Trivy 0.72.0 双数据库、归档工具、Java 反编译工具、Ghidra 运行时、含完整 Maven 依赖的 C checker builder 和 Java checker builder，以及两个 checker 共用的 JDK 17 JRE，共 9 个依赖镜像。脚本会冻结 image ID，并输出带 SHA-256 清单的 `binaryscan-dependency-images.tar`。Java/Ghidra 源镜像名可分别通过 `BINARYSCAN_JAVA_SOURCE_IMAGE` 和 `BINARYSCAN_GHIDRA_SOURCE_IMAGE` 指定。

## 检测机快速部署

macOS，以及按下文准备好数据目录的 Linux/WSL/Git Bash：

```sh
./scripts/binaryscan.sh deploy /path/to/dependency-images
```

Windows PowerShell：

```powershell
.\scripts\binaryscan.ps1 deploy D:\binaryscan-images
```

该命令依次完成环境检查、镜像包哈希验证、`docker load`、断网编译、7 服务启动、管理员初始化和健康检查。默认管理员账号固定为 `admin`，默认密码固定为 `admin123456789`；重复部署不会自动改动该密码。

也可以逐步执行：

```sh
./scripts/binaryscan.sh doctor
./scripts/binaryscan.sh import /path/to/dependency-images
./scripts/binaryscan.sh build
./scripts/binaryscan.sh up
./scripts/binaryscan.sh init-admin
./scripts/binaryscan.sh verify
```

启动后访问 `http://127.0.0.1:8080`。停止服务使用 `./scripts/binaryscan.sh down`，该命令不会删除宿主机数据目录。

## 数据目录

MySQL 和应用数据使用宿主机目录绑定，不再写入 Docker 命名卷。部署前先从模板创建本机配置，再指定数据根目录：

```sh
cp .env.example .env
```

```env
BINARYSCAN_DATA_ROOT=/Users/chenzhe/Documents/binary_data
```

仓库内的 `.env.example` 使用项目内 `./runtime/data` 作为 macOS/Windows 开发默认值；`.env` 不进入 Git，可以在每台部署机器上改成绝对路径。当前 macOS 环境使用上面的 `/Users/chenzhe/Documents/binary_data`。`.env` 的引号、行尾注释、重复键以及进程环境变量优先级均由 Docker Compose 自己解析，启动脚本和实际挂载不会使用两套 dotenv 语义。启动脚本会安全创建并检查以下目录：

```text
/Users/chenzhe/Documents/binary_data/
├── mysql/                         # 挂载到 /var/lib/mysql
└── application/                   # 挂载到 /data
    ├── uploads/
    ├── repository/
    │   ├── .staging/
    │   └── source-projects/       # 第一次发布反编译源码项目时按需创建
    └── task-work/
```

macOS 上应将数据根目录放在 Docker Desktop 允许共享的路径中，`/Users` 默认通常已共享。初始化脚本会在空绑定目录中创建 `uploads/`、`repository/.staging/uploads/` 和 `task-work/`，避免绑定挂载遮蔽镜像内的预置目录。

Linux 上产品容器固定使用 UID/GID `10001`。使用 `/srv/binaryscan-data` 时，先让当前部署用户拥有专用数据根，再以 `10001:10001` 预建应用目录：

```sh
sudo install -d -m 0755 -o "$(id -u)" -g "$(id -g)" /srv/binaryscan-data
sudo install -d -m 0755 -o 10001 -g 10001 \
  /srv/binaryscan-data/application \
  /srv/binaryscan-data/application/uploads \
  /srv/binaryscan-data/application/repository \
  /srv/binaryscan-data/application/repository/.staging \
  /srv/binaryscan-data/application/repository/.staging/uploads \
  /srv/binaryscan-data/application/task-work
```

新目录或跨机恢复后若权限预检失败，只修复专用的 `application` 子树，不要修改 `mysql` 或整个数据根目录：

```sh
sudo chown -R 10001:10001 /srv/binaryscan-data/application
sudo chmod -R u+rwX /srv/binaryscan-data/application
sudo find /srv/binaryscan-data/application -type d -exec chmod go+x {} +
./scripts/binaryscan.sh doctor
```

因此 Linux/WSL 首次部署不能直接沿用当前用户拥有的 `./runtime/data` 空目录，除非该用户本身就是 UID/GID `10001`；先完成上面的专用目录步骤，再执行部署命令。Git Bash 可在 `.env` 中写 `BINARYSCAN_DATA_ROOT=D:/binary_data` 或 `/d/binary_data`，脚本会把它规范化为 Docker Desktop 使用的 Windows 绝对路径；不要使用 `D:binary_data` 这种盘符相对路径。

Linux 上只读密码文件绑定会保留宿主机 UID/GID，不能替容器 UID `10001` 重映射。初始化脚本因此把 `runtime/` 和 `runtime/secrets/` 固定为 `0700`，把其中三个密码文件设为 `0644`：MySQL 密码随机生成，管理员初始密码固定为 `admin123456789`。宿主机其他用户无法穿过私有父目录，容器内的只读单文件挂载则可以读取。Compose 对共享的应用密码使用 `ro,z`，对单容器密码使用 `ro,Z`，可在 enforcing SELinux 主机上完成重标记。不要把 `runtime/secrets` 移到公共目录或放宽父目录权限。

脚本会逐项检查应用根目录、上传目录、仓库目录、仓库暂存目录和任务工作目录的读、写、遍历权限，而不是只检查顶层目录。SELinux 主机通过 Compose 短绑定参数为共享应用、配置和应用密码使用 `z`，为 MySQL 数据、root 密码和管理员初始密码使用 `Z`。请使用启动脚本；直接执行 `docker compose up` 会绕过目录预检，并可能自动创建缺失目录。

旧部署创建的 `binaryscan_mysql-data` 和 `binaryscan_binaryscan-data` 命名卷不会被新 Compose 使用，也不会被自动删除。可以用 `docker volume ls` 查看它们。`./scripts/binaryscan.sh down` 和 `docker compose down -v` 都不会删除 `BINARYSCAN_DATA_ROOT` 中的绑定目录。

数据库迁移 `28` 会兼容展示旧反编译结果；一旦新版本已发布 `project-v1` 源码项目，就不能直接回滚到不认识共享 canonical C 文件的旧应用。回滚保护会明确拒绝该降级，避免留下旧版本无法读取或清理的数据。

Java 分析以新迁移 `32`/`33` 增量加入，不重写已在生产执行的 C 分析迁移。一旦存在 Java 检测 run、job、analyzer 或报告依赖，Down 迁移会拒绝有损回滚；应先停止新建 Java 检测并保留数据库 schema，不得为运行旧代码而强制删除证据表。

### 备份与重新开始

一致性文件备份应先停止服务，再完整备份数据根目录，并保留原有文件权限：

```sh
./scripts/binaryscan.sh down
tar -C /Users/chenzhe/Documents -czf binary_data-backup.tar.gz binary_data
```

恢复时也应先停止服务，并将 `mysql/` 与 `application/` 作为同一份快照恢复。不要只复制正在运行的 MySQL 数据目录。

需要从空数据重新开始时，最安全的方法是停止服务后重命名原目录，让启动脚本创建新目录：

```sh
./scripts/binaryscan.sh down
mv /Users/chenzhe/Documents/binary_data /Users/chenzhe/Documents/binary_data.previous
./scripts/binaryscan.sh init
./scripts/binaryscan.sh up
./scripts/binaryscan.sh init-admin
```

管理员初始化标记保存在对应的数据根目录中，因此切换到新的空目录后会正常创建新数据库管理员。

## 源码封存

源码仓库必须先提交且保持干净：

```sh
./scripts/package-source.sh 0.1.0 /path/to/release
```

输出：

- `binaryscan-source-0.1.0.zip`
- `binaryscan-source-0.1.0.zip.sha256`
- ZIP 内的 `SOURCE_COMMIT` 和逐文件 `MANIFEST.sha256`

镜像永远单独导出：

```sh
./scripts/freeze-image-lock.sh
git add images.lock.env
git commit -m "chore: freeze acceptance image identities"
./scripts/export-dependency-images.sh /path/to/dependency-images
```

完整交付和验收步骤见 [docs/ACCEPTANCE.md](docs/ACCEPTANCE.md)，镜像内容约束见 [docs/IMAGE-CONTRACTS.md](docs/IMAGE-CONTRACTS.md)。

## 本地验证

```sh
go test ./...
npm --prefix web ci
npm --prefix web run typecheck
npm --prefix web run test
npm --prefix web run build
mvn -f c-checker/pom.xml test
mvn -f java-checker/pom.xml test
docker compose --env-file .env.example config
```
