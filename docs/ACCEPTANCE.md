# 自主可控交付与验收流程

## 交付物分组

甲方接收两组彼此独立的介质：

1. 源码包：`binaryscan-source-<version>.zip` 及同名 `.sha256`。
2. 镜像包：一个或多个 `.tar`、`IMAGE_FILES.sha256`、镜像清单说明。

源码 ZIP 只允许包含 Go/Vue 源码、`go.mod`、`go.sum`、`package-lock.json`、数据库迁移、Dockerfile、Compose、配置、许可证、文档和脚本。禁止包含镜像 tar、Trivy DB、Java DB、依赖目录、编译结果、运行数据和密码。

## 制备机流程

1. 构建并测试 Builder、MySQL、Scanner 双库、归档工具、Java 反编译工具、Ghidra、C checker Maven builder、Java checker Maven builder 和共用 JDK 17 JRE 这 9 个外部依赖镜像。
2. 执行 `./scripts/freeze-image-lock.sh`，把实际 image ID 写入 `images.lock.env`。
3. 执行 `go test ./...`、前端 typecheck/test/build 和 Compose 配置检查。
4. 提交所有源码，确认 `git status --short` 为空。
5. 执行 `./scripts/package-source.sh <version> <release-dir>`。
6. 执行 `./scripts/export-dependency-images.sh <image-dir>`，镜像介质与源码包分开保存。
7. 将源码 ZIP SHA-256、Git commit、镜像 tar SHA-256 和 image ID 写入交付记录。

## 检测机流程

先验证源码 ZIP 外层哈希：

```sh
sha256sum -c binaryscan-source-0.1.0.zip.sha256
unzip binaryscan-source-0.1.0.zip
cd binaryscan-source-0.1.0
```

macOS 可使用 `shasum -a 256 -c`。Windows 可使用：

```powershell
Get-FileHash .\binaryscan-source-0.1.0.zip -Algorithm SHA256
Expand-Archive .\binaryscan-source-0.1.0.zip
```

随后一条命令部署。先创建本机 `.env`：

```sh
cp .env.example .env
```

在 `.env` 中设置检测机的数据根目录。Linux 可以使用 `/srv/binaryscan-data`，macOS 可以使用 `/Users/<用户名>/Documents/binary_data`：

```env
BINARYSCAN_DATA_ROOT=/srv/binaryscan-data
```

Linux 普通用户首次使用 `/srv` 前，先准备宿主机目录和容器 UID `10001` 的应用子树：

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

部署脚本会创建缺失的 `mysql/` 和 `application/` 绑定目录并执行权限预检，不会迁移或删除历史 Docker 命名卷。不要用裸 `docker compose up` 绕过预检。

```sh
./scripts/binaryscan.sh deploy /media/binaryscan-images
```

或 PowerShell：

```powershell
Copy-Item .env.example .env
# 在 .env 中设置：BINARYSCAN_DATA_ROOT=D:\binary_data
.\scripts\binaryscan.ps1 deploy D:\binaryscan-images
```

Git Bash 使用 Windows 目录时，在 `.env` 中写
`BINARYSCAN_DATA_ROOT=D:/binary_data`（或 `/d/binary_data`）；不得使用
`D:binary_data` 这种盘符相对路径。Linux/WSL 必须先完成上面的 UID/GID
`10001` 应用目录准备，模板内的 `./runtime/data` 不作为 Linux 首部署捷径。

编译阶段所有 Docker build 均指定 `--network=none`，因此缺失 Go/npm 缓存或基础镜像时会直接失败，不会偷偷联网下载。

## 验收证据

至少保存以下命令输出：

```sh
./scripts/verify-source.sh
docker compose --env-file .env config --services
./scripts/binaryscan.sh status
./scripts/binaryscan.sh verify
docker image inspect binaryscan/app:0.1.0
docker image inspect binaryscan/scanner:0.1.0
docker image inspect binaryscan/c-checker:0.1.0
docker image inspect binaryscan/java-checker:0.1.0
```

判定标准：

- Compose 服务列表恰好为 `mysql app scanner c-checker ghidra java java-checker`，总数 7；
- 6 个产品镜像均从本次源码在断网模式编译；
- `scanner` 的 Bundle 校验输出同时包含主库版本和 Java 库版本；
- 所有 7 个服务为 running/healthy；
- Compose 渲染结果中的 `/var/lib/mysql` 与 `/data` 来源均位于 `BINARYSCAN_DATA_ROOT`；
- 浏览器能上传文件、查看识别结果，并能分别触发原生、Java 和 Trivy 流程；
- 所有“新建任务”入口先要求选择 01 二进制、02 压缩包或 03 容器镜像，刷新页面后类别保持，上传队列非空时不能切换；
- 二进制和容器上传在服务端内容校验通过后按文件分别创建任务；类别不匹配、未知格式以及被排除的磁盘/文件系统镜像不创建任务并可直接删除；
- 同时上传多个压缩包时，每个包独立解析和预览；TAR.GZ、DEB、RPM 能穿透固有包装，但成员中的普通嵌套压缩包不会递归；
- 归档预览默认选择有效二进制/容器成员，每批最多创建 20 个任务，重复提交不重复建任务，删除外层压缩包不影响已创建任务；
- 加密包、分卷包、路径穿越、链接、设备节点、重复路径和全局解压限制均 fail closed，空包或无有效成员时不创建任务并提供删除入口；
- 完成一次 Ghidra 反编译后，能创建 C 检测、查看四级发现/函数片段、生成含独立 C 章节的报告，并通过多重确认级联删除源码和衍生证据；
- 完成一次 Java 字节码反编译后，能创建 Java 检测、查看四级发现/文件和可调用符号/代码片段、生成含独立 Java 章节的报告，且结果不改变任务总风险等级；
- 源码 ZIP 中不存在 `.tar`、`trivy.db`、`trivy-java.db`、`node_modules`、`runtime` 或密码文件。

## 版本升级

新版本使用新的 Git commit、源码 ZIP 哈希、产品镜像标签和外部镜像 ID。数据库结构可以通过新迁移演进，但不承诺从旧项目数据库导入。Trivy 数据库更新必须发布新的 Scanner 双库镜像，不在运行界面中上传或切换数据库。
