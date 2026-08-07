# 自主可控交付与验收流程

## 交付物分组

甲方接收两组彼此独立的介质：

1. 源码包：`binaryscan-source-<version>.zip` 及同名 `.sha256`。
2. 镜像包：一个或多个 `.tar`、`IMAGE_FILES.sha256`、镜像清单说明。

源码 ZIP 只允许包含 Go/Vue 源码、`go.mod`、`go.sum`、`package-lock.json`、数据库迁移、Dockerfile、Compose、配置、许可证、文档和脚本。禁止包含镜像 tar、Trivy DB、Java DB、依赖目录、编译结果、运行数据和密码。

## 制备机流程

1. 构建并测试 Builder、MySQL、Scanner 双库、Java、Ghidra 这 5 个外部依赖镜像。
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

随后一条命令部署：

```sh
./scripts/binaryscan.sh deploy /media/binaryscan-images
```

或 PowerShell：

```powershell
.\scripts\binaryscan.ps1 deploy D:\binaryscan-images
```

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
```

判定标准：

- Compose 服务列表恰好为 `mysql app scanner java ghidra`，总数 5；
- 4 个产品镜像均从本次源码在断网模式编译；
- `scanner` 的 Bundle 校验输出同时包含主库版本和 Java 库版本；
- 所有 5 个服务为 running/healthy；
- 浏览器能上传文件、查看识别结果，并能分别触发原生、Java 和 Trivy 流程；
- 源码 ZIP 中不存在 `.tar`、`trivy.db`、`trivy-java.db`、`node_modules`、`runtime` 或密码文件。

## 版本升级

新版本使用新的 Git commit、源码 ZIP 哈希、产品镜像标签和外部镜像 ID。数据库结构可以通过新迁移演进，但不承诺从旧项目数据库导入。Trivy 数据库更新必须发布新的 Scanner 双库镜像，不在运行界面中上传或切换数据库。
