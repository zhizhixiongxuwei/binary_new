# BinaryScan 自主可控验收版

本仓库是面向离线编译、部署和源码封存的全新基线，不兼容旧数据库，也不包含任何 Docker 镜像、Trivy 数据库或运行时缓存。

## 最终运行形态

`compose.yaml` 只定义 5 个长期运行容器：

| 服务 | 职责 |
| --- | --- |
| `app` | Vue 前端、Go API、数据库迁移和维护任务 |
| `mysql` | 全新 MySQL 数据库，不执行旧库升级 |
| `scanner` | 文件扫描、容器镜像解析、Trivy 扫描；一个镜像内固定主库和 Java 库 |
| `java` | JAR、WAR、EAR、APK、DEX、PYC 等字节码反编译 |
| `ghidra` | C/C++ 等原生二进制反编译 |

系统没有 Trivy 数据库上传、签名、激活、回滚或安装标识流程。数据库更新方式只有一种：更换经过封存的新 `scanner` 基础镜像并重新构建。

项目不实现 license key、授权服务器、有效期、机器码或功能解锁检查。`licenses/` 只保存第三方开源组件的法律告知文件，不参与启动、登录、扫描或反编译流程。

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

脚本会准备 Go 1.25/Node 22 离线 builder、MySQL、Trivy 0.72.0 双数据库、Java 工具和 Ghidra 运行时共 5 个依赖镜像，冻结 image ID，并输出带 SHA-256 清单的 `binaryscan-dependency-images.tar`。Java/Ghidra 源镜像名可分别通过 `BINARYSCAN_JAVA_SOURCE_IMAGE` 和 `BINARYSCAN_GHIDRA_SOURCE_IMAGE` 指定。

## 检测机快速部署

Linux、macOS 或 Windows WSL/Git Bash：

```sh
./scripts/binaryscan.sh deploy /path/to/dependency-images
```

Windows PowerShell：

```powershell
.\scripts\binaryscan.ps1 deploy D:\binaryscan-images
```

该命令依次完成环境检查、镜像包哈希验证、`docker load`、断网编译、5 服务启动、管理员初始化和健康检查。首次执行会输出随机管理员密码，用户名为 `admin`。

也可以逐步执行：

```sh
./scripts/binaryscan.sh doctor
./scripts/binaryscan.sh import /path/to/dependency-images
./scripts/binaryscan.sh build
./scripts/binaryscan.sh up
./scripts/binaryscan.sh init-admin
./scripts/binaryscan.sh verify
```

启动后访问 `http://127.0.0.1:8080`。停止服务使用 `./scripts/binaryscan.sh down`，该命令不会删除数据卷。

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
docker compose --env-file .env.example config
```
