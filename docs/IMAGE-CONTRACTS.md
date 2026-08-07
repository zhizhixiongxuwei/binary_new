# 外部镜像约束

源码 ZIP 不包含本文件所述镜像或数据库文件。所有依赖镜像必须先在制备机上构建和审查，再通过 `docker save` 单独交付。

所有外部镜像和最终产品镜像都不得携带安装标识、数据库签名状态、Sigstore Bundle 或信任密钥标签。导入脚本会拒绝含此类历史标签的镜像。

## Builder

`BINARYSCAN_BUILDER_IMAGE` 必须包含：

- Linux amd64、Go 1.24.x、Node.js 22.x、npm；
- `go.sum` 对应的完整 Go module cache；
- `web/package-lock.json` 对应的完整 npm cache，路径 `/opt/binaryscan/npm-cache`；
- `go mod download` 和 `npm ci --offline` 在 `--network=none` 下可成功执行；
- 不需要携带项目源代码。

## Scanner 与双 Trivy 数据库

`BINARYSCAN_TRIVY_RUNTIME_DB_IMAGE` 必须同时包含：

- `/usr/local/bin/trivy`，版本与 `config/app.yaml` 一致；
- 文件解包和镜像解析所需的受控命令行工具；
- `/opt/trivy-cache/bundle.json`；
- `/opt/trivy-cache/db/versions/<uuid>/metadata.json`；
- `/opt/trivy-cache/db/versions/<uuid>/trivy.db`；
- `/opt/trivy-cache/java-db/versions/<uuid>/metadata.json`；
- `/opt/trivy-cache/java-db/versions/<uuid>/trivy-java.db`。

`bundle.json` 的核心结构：

```json
{
  "schema_version": 1,
  "id": "UUIDv4",
  "version": "2026.08.07",
  "generated_at": "2026-08-07T00:00:00Z",
  "content_sha256": "64 lowercase hex",
  "databases": [
    {
      "id": "UUIDv4",
      "database_type": "trivy-db",
      "version": "2026.08.07",
      "schema_version": 2,
      "storage_key": "trivy/db/versions/<uuid>",
      "files": []
    },
    {
      "id": "UUIDv4",
      "database_type": "trivy-java-db",
      "version": "2026.08.07",
      "schema_version": 1,
      "storage_key": "trivy/java-db/versions/<uuid>",
      "files": []
    }
  ]
}
```

每个 `files` 数组必须按规范顺序列出文件名、实际 SHA-256 和字节数。所有目录和文件在镜像中必须不可写。`content_sha256` 是按数据库类型排序后，对组件 ID、版本、schema、storage key 和文件元数据计算的固定摘要；实现见 `internal/trivydb/calculatedBundleHash`。

## Java

`BINARYSCAN_JAVA_RUNTIME_IMAGE` 必须包含：

- `/opt/java/openjdk/bin/java`；
- `/opt/bytecode-tools/vineflower/vineflower.jar`；
- `/opt/bytecode-tools/cfr/cfr.jar`；
- `/opt/bytecode-tools/jadx/lib/jadx-all.jar`；
- 文件内容必须匹配 `internal/bytecode/source_engine.go` 中的固定 SHA-256。

## Ghidra

`BINARYSCAN_GHIDRA_RUNTIME_IMAGE` 必须包含：

- `/opt/ghidra/support/analyzeHeadless`，Ghidra 12.1.2；
- `/opt/java/openjdk/bin/java`，输出版本行与 `config/app.yaml` 完全一致；
- UID `10001` 对所需运行文件具有只读和执行权限。

## MySQL

`BINARYSCAN_MYSQL_IMAGE` 是单独导入的固定 MySQL 镜像。镜像标签和本地 image ID 都必须写入 `images.lock.env`。不得使用 `latest`，不得在检测机上拉取。

## 身份冻结

制备机完成镜像导入后执行：

```sh
./scripts/freeze-image-lock.sh
```

检测机的导入脚本会同时检查标签和 image ID。镜像 tar 文件再由 `IMAGE_FILES.sha256` 独立封存，避免和源码 ZIP 哈希混淆。
