# 新建任务输入分类与归档导入合同

本文档冻结新建任务三类输入与归档导入的 v1 产品合同。实现不得依赖文件扩展名或浏览器 MIME 作最终判断。

## 输入分类

- `binary`（01 二进制格式）：`pe32`、`pe32+`、`elf32`、`elf64`、`macho-thin`、`macho-fat`、`java-class`、`jar`、`war`、`ear`、`dex`、`apk`、`pyc`。
- `archive`（02 压缩包格式）：`zip`、`7z`、`rar`、`tar`、`gzip`、`bzip2`、`xz`、`zstd`、`cab`、`cpio`、`ar`、`deb`、`rpm`。
- `container`（03 容器镜像格式）：`docker-tar`、`oci-tar`。

EXT2/3/4、SquashFS、ISO9660、UDF、MBR/GPT 不属于新建任务支持范围。JAR/WAR/EAR/APK 优先归入 `binary`；Docker/OCI TAR 优先归入 `container`。

## 上传与校验

- 新建上传必须携带不可变的 `input_category`；历史上传可无该字段，但不得据此新建任务。
- 浏览器只做有把握的有限文件头/尾预检；未知结果必须上传后由服务端判断。
- 服务端内容检测是权威结果。类别不匹配或格式不支持时不得创建 Task/Scan Job，只允许删除上传。
- `binary` 和 `container` 校验通过后沿用一文件一任务流程。
- `archive` 校验通过后只创建归档导入批次，不为外层压缩包创建任务。

## 归档导入

- 一个上传压缩包对应一个独立导入批次；多个压缩包不得跨包合并创建任务。
- 允许展开外层逻辑包所需的固有包装，例如 TAR.GZ 和 DEB/RPM payload；得到成员文件后停止递归。
- 成员中的普通压缩包跳过；成员若识别为 `binary` 或 `container`，进入可选列表。
- 加密包、分卷包、路径穿越、绝对路径、软硬链接、设备节点及重复路径不得成为候选。
- 每批最多选择 20 个候选。每个条目最多创建一次任务；不同路径但相同 SHA-256 仍是不同条目，Blob 存储可去重。
- 任务名为 `<外层压缩包名> :: <内部相对路径>`。
- 删除外层压缩包不得影响已经创建的任务；未创建条目及其存储引用随导入批次清理。

## 限制

- 单个上传最大 2 GiB；解压总量最大 10 GiB；压缩比最大 50:1；最多 20,000 个节点；单个候选最大 2 GiB。
- 全局安全限制触发时导入失败；单个成员不支持或过大时仅跳过该成员。
- 所有创建、重试、发布、删除和恢复路径必须幂等并受数据库 fencing 保护。

## API 语义

- `POST /api/v1/uploads` 必填 `input_category`。
- `GET /api/v1/archive-imports/:id` 返回导入状态与计数。
- `GET /api/v1/archive-imports/:id/entries` 返回游标分页候选/跳过/已创建条目。
- `POST /api/v1/archive-imports/:id/task-batches` 要求 CSRF 与 `Idempotency-Key`，最多 20 个 entry ID，返回逐项结果。
- `DELETE /api/v1/uploads/:id` 可删除不匹配、空、失败或已就绪的归档上传；解析或批量创建期间返回冲突。已经从内部条目创建的任务和派生上传独立保留，不阻止外层归档删除。

新功能不得改变已有任务风险计算、扫描、反编译、静态检测或报告语义，也不得新增长期运行容器。
