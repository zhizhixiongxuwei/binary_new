# BinaryScan 安装与启动说明（Windows）

本安装包面向 Windows 10/11 用户，采用 Docker Desktop 运行全部服务。

---

## 一、安装包内容

| 文件 | 说明 |
|---|---|
| `binaryscan-source.tar.gz` | 完整源码（含脚本、配置、前端） |
| `dependency-images/binaryscan-dependency-images.tar` | 9 个标准依赖镜像（MySQL、Trivy 数据库、Ghidra/Java 运行时、离线构建器等） |
| `dependency-images/binaryscan-pycdc-tools-image.tar` | pycdc 反编译工具 + Python 运行时镜像 |
| `binaryscan-product-images.tar` | 7 个产品镜像（已构建好，**免编译直接使用**） |

---

## 二、前置条件

1. **Windows 10 21H2 或 Windows 11**
2. **Docker Desktop 4.x**（引擎与 Compose v2 已启用；建议分配内存 ≥ 8 GB、磁盘 ≥ 30 GB）
3. **PowerShell 5.1 或 PowerShell 7**（以管理员身份运行）
4. 首次启动需要联网加载 Windows 容器共享（后续运行完全离线）

---

## 三、安装步骤（推荐：免编译）

打开 PowerShell（管理员），进入解压后的源码目录（例如 `D:\binaryscan`），依次执行：

### 1. 加载全部镜像（约 5–10 分钟，仅首次）

```powershell
docker load -i .\dependency-images\binaryscan-dependency-images.tar
docker load -i .\dependency-images\binaryscan-pycdc-tools-image.tar
docker load -i .\binaryscan-product-images.tar
```

### 2. 初始化本地配置（生成 .env 与密码文件）

```powershell
.\scripts\binaryscan.ps1 init
```

### 3. 设置数据挂载目录（重要）

编辑项目根目录的 **`.env`** 文件，修改 `BINARYSCAN_DATA_ROOT`：

```ini
# 默认（项目内目录，无需额外设置）：
BINARYSCAN_DATA_ROOT=./runtime/data

# 或改为 Windows 独立目录（例如 D 盘）：
BINARYSCAN_DATA_ROOT=D:/binaryscan-data
```

说明：
- 该目录用于存放数据库、上传样本、反编译结果等**全部数据**，请确保磁盘空间 ≥ 20 GB。
- 使用 Windows 路径时请用**正斜杠**（`D:/binaryscan-data`），不要用反斜杠。
- 目录由脚本自动创建，无需手动新建。
- 若使用默认相对路径，数据会保存在项目的 `runtime\data` 下，同样可用。

### 4. 启动全部服务（约 1–2 分钟）

```powershell
.\scripts\binaryscan.ps1 up
```

看到 8 个服务全部 `healthy` 即启动完成。

### 5. 创建初始管理员

```powershell
.\scripts\binaryscan.ps1 init-admin
```

### 6. 访问系统

浏览器打开：**http://127.0.0.1:8080**

初始账号：

| 项 | 值 |
|---|---|
| 用户名 | `admin` |
| 密码 | `admin123456789`（登录后请立即修改） |

---

## 四、可选：从源码离线构建（不使用产品镜像包时）

如果希望自己在目标机器上重新编译全部产品镜像（首次约 30–60 分钟）：

```powershell
.\scripts\binaryscan.ps1 deploy .\dependency-images
```

该命令会依次完成：环境检查 → 导入依赖镜像 → 离线编译 7 个产品镜像 → 启动 → 创建管理员 → 运行验证。

---

## 五、常用运维命令

```powershell
.\scripts\binaryscan.ps1 status        # 查看 8 个服务状态
.\scripts\binaryscan.ps1 logs          # 跟踪全部日志
.\scripts\binaryscan.ps1 logs app      # 跟踪单个服务日志
.\scripts\binaryscan.ps1 verify        # 运行完整健康检查
.\scripts\binaryscan.ps1 down          # 停止服务（不删除数据）
.\scripts\binaryscan.ps1 up            # 再次启动（数据保留）
```

### 清空全部数据（恢复出厂）

```powershell
# 1) 停止服务
.\scripts\binaryscan.ps1 down

# 2) 手动删除数据目录（.env 中 BINARYSCAN_DATA_ROOT 指向的目录），
#    例如删除 D:\binaryscan-data 的整个内容（保留目录本身）

# 3) 重新启动并重建管理员
.\scripts\binaryscan.ps1 up
.\scripts\binaryscan.ps1 init-admin
```

---

## 六、注意事项

1. **Docker Desktop 文件共享**：若数据目录在 D 盘等位置，需在 Docker Desktop → Settings → Resources → File Sharing 中确认该盘已共享（`D:\` 通常默认共享；如遇到挂载失败，把数据目录加入共享列表后重启 Docker）。
2. **首次启动较慢**：MySQL 初始化 + Ghidra 运行时预热约需 1–2 分钟，期间服务状态为 `Waiting`，属正常现象。
3. **端口冲突**：系统占用本机 `8080` 端口；如被占用，修改 `.env` 中的 `BINARYSCAN_HTTP_PORT` 后重新 `up`。
4. **数据备份**：备份 = 备份数据目录（`BINARYSCAN_DATA_ROOT`）；恢复时放回原路径即可。
5. **支持的上传格式**：PE/ELF/Mach-O(x86_64)、CLASS/JAR/WAR/EAR、DEX/APK、PYC(Python 3.13 已适配)、容器镜像包与磁盘映像。
6. **离线运行**：镜像加载完成后，日常使用完全不需要联网。

---

## 七、常见问题

| 现象 | 处理 |
|---|---|
| `docker` 命令找不到 | 安装 Docker Desktop 并重启 PowerShell |
| 挂载目录报权限错误 | Docker Desktop Settings → File Sharing 添加该目录 |
| 服务一直 `Waiting` | `.\scripts\binaryscan.ps1 logs mysql` 查看初始化进度 |
| 浏览器打不开 | 确认 8080 端口未被占用，`status` 检查 8 个服务是否 healthy |
| 忘记管理员密码 | 执行 `.\scripts\binaryscan.ps1 down`，删除数据目录下的 `.admin-initialized` 文件后重新 `up` 与 `init-admin`（注意：这会重建管理员，不影响其他数据） |

---

## 附：如何确认 Docker Desktop 已正确安装

**一条命令**（PowerShell 管理员）：

```powershell
docker version
```

- 提示"无法将 docker 项识别为 cmdlet" → **未安装**：到 docker.com 下载 Docker Desktop，默认勾选 WSL2 后端，安装后重启电脑；
- 输出 Client 信息后报 `docker daemon is not running` → **已安装但未启动**：开始菜单打开 Docker Desktop，等待托盘鲸鱼图标稳定；
- Client 与 Server 两段均正常输出 → 安装且运行正常。

**确认引擎就绪**：

```powershell
docker info
```

输出最后一行 `Server Version: 27.x.x` 即正常；若报 `Cannot connect to the Docker daemon`，请先启动 Docker Desktop。

**项目自检**（在源码目录执行，一步到位）：

```powershell
.\scripts\binaryscan.ps1 doctor
```

**图形界面确认**：开始菜单能搜到 "Docker Desktop" = 已安装；右下角托盘鲸鱼图标 = 正在运行。

**Windows 11 特别说明**：若 Docker Desktop 提示 WSL2 未安装，在管理员 PowerShell 执行 `wsl --install` 并按提示重启。

---

## 附：修改访问端口（默认 8080）

编辑项目根目录的 `.env` 文件，修改第一行：

```ini
BINARYSCAN_HTTP_PORT=8080
```

改为新端口（例如 9090）：

```ini
BINARYSCAN_HTTP_PORT=9090
```

然后执行 `.\scripts\binaryscan.ps1 up` 重新启动（只重建 app 容器，数据不受影响），浏览器访问 `http://127.0.0.1:9090` 即可。

注意：该变量仅修改宿主机映射端口，容器内部端口固定为 8080，修改后无需调整其他配置；若 `.env` 不存在，请先执行 `.\scripts\binaryscan.ps1 init`。

---

## 附：Windows 查看端口占用与释放

查看指定端口（例如 8080）是否被占用（CMD 或 PowerShell）：

```powershell
netstat -ano | findstr :8080
```

输出中最后一列是占用进程的 PID，例如：

```
TCP    0.0.0.0:8080    0.0.0.0:0    LISTENING    12345
```

根据 PID 查看进程名：

```powershell
tasklist /FI "PID eq 12345"
```

结束占用进程（确认安全后）：

```powershell
taskkill /PID 12345 /F
```

其他方式：

```powershell
# 一条 PowerShell 命令直接查看
Get-NetTCPConnection -LocalPort 8080

# 查看全部监听端口
netstat -ano | findstr LISTENING
```

图形界面：`Win+R` 输入 `resmon` 打开资源监视器 → 「网络」→「侦听端口」，可按端口排序查看。
