# grpcapture

一个基于 eBPF 的 TLS 流量捕获工具，用于监控和分析 TLS 加密通信。

## 系统要求

- Linux 内核版本 >= 4.18（支持 BTF）
- Go 1.18+
- Clang/LLVM
- 管理员权限（运行 eBPF 程序需要）

## 依赖工具安装

### 1. 安装基础开发工具

```bash
# 更新包管理器
sudo apt update

# 安装 Clang 编译器
sudo apt install -y clang llvm

# 安装 Go（如果尚未安装）
# 请从 https://golang.org/dl/ 下载最新版本
```

### 2. 安装 BPF 工具链

```bash
# 安装通用 Linux 工具
sudo apt install -y linux-tools-common linux-tools-generic

# 安装特定内核版本的工具（根据当前内核版本）
sudo apt install -y linux-tools-$(uname -r)

# 验证 bpftool 安装
which bpftool
```

### 3. 验证 BTF 支持

```bash
# 检查内核是否支持 BTF
ls -la /sys/kernel/btf/vmlinux
```

如果文件不存在，说明内核不支持 BTF，需要升级内核或重新编译内核并启用 BTF 支持。

## 构建步骤

### 1. 生成 vmlinux.h 头文件

```bash
make vmlinux
```

这个命令会：
- 检查 `ebpf/vmlinux.h` 是否存在
- 如果不存在，使用 `bpftool` 从内核 BTF 信息生成头文件

### 2. 生成 eBPF Go 绑定

```bash
make generate
```

这个命令会：
- 调用 `vmlinux` 目标确保头文件存在
- 使用 `bpf2go` 工具编译 eBPF C 代码并生成 Go 绑定
- 根据系统架构自动选择编译目标（amd64/arm64）

### 3. 构建最终可执行文件

```bash
make build
```

或者一步完成所有构建：

```bash
make
```

## 运行

```bash
# 需要管理员权限
sudo ./tls-capture
```

## 清理

```bash
# 清理生成的 Go 文件和可执行文件
make clean

# 清理所有文件（包括 vmlinux.h）
make clean-all
```

## 故障排除

### 1. vmlinux.h 生成失败

**错误现象：** 出现 `unknown type name '__u64'` 等类型未定义错误

**解决方案：**
1. 确保安装了正确版本的 `linux-tools`：
   ```bash
   sudo apt install -y linux-tools-$(uname -r)
   ```

2. 验证 `bpftool` 可用：
   ```bash
   which bpftool
   bpftool version
   ```

3. 手动重新生成 vmlinux.h：
   ```bash
   rm -f ebpf/vmlinux.h
   make vmlinux
   ```

### 2. 编译错误

**错误现象：** Clang 编译 eBPF 代码时出错

**解决方案：**
1. 确保安装了 Clang：
   ```bash
   clang --version
   ```

2. 检查内核头文件：
   ```bash
   ls -la /usr/src/linux-headers-$(uname -r)/
   ```

### 3. 运行时权限错误

**错误现象：** 程序启动时提示权限不足

**解决方案：**
- 确保使用 `sudo` 运行程序
- 检查 eBPF 功能是否在内核中启用

## 项目结构

```
.
├── cmd/                 # Go 主程序和生成的绑定文件
│   ├── main.go         # 主程序入口
│   ├── tls_x86_bpfel.go # 生成的 eBPF Go 绑定（x86_64）
│   └── tls_x86_bpfel.o  # 编译的 eBPF 字节码
├── ebpf/               # eBPF C 代码
│   ├── tls_probe.c     # TLS 探测 eBPF 程序
│   └── vmlinux.h       # 内核类型定义（生成）
├── Makefile            # 构建配置
├── go.mod              # Go 模块定义
├── go.sum              # Go 依赖校验
└── README.md           # 项目文档
```

## 许可证

请查看 LICENSE 文件了解许可证信息。