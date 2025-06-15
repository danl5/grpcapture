# 调试模式使用说明

## 概述

本项目的eBPF代码支持调试模式，可以控制是否输出调试信息到内核日志。默认情况下，调试模式是关闭的，以减少性能开销和日志噪音。

## 启用调试模式

### 方法1：编译时启用

在编译时通过定义 `DEBUG_MODE` 宏来启用调试模式：

```bash
# 启用调试模式编译
make DEBUG_MODE=1

# 正常模式编译（默认）
make

# 清理编译文件
make clean
```

## 调试模式说明

调试模式会启用以下特性：
- 添加 `-DDEBUG_MODE=1` 编译标志
- 禁用优化 (`-O0`)
- 增强调试信息 (`-g3`)
- 在eBPF代码中可以使用 `DEBUG_PRINT` 宏进行调试输出

## 编译标志对比

| 模式 | 优化级别 | 调试信息 | 其他标志 | DEBUG_MODE宏 |
|------|----------|----------|----------|-------------|
| 正常模式 | `-O2` | `-g` | - | 未定义 |
| 调试模式 | `-O1` | `-g3` | `-fno-stack-protector` | 已定义 |

## 调试模式技术说明

### 为什么使用 `-O1` 而不是 `-O0`？

在eBPF程序中，完全禁用优化（`-O0`）可能导致BTF（BPF Type Format）验证失败，特别是在包含调试输出的复杂函数中。使用 `-O1` 可以：
- 保持基本的代码优化，确保eBPF验证器能够正确验证程序
- 仍然提供良好的调试体验
- 避免BTF加载错误

### 为什么添加 `-fno-stack-protector`？

栈保护功能在eBPF环境中可能引起兼容性问题，禁用它可以：
- 避免额外的栈检查代码影响eBPF验证
- 减少生成代码的复杂度
- 提高调试模式的稳定性

### 方法2：修改源码

直接修改 `ebpf/common.h` 文件中的 `DEBUG_MODE` 定义：

```c
// 将这行
#define DEBUG_MODE 0
// 改为
#define DEBUG_MODE 1
```

然后重新编译：

```bash
make clean
make
```

## 查看调试输出

启用调试模式后，可以通过以下方式查看调试输出：

```bash
# 查看内核日志中的调试信息
sudo dmesg | grep "DEBUG:"

# 实时监控调试输出
sudo dmesg -w | grep "DEBUG:"

# 或者查看 /sys/kernel/debug/tracing/trace_pipe
sudo cat /sys/kernel/debug/tracing/trace_pipe | grep "DEBUG:"
```

## 调试信息说明

调试输出包含以下类型的信息：

- **SSL操作跟踪**：SSL_write、SSL_read等函数的调用信息
- **连接管理**：socket创建、文件描述符映射等
- **数据传输**：TLS数据包的发送和接收
- **网络层信息**：TCP四元组提取、连接标识等

## 性能影响

- **调试模式关闭**（默认）：无性能影响，所有调试代码被编译器优化掉
- **调试模式开启**：会有一定的性能开销，主要来自：
  - 字符串格式化
  - 内核日志写入
  - 额外的函数调用

## 建议

- **生产环境**：保持调试模式关闭（`DEBUG_MODE=0`）
- **开发调试**：根据需要临时启用调试模式
- **问题排查**：启用调试模式可以帮助定位SSL捕获相关的问题

## 示例输出

启用调试模式后，典型的输出如下：

```
[12345.678901] DEBUG: SSL_write entry - pid=1234, ssl=0xffff888012345678
[12345.678902] DEBUG: SSL_write entry - buf=0xffff888087654321, num=1024
[12345.678903] DEBUG: fill_meta - pid=1234, ssl=ffff888012345678, is_read=0
[12345.678904] DEBUG: fill_meta - TCP tuple extracted successfully
[12345.678905] DEBUG: fill_meta - src addr: 0xc0a80101 port: 12345
[12345.678906] DEBUG: fill_meta - dst addr: 0xc0a80102 port: 443
```