// tls_probe.c
#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_core_read.h>
#include <bpf/bpf_tracing.h>

#define MAX_DATA_SIZE 4096
#define MAX_ENTRIES 10240
#define COMM_LEN 16

// TLS 数据事件结构 - 添加连接信息
struct tls_data_event {
    __u32 pid;
    __u32 tid;
    __u64 timestamp;
    __u32 data_len;
    __u8 is_read;
    __u8 _pad[3];
    char comm[COMM_LEN];
    __u64 ssl_ptr;  // SSL 结构体指针，用作连接标识
} __attribute__((packed));

struct {
    __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
    __uint(key_size, sizeof(__u32));
    __uint(max_entries, 1);
    __type(value, struct tls_data_event);
} event_buffer_map SEC(".maps");

// 单独的数据缓冲区结构
struct data_buffer {
    __u8 data[MAX_DATA_SIZE];
};

// Per-CPU 数组用于存储大的数据缓冲区
struct {
    __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
    __uint(key_size, sizeof(__u32));
    __uint(max_entries, 1);
    __type(value, struct data_buffer);
} data_buffer_map SEC(".maps");

// 用于保存函数参数的结构
struct ssl_args {
    const void *ssl;
    const void *buf;
    int num;
};

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(key_size, sizeof(__u64));
    __uint(value_size, sizeof(struct ssl_args));
    __uint(max_entries, MAX_ENTRIES);
} ssl_read_args SEC(".maps");

// Maps 定义
struct {
    __uint(type, BPF_MAP_TYPE_PERF_EVENT_ARRAY);
    __uint(key_size, sizeof(__u32));
    __uint(value_size, sizeof(__u32));
} tls_events SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(key_size, sizeof(__u64));
    __uint(value_size, sizeof(struct ssl_args));
    __uint(max_entries, MAX_ENTRIES);
} ssl_write_args SEC(".maps");

// SSL_write uprobe - 函数入口
SEC("uprobe/SSL_write")
int probe_entry_ssl_write(struct pt_regs *ctx)
{
    __u64 pid_tgid = bpf_get_current_pid_tgid();
    struct ssl_args args = {};
    
    args.ssl = (void *)PT_REGS_PARM1(ctx);
    args.buf = (void *)PT_REGS_PARM2(ctx);
    args.num = (int)PT_REGS_PARM3(ctx);
    
    bpf_map_update_elem(&ssl_write_args, &pid_tgid, &args, BPF_ANY);
    return 0;
}

// SSL_write uretprobe - 函数返回
SEC("uretprobe/SSL_write")
int probe_return_ssl_write(struct pt_regs *ctx)
{
    long ret = PT_REGS_RC(ctx);
    if (ret <= 0) {
        return 0;
    }
    
    __u64 pid_tgid = bpf_get_current_pid_tgid();
    struct ssl_args *args = bpf_map_lookup_elem(&ssl_write_args, &pid_tgid);
    if (!args) {
        return 0;
    }
    
    // 获取 per-CPU 缓冲区
    __u32 zero = 0;
    struct tls_data_event *event = bpf_map_lookup_elem(&event_buffer_map, &zero);
    if (!event) {
        return 0;
    }
    
    struct data_buffer *data_buf = bpf_map_lookup_elem(&data_buffer_map, &zero);
    if (!data_buf) {
        return 0;
    }
    
    // 清空事件结构
    __builtin_memset(event, 0, sizeof(*event));
    
    // 填充事件基本信息
    event->pid = pid_tgid >> 32;
    event->tid = (__u32)pid_tgid;
    event->timestamp = bpf_ktime_get_ns();
    event->is_read = 0;
    event->ssl_ptr = (__u64)args->ssl;  // 添加SSL指针作为连接标识
    
    // 获取进程名
    bpf_get_current_comm(&event->comm, sizeof(event->comm));
    
    // 确保大小是无符号且在有效范围内 - 使用更小的限制
    __u32 bytes_to_read = 0;
    if (ret > 0 && ret < 4000) {
        bytes_to_read = (__u32)ret;
    } else if (ret >= 4000) {
        bytes_to_read = 4000;
    }
    
    // 读取数据
    if (bytes_to_read > 0 && bytes_to_read <= 4000 && args->buf) {
        const void *buf_ptr = args->buf;
        if ((uintptr_t)buf_ptr >= 0x1000 && (uintptr_t)buf_ptr <= 0x7fffffffffff) {
            long read_result = bpf_probe_read_user(data_buf->data, bytes_to_read, buf_ptr);
            if (read_result == 0) {
                event->data_len = bytes_to_read;
            }
        }
    }
    
    // 提交事件元数据
    bpf_perf_event_output(ctx, &tls_events, BPF_F_CURRENT_CPU, 
        event, sizeof(struct tls_data_event));

    if (event->data_len > 0) {
        __u32 data_size = event->data_len;
        // 确保大小是无符号的并在合理范围内
        data_size &= 0x0FFF;  // 限制为4095以内 (12位)
        
        if (data_size > 0) {
            bpf_perf_event_output(ctx, &tls_events, BPF_F_CURRENT_CPU, 
                              data_buf->data, data_size);
        }
    }
    
    // 清理
    bpf_map_delete_elem(&ssl_write_args, &pid_tgid);
    
    return 0;
}

// SSL_read uprobe - 函数入口
SEC("uprobe/SSL_read")
int probe_entry_ssl_read(struct pt_regs *ctx)
{
    __u64 pid_tgid = bpf_get_current_pid_tgid();
    struct ssl_args args = {};
    
    args.ssl = (void *)PT_REGS_PARM1(ctx);
    args.buf = (void *)PT_REGS_PARM2(ctx);
    args.num = (int)PT_REGS_PARM3(ctx);
    
    bpf_map_update_elem(&ssl_read_args, &pid_tgid, &args, BPF_ANY);
    return 0;
}

// SSL_read uretprobe - 函数返回
SEC("uretprobe/SSL_read")
int probe_return_ssl_read(struct pt_regs *ctx)
{
    long ret = PT_REGS_RC(ctx);
    if (ret <= 0) {
        return 0;
    }
    
    __u64 pid_tgid = bpf_get_current_pid_tgid();
    struct ssl_args *args = bpf_map_lookup_elem(&ssl_read_args, &pid_tgid);
    if (!args) {
        return 0;
    }
    
    // 获取 per-CPU 缓冲区
    __u32 zero = 0;
    struct tls_data_event *event = bpf_map_lookup_elem(&event_buffer_map, &zero);
    if (!event) {
        return 0;
    }
    
    struct data_buffer *data_buf = bpf_map_lookup_elem(&data_buffer_map, &zero);
    if (!data_buf) {
        return 0;
    }
    
    // 清空事件结构
    __builtin_memset(event, 0, sizeof(*event));
    
    // 填充事件基本信息
    event->pid = pid_tgid >> 32;
    event->tid = (__u32)pid_tgid;
    event->timestamp = bpf_ktime_get_ns();
    event->is_read = 1;   // 这里标记为读取操作
    event->ssl_ptr = (__u64)args->ssl;  // 添加SSL指针作为连接标识
    
    // 获取进程名
    bpf_get_current_comm(&event->comm, sizeof(event->comm));
    
    // 确保大小是无符号且在有效范围内 - 修改此处，使用更小的限制
    __u32 bytes_to_read = 0;
    if (ret > 0 && ret < 4000) {
        bytes_to_read = (__u32)ret;
    } else if (ret >= 4000) {
        bytes_to_read = 4000;
    }
    
    // 读取数据 - 使用更简单的逻辑帮助验证器跟踪
    if (bytes_to_read > 0 && bytes_to_read <= 4000 && args->buf) {
        const void *buf_ptr = args->buf;
        if ((uintptr_t)buf_ptr >= 0x1000 && (uintptr_t)buf_ptr <= 0x7fffffffffff) {
            long read_result = bpf_probe_read_user(data_buf->data, bytes_to_read, buf_ptr);
            if (read_result == 0) {
                event->data_len = bytes_to_read;
            }
        }
    }
    
    // 提交事件元数据
    bpf_perf_event_output(ctx, &tls_events, BPF_F_CURRENT_CPU, 
        event, sizeof(struct tls_data_event));
    
    if (event->data_len > 0) {
        __u32 data_size = event->data_len;
        data_size &= 0x0FFF;
        if (data_size > 0) {
            bpf_perf_event_output(ctx, &tls_events, BPF_F_CURRENT_CPU, 
                              data_buf->data, data_size);
        }
    }
    
    // 清理
    bpf_map_delete_elem(&ssl_read_args, &pid_tgid);
    
    return 0;
}

// 过滤功能
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(key_size, sizeof(__u32));
    __uint(value_size, sizeof(__u8));
    __uint(max_entries, 1024);
} target_pids SEC(".maps");

char LICENSE[] SEC("license") = "GPL";