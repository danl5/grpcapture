// tls_probe.c
#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>

#define MAX_DATA_SIZE 16384
#define MAX_ENTRIES 102400
#define COMM_LEN 16
#define MIN_DATA_SIZE 1   // 最小数据长度过滤（数据包抓取场景）

// TCP四元组结构体
struct tcp_tuple {
    __u32 saddr;    // 源IP地址
    __u32 daddr;    // 目标IP地址
    __u16 sport;    // 源端口
    __u16 dport;    // 目标端口
} __attribute__((packed));

struct meta {
    __u32 pid;
    __u32 tid;
    __u64 timestamp;
    __u32 data_len;
    __u8 is_read;
    __u8 _pad[3];
    char comm[COMM_LEN];
    __u64 ssl_ptr;
    __u64 conn_id;          
    struct tcp_tuple tuple; 
    __u8 tuple_valid;       // 四元组是否有效
    __u8 _pad2[3];
} __attribute__((packed));

struct tls_event {
    struct meta meta;
    __u8 data[MAX_DATA_SIZE];
} __attribute__((packed));

// 参数缓存结构
struct ssl_args {
    const void *ssl;
    const void *buf;
    int num;
} __attribute__((packed));

// 读写参数缓存Map
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(key_size, sizeof(__u64));
    __uint(value_size, sizeof(struct ssl_args));
    __uint(max_entries, MAX_ENTRIES);
} ssl_read_args SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(key_size, sizeof(__u64));
    __uint(value_size, sizeof(struct ssl_args));
    __uint(max_entries, MAX_ENTRIES);
} ssl_write_args SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 256 * 1024 * 1024); // 256MB 缓冲区
} tls_events SEC(".maps");

// 统计计数器
struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(key_size, sizeof(__u32));
    __uint(value_size, sizeof(__u64));
    __uint(max_entries, 4);
} stats SEC(".maps");

// Map to store socket file descriptors for each process during SSL operations
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(key_size, sizeof(__u64));
    __uint(value_size, sizeof(__u32));
    __uint(max_entries, MAX_ENTRIES);
} active_ssl_sockets SEC(".maps");

// Map to mark processes that are currently in SSL operations
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(key_size, sizeof(__u64));
    __uint(value_size, sizeof(__u8));
    __uint(max_entries, MAX_ENTRIES);
} ssl_operation_flag SEC(".maps");

static int extract_tcp_tuple(struct sock *sk, struct tcp_tuple *tuple) {
    if (!sk || !tuple) return -1;

    // 从socket结构体中读取地址和端口信息
    // skc_rcv_saddr: 本地绑定地址 (local address)
    // skc_daddr: 远程地址 (remote address)  
    // skc_num: 本地端口 (local port)
    // skc_dport: 远程端口 (remote port)
    
    __u32 local_addr, remote_addr;
    __u16 local_port, remote_port;
    
    if (bpf_probe_read_kernel(&remote_addr, sizeof(remote_addr), &sk->__sk_common.skc_daddr) ||
        bpf_probe_read_kernel(&local_addr, sizeof(local_addr), &sk->__sk_common.skc_rcv_saddr) ||
        bpf_probe_read_kernel(&remote_port, sizeof(remote_port), &sk->__sk_common.skc_dport) ||
        bpf_probe_read_kernel(&local_port, sizeof(local_port), &sk->__sk_common.skc_num)) {
        return -1; // 任一读取失败则返回错误
    }

    // 字节序转换
    remote_addr = __builtin_bswap32(remote_addr);
    local_addr = __builtin_bswap32(local_addr);
    remote_port = __builtin_bswap16(remote_port);
    // local_port (skc_num) 已经是主机字节序，不需要转换
    
    // 将本地地址作为源地址，远程地址作为目标地址
    // 这样可以确保从不同进程角度看到的四元组是一致的
    tuple->saddr = local_addr;
    tuple->daddr = remote_addr;
    tuple->sport = local_port;
    tuple->dport = remote_port;
    
    return 0;
}

// 用于存储从网络系统调用中获取的sock结构体
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(key_size, sizeof(__u64));  // pid_tgid
    __uint(value_size, sizeof(struct sock *));
    __uint(max_entries, 1024);
} sock_storage SEC(".maps");

// 从SSL结构体获取socket结构体
static struct sock *get_sock_from_ssl() {
    __u64 pid_tgid = bpf_get_current_pid_tgid();
    
    // 从sock_storage map中获取sock结构体
    struct sock **sock_ptr = bpf_map_lookup_elem(&sock_storage, &pid_tgid);
    if (!sock_ptr) {
        return NULL;
    }
    
    return *sock_ptr;
}


// 辅助函数：填充元数据（增强版，包含四元组）
static void fill_meta(struct meta *m, __u64 pid_tgid, int is_read, const struct ssl_args *args) {
    m->pid = pid_tgid >> 32;
    m->tid = (__u32)pid_tgid;
    m->timestamp = bpf_ktime_get_ns();
    m->is_read = is_read;
    m->ssl_ptr = (__u64)args->ssl;
    m->conn_id = ((__u64)m->pid << 32) | (m->ssl_ptr & 0xFFFFFFFF);
    bpf_get_current_comm(&m->comm, COMM_LEN);
    
    // 初始化四元组相关字段
    __builtin_memset(&m->tuple, 0, sizeof(m->tuple));
    m->tuple_valid = 0;
    
    // 尝试获取TCP四元组
    struct sock *sk = get_sock_from_ssl();
    if (sk) {
        if (extract_tcp_tuple(sk, &m->tuple) == 0) {
            m->tuple_valid = 1;
            // 使用四元组构造更稳定的连接ID
            // 为了确保双向连接产生相同的ID，我们需要标准化四元组
            // 将较小的IP:Port组合作为"端点1"，较大的作为"端点2"
            __u64 endpoint1 = ((__u64)m->tuple.saddr << 16) | m->tuple.sport;
            __u64 endpoint2 = ((__u64)m->tuple.daddr << 16) | m->tuple.dport;
            
            // 确保endpoint1总是较小的那个，这样双向连接会产生相同的ID
            if (endpoint1 > endpoint2) {
                __u64 temp = endpoint1;
                endpoint1 = endpoint2;
                endpoint2 = temp;
            }
            
            // 使用标准化后的端点生成连接ID
            m->conn_id = (endpoint1 << 32) | (endpoint2 & 0xFFFFFFFF);
        }
    }
}

// SSL_write 入口探针
SEC("uprobe/SSL_write")
int probe_entry_ssl_write(struct pt_regs *ctx) {
    __u64 pid_tgid = bpf_get_current_pid_tgid();
    struct ssl_args args;
    args.ssl = (void *)PT_REGS_PARM1(ctx);
    args.buf = (void *)PT_REGS_PARM2(ctx);
    args.num = (int)PT_REGS_PARM3(ctx);
    bpf_map_update_elem(&ssl_write_args, &pid_tgid, &args, BPF_ANY);
    
    // Mark this process as being in SSL operation
    __u8 flag = 1;
    bpf_map_update_elem(&ssl_operation_flag, &pid_tgid, &flag, BPF_ANY);
    
    return 0;
}

// SSL_write 返回探针（RINGBUF 优化版）
SEC("uretprobe/SSL_write")
int probe_return_ssl_write(struct pt_regs *ctx) {
    long ret = PT_REGS_RC(ctx);
    if (ret <= 0) return 0;

    __u64 pid_tgid = bpf_get_current_pid_tgid();
    struct ssl_args *args = bpf_map_lookup_elem(&ssl_write_args, &pid_tgid);
    if (!args) return 0;

    // 数据长度过滤 - 确保有效数据
    if (ret < MIN_DATA_SIZE) {
        bpf_map_delete_elem(&ssl_write_args, &pid_tgid);
        return 0;
    }

    __u32 data_len = (ret > MAX_DATA_SIZE) ? MAX_DATA_SIZE : (__u32)ret;
    // 使用固定大小以满足eBPF验证器要求，Go端根据meta.data_len处理实际数据
    struct tls_event *e = bpf_ringbuf_reserve(&tls_events, sizeof(struct tls_event), 0);
    if (!e) {
        bpf_map_delete_elem(&ssl_write_args, &pid_tgid);
        return 0; // 缓冲区满时优雅丢弃
    }

    // 填充元数据
    fill_meta(&e->meta, pid_tgid, 0, args);
    e->meta.data_len = 0;

    // 安全复制数据
    if (data_len > 0 && args->buf) {
        long res = bpf_probe_read_user(e->data, data_len, args->buf);
        e->meta.data_len = (res >= 0) ? data_len : 0;
    }

    // 统计write事件提交次数
    __u32 write_key = 0;
    __u64 *write_count = bpf_map_lookup_elem(&stats, &write_key);
    if (write_count) {
        __sync_fetch_and_add(write_count, 1);
    } else {
        __u64 init_count = 1;
        bpf_map_update_elem(&stats, &write_key, &init_count, BPF_ANY);
    }
    
    bpf_ringbuf_submit(e, 0);
    bpf_map_delete_elem(&ssl_write_args, &pid_tgid);
    
    // Clear SSL operation flag and socket fd after SSL_write completes
    bpf_map_delete_elem(&ssl_operation_flag, &pid_tgid);
    bpf_map_delete_elem(&active_ssl_sockets, &pid_tgid);
    bpf_map_delete_elem(&sock_storage, &pid_tgid);
    
    return 0;
}

// SSL_read 入口探针
SEC("uprobe/SSL_read")
int probe_entry_ssl_read(struct pt_regs *ctx) {
    __u64 pid_tgid = bpf_get_current_pid_tgid();
    
    // Mark this process as being in SSL operation
    __u8 flag = 1;
    bpf_map_update_elem(&ssl_operation_flag, &pid_tgid, &flag, BPF_ANY);
    
    struct ssl_args args;
    args.ssl = (void *)PT_REGS_PARM1(ctx);
    args.buf = (void *)PT_REGS_PARM2(ctx);
    args.num = (int)PT_REGS_PARM3(ctx);
    bpf_map_update_elem(&ssl_read_args, &pid_tgid, &args, BPF_ANY);
    return 0;
}

// SSL_read 返回探针（对称逻辑）
SEC("uretprobe/SSL_read")
int probe_return_ssl_read(struct pt_regs *ctx) {
    long ret = PT_REGS_RC(ctx);
    if (ret <= 0) return 0;

    __u64 pid_tgid = bpf_get_current_pid_tgid();
    struct ssl_args *args = bpf_map_lookup_elem(&ssl_read_args, &pid_tgid);
    if (!args) return 0;

    // 数据长度过滤 - 确保有效数据
    if (ret < MIN_DATA_SIZE) {
        bpf_map_delete_elem(&ssl_read_args, &pid_tgid);
        return 0;
    }

    __u32 data_len = (ret > MAX_DATA_SIZE) ? MAX_DATA_SIZE : (__u32)ret;
    // 使用固定大小以满足eBPF验证器要求，Go端根据meta.data_len处理实际数据
    struct tls_event *e = bpf_ringbuf_reserve(&tls_events, sizeof(struct tls_event), 0);
    if (!e) {
        bpf_map_delete_elem(&ssl_read_args, &pid_tgid);
        return 0;
    }

    fill_meta(&e->meta, pid_tgid, 1, args);
    e->meta.data_len = 0;

    if (data_len > 0 && args->buf) {
        long res = bpf_probe_read_user(e->data, data_len, args->buf);
        e->meta.data_len = (res >= 0) ? data_len : 0;
    }

    // 统计read事件提交次数
    __u32 read_key = 1;
    __u64 *read_count = bpf_map_lookup_elem(&stats, &read_key);
    if (read_count) {
        __sync_fetch_and_add(read_count, 1);
    } else {
        __u64 init_count = 1;
        bpf_map_update_elem(&stats, &read_key, &init_count, BPF_ANY);
    }
    
    bpf_ringbuf_submit(e, 0);
    bpf_map_delete_elem(&ssl_read_args, &pid_tgid);
    
    // Clear SSL operation flag and socket fd after SSL_read completes
    bpf_map_delete_elem(&ssl_operation_flag, &pid_tgid);
    bpf_map_delete_elem(&active_ssl_sockets, &pid_tgid);
    bpf_map_delete_elem(&sock_storage, &pid_tgid);
    
    return 0;
}

// 系统调用探针 - 捕获socket文件描述符
// 监控sendto系统调用入口
SEC("tracepoint/syscalls/sys_enter_sendto")
int trace_enter_sendto(struct trace_event_raw_sys_enter *ctx) {
    __u64 pid_tgid = bpf_get_current_pid_tgid();
    
    // Check if this process is currently in SSL operation
    __u8 *flag = bpf_map_lookup_elem(&ssl_operation_flag, &pid_tgid);
    if (flag && *flag == 1) {
        __u32 sockfd = (__u32)ctx->args[0];
        // Store socket fd for this SSL operation
        bpf_map_update_elem(&active_ssl_sockets, &pid_tgid, &sockfd, BPF_ANY);
    }
    
    return 0;
}

// Hook into socket-related kernel functions to capture sock structures
SEC("kprobe/tcp_sendmsg")
int trace_tcp_sendmsg(struct pt_regs *ctx) {
    __u64 pid_tgid = bpf_get_current_pid_tgid();
    
    // Check if this process is currently in an SSL operation
    __u8 *flag = bpf_map_lookup_elem(&ssl_operation_flag, &pid_tgid);
    if (flag && *flag == 1) {
        // Get sock structure from first argument of tcp_sendmsg
        struct sock *sk = (struct sock *)PT_REGS_PARM1(ctx);
        if (sk) {
            // Store the sock structure in sock_storage
            bpf_map_update_elem(&sock_storage, &pid_tgid, &sk, BPF_ANY);
        }
    }
    
    return 0;
}

SEC("kprobe/tcp_recvmsg")
int trace_tcp_recvmsg(struct pt_regs *ctx) {
    __u64 pid_tgid = bpf_get_current_pid_tgid();
    
    // Check if this process is currently in an SSL operation
    __u8 *flag = bpf_map_lookup_elem(&ssl_operation_flag, &pid_tgid);
    if (flag && *flag == 1) {
        // Get sock structure from first argument of tcp_recvmsg
        struct sock *sk = (struct sock *)PT_REGS_PARM1(ctx);
        if (sk) {
            // Store the sock structure in sock_storage
            bpf_map_update_elem(&sock_storage, &pid_tgid, &sk, BPF_ANY);
        }
    }
    
    return 0;
}

// 监控recvfrom系统调用入口
SEC("tracepoint/syscalls/sys_enter_recvfrom")
int trace_enter_recvfrom(struct trace_event_raw_sys_enter *ctx) {
    __u64 pid_tgid = bpf_get_current_pid_tgid();
    
    // Check if this process is currently in SSL operation
    __u8 *flag = bpf_map_lookup_elem(&ssl_operation_flag, &pid_tgid);
    if (flag && *flag == 1) {
        __u32 sockfd = (__u32)ctx->args[0];
        // Store socket fd for this SSL operation
        bpf_map_update_elem(&active_ssl_sockets, &pid_tgid, &sockfd, BPF_ANY);
    }
    
    return 0;
}

// 监控send系统调用入口
SEC("tracepoint/syscalls/sys_enter_send")
int trace_enter_send(struct trace_event_raw_sys_enter *ctx) {
    __u64 pid_tgid = bpf_get_current_pid_tgid();
    
    // Check if this process is currently in SSL operation
    __u8 *flag = bpf_map_lookup_elem(&ssl_operation_flag, &pid_tgid);
    if (flag && *flag == 1) {
        __u32 sockfd = (__u32)ctx->args[0];
        // Store socket fd for this SSL operation
        bpf_map_update_elem(&active_ssl_sockets, &pid_tgid, &sockfd, BPF_ANY);
    }
    
    return 0;
}

// 监控recv系统调用入口
SEC("tracepoint/syscalls/sys_enter_recv")
int trace_enter_recv(struct trace_event_raw_sys_enter *ctx) {
    __u64 pid_tgid = bpf_get_current_pid_tgid();
    
    // Check if this process is currently in SSL operation
    __u8 *flag = bpf_map_lookup_elem(&ssl_operation_flag, &pid_tgid);
    if (flag && *flag == 1) {
        __u32 sockfd = (__u32)ctx->args[0];
        // Store socket fd for this SSL operation
        bpf_map_update_elem(&active_ssl_sockets, &pid_tgid, &sockfd, BPF_ANY);
    }
    
    return 0;
}

char LICENSE[] SEC("license") = "GPL";