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

// 临时存储当前SSL操作的SSL指针
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(key_size, sizeof(__u64));  // pid_tgid
    __uint(value_size, sizeof(__u64)); // ssl_ptr
    __uint(max_entries, 102400);
} current_ssl_ptr SEC(".maps");

// Map to mark processes that are currently in SSL operations
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(key_size, sizeof(__u64));
    __uint(value_size, sizeof(__u8));
    __uint(max_entries, MAX_ENTRIES);
} ssl_operation_flag SEC(".maps");

// PID过滤白名单Map
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(key_size, sizeof(__u32));  // PID
    __uint(value_size, sizeof(__u8)); // 标志位（1表示允许）
    __uint(max_entries, 1024);
} pid_filter SEC(".maps");

// 过滤模式配置
struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(key_size, sizeof(__u32));
    __uint(value_size, sizeof(__u8));
    __uint(max_entries, 1);
} filter_config SEC(".maps");

// PID过滤函数
static int should_filter_pid(__u32 pid) {
    __u32 key = 0;
    __u8 *filter_enabled = bpf_map_lookup_elem(&filter_config, &key);
    
    // 如果未启用过滤，允许所有PID
    if (!filter_enabled || *filter_enabled == 0) {
        return 0; // 不过滤
    }
    
    // 检查PID是否在白名单中
    __u8 *allowed = bpf_map_lookup_elem(&pid_filter, &pid);
    if (allowed && *allowed == 1) {
        return 0; // 不过滤
    }
    
    return 1; // 过滤掉
}

// SSL连接标识结构体 - 用作更精确的key
struct ssl_conn_key {
    __u64 pid_tgid;    // 进程/线程ID
    __u64 ssl_ptr;     // SSL结构体指针
};

// 文件描述符到sock结构体的映射key
struct fd_key {
    __u64 pid_tgid;    // 进程/线程ID
    int fd;           // 文件描述符
};

// 用于存储从网络系统调用中获取的sock结构体
// 使用SSL连接标识作为key，支持一个进程内的多个SSL连接
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(key_size, sizeof(struct ssl_conn_key));
    __uint(value_size, sizeof(struct sock *));
    __uint(max_entries, 102400);
} sock_storage SEC(".maps");

// 文件描述符到sock结构体的映射
// 使用pid_tgid+fd作为key，直接映射到sock结构体
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(key_size, sizeof(struct fd_key));
    __uint(value_size, sizeof(struct sock *));
    __uint(max_entries, 102400);
} fd_to_sock_map SEC(".maps");


// 辅助函数：从sock结构体提取TCP四元组
static int extract_tcp_tuple(struct sock *sk, struct tcp_tuple *tuple) {
    if (!sk || !tuple) {
        return -1;
    }
    
    // 从 sock 结构体的 __sk_common 部分读取网络信息
    // 使用 bpf_probe_read_kernel 安全地读取内核内存
    __be32 saddr, daddr;
    __be16 sport, dport;
    
    // 读取源地址和目标地址
    if (bpf_probe_read_kernel(&saddr, sizeof(saddr), &sk->__sk_common.skc_rcv_saddr) != 0) {
        return -1;
    }
    if (bpf_probe_read_kernel(&daddr, sizeof(daddr), &sk->__sk_common.skc_daddr) != 0) {
        return -1;
    }
    
    // 读取源端口和目标端口
    if (bpf_probe_read_kernel(&sport, sizeof(sport), &sk->__sk_common.skc_num) != 0) {
        return -1;
    }
    if (bpf_probe_read_kernel(&dport, sizeof(dport), &sk->__sk_common.skc_dport) != 0) {
        return -1;
    }
    
    // 转换字节序并填充结构体
    tuple->saddr = bpf_ntohl(saddr);
    tuple->daddr = bpf_ntohl(daddr);
    tuple->sport = bpf_ntohs(sport);
    tuple->dport = bpf_ntohs(dport);
    
    return 0;
}

// 辅助函数：填充元数据（包含完整的四元组提取）
static void fill_meta(struct meta *m, __u64 pid_tgid, int is_read, const struct ssl_args *args) {
    m->pid = pid_tgid >> 32;
    m->tid = (__u32)pid_tgid;
    m->timestamp = bpf_ktime_get_ns();
    m->is_read = is_read;
    m->ssl_ptr = (__u64)args->ssl;
    m->conn_id = ((__u64)m->pid << 32) | (m->ssl_ptr & 0xFFFFFFFF);
    bpf_get_current_comm(&m->comm, COMM_LEN);
    
    // 初始化四元组相关字段
    m->tuple.saddr = 0;
    m->tuple.daddr = 0;
    m->tuple.sport = 0;
    m->tuple.dport = 0;
    m->tuple_valid = 0;
    
    bpf_printk("DEBUG: fill_meta - pid=%u, ssl=%llx, is_read=%d", m->pid, m->ssl_ptr, is_read);
    
    // 尝试从 sock_storage 获取 sock 结构体并提取四元组
    struct ssl_conn_key key = {
        .pid_tgid = pid_tgid,
        .ssl_ptr = m->ssl_ptr
    };
    
    struct sock **sk_ptr = bpf_map_lookup_elem(&sock_storage, &key);
    if (sk_ptr && *sk_ptr) {
        struct sock *sk = *sk_ptr;
        if (extract_tcp_tuple(sk, &m->tuple) == 0) {
            m->tuple_valid = 1;
            bpf_printk("DEBUG: fill_meta - TCP tuple extracted: %u.%u.%u.%u:%u -> %u.%u.%u.%u:%u",
                      (m->tuple.saddr >> 24) & 0xFF, (m->tuple.saddr >> 16) & 0xFF,
                      (m->tuple.saddr >> 8) & 0xFF, m->tuple.saddr & 0xFF, m->tuple.sport,
                      (m->tuple.daddr >> 24) & 0xFF, (m->tuple.daddr >> 16) & 0xFF,
                      (m->tuple.daddr >> 8) & 0xFF, m->tuple.daddr & 0xFF, m->tuple.dport);
        } else {
            bpf_printk("DEBUG: fill_meta - Failed to extract TCP tuple from sock=%p", sk);
        }
    } else {
        bpf_printk("DEBUG: fill_meta - No sock found for SSL=%llx", m->ssl_ptr);
    }
    
    // 尝试从 active_ssl_sockets 获取文件描述符信息以增强连接ID
    __u32 *sockfd = bpf_map_lookup_elem(&active_ssl_sockets, &pid_tgid);
    if (sockfd) {
        // 使用 sockfd 增强连接ID的唯一性
        m->conn_id = ((__u64)m->pid << 32) | ((__u64)*sockfd << 16) | (m->ssl_ptr & 0xFFFF);
        bpf_printk("DEBUG: fill_meta - Using sockfd-enhanced conn_id=%llx", m->conn_id);
    } else {
        bpf_printk("DEBUG: fill_meta - No sockfd found, using basic conn_id=%llx", m->conn_id);
    }
}

// SSL_write 入口探针
SEC("uprobe/SSL_write")
int probe_entry_ssl_write(struct pt_regs *ctx) {
    __u64 pid_tgid = bpf_get_current_pid_tgid();
    __u32 pid = pid_tgid >> 32;
    
    // PID过滤检查
    if (should_filter_pid(pid)) {
        return 0; // 跳过此进程
    }
    
    struct ssl_args args;
    args.ssl = (void *)PT_REGS_PARM1(ctx);
    args.buf = (void *)PT_REGS_PARM2(ctx);
    args.num = (int)PT_REGS_PARM3(ctx);
    
    bpf_printk("DEBUG: SSL_write entry - pid=%u, ssl=%p", pid, args.ssl);
     bpf_printk("DEBUG: SSL_write entry - buf=%p, num=%d", args.buf, args.num);
    
    bpf_map_update_elem(&ssl_write_args, &pid_tgid, &args, BPF_ANY);
    
    // Mark this process as being in SSL operation
    __u8 flag = 1;
    bpf_map_update_elem(&ssl_operation_flag, &pid_tgid, &flag, BPF_ANY);
    
    // Store current SSL pointer for this process
    __u64 ssl_ptr = (__u64)args.ssl;
    bpf_map_update_elem(&current_ssl_ptr, &pid_tgid, &ssl_ptr, BPF_ANY);
    
    bpf_printk("DEBUG: SSL_write entry - Set SSL operation flag and stored ssl_ptr=%llx", ssl_ptr);
    
    return 0;
}

// SSL_write 返回探针（RINGBUF 优化版）
SEC("uretprobe/SSL_write")
int probe_return_ssl_write(struct pt_regs *ctx) {
    long ret = PT_REGS_RC(ctx);
    if (ret <= 0) return 0;

    __u64 pid_tgid = bpf_get_current_pid_tgid();
    __u32 pid = pid_tgid >> 32;
    
    // PID过滤检查
    if (should_filter_pid(pid)) {
        return 0; // 跳过此进程
    }
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
    
    // 清理相关map条目
    bpf_map_delete_elem(&ssl_write_args, &pid_tgid);
    
    // 构造SSL连接key进行清理
    struct ssl_conn_key key = {
        .pid_tgid = pid_tgid,
        .ssl_ptr = (__u64)args->ssl
    };
    bpf_map_delete_elem(&sock_storage, &key);
    
    // Clear SSL operation flag and current SSL pointer after SSL_write completes
    bpf_map_delete_elem(&ssl_operation_flag, &pid_tgid);
    bpf_map_delete_elem(&current_ssl_ptr, &pid_tgid);
    bpf_map_delete_elem(&active_ssl_sockets, &pid_tgid);
    
    return 0;
}

// SSL_read 入口探针
SEC("uprobe/SSL_read")
int probe_entry_ssl_read(struct pt_regs *ctx) {
    __u64 pid_tgid = bpf_get_current_pid_tgid();
    __u32 pid = pid_tgid >> 32;
    
    // PID过滤检查
    if (should_filter_pid(pid)) {
        return 0; // 跳过此进程
    }
    
    struct ssl_args args;
    args.ssl = (void *)PT_REGS_PARM1(ctx);
    args.buf = (void *)PT_REGS_PARM2(ctx);
    args.num = (int)PT_REGS_PARM3(ctx);
    
    bpf_printk("DEBUG: SSL_read entry - pid=%u, ssl=%p", pid, args.ssl);
     bpf_printk("DEBUG: SSL_read entry - buf=%p, num=%d", args.buf, args.num);
    
    // Mark this process as being in SSL operation
    __u8 flag = 1;
    bpf_map_update_elem(&ssl_operation_flag, &pid_tgid, &flag, BPF_ANY);
    
    bpf_map_update_elem(&ssl_read_args, &pid_tgid, &args, BPF_ANY);
    
    // Store current SSL pointer for this process
    __u64 ssl_ptr = (__u64)args.ssl;
    bpf_map_update_elem(&current_ssl_ptr, &pid_tgid, &ssl_ptr, BPF_ANY);
    
    bpf_printk("DEBUG: SSL_read entry - Set SSL operation flag and stored ssl_ptr=%llx", ssl_ptr);
    
    return 0;
}

// SSL_read 返回探针（对称逻辑）
SEC("uretprobe/SSL_read")
int probe_return_ssl_read(struct pt_regs *ctx) {
    long ret = PT_REGS_RC(ctx);
    if (ret <= 0) return 0;

    __u64 pid_tgid = bpf_get_current_pid_tgid();
    __u32 pid = pid_tgid >> 32;
    
    // PID过滤检查
    if (should_filter_pid(pid)) {
        return 0; // 跳过此进程
    }
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
    
    // 构造SSL连接key进行清理
    struct ssl_conn_key key = {
        .pid_tgid = pid_tgid,
        .ssl_ptr = (__u64)args->ssl
    };
    bpf_map_delete_elem(&sock_storage, &key);
    
    // Clear SSL operation flag and socket fd after SSL_read completes
    bpf_map_delete_elem(&ssl_operation_flag, &pid_tgid);
    bpf_map_delete_elem(&current_ssl_ptr, &pid_tgid);
    bpf_map_delete_elem(&active_ssl_sockets, &pid_tgid);
    
    return 0;
}


// 尝试从 fd_to_sock_map 中获取已缓存的 socket 结构体
static int get_socket_from_fd(__u32 sockfd, struct sock **sk_out) {
    if (!sk_out) {
        return -1;
    }
    
    __u64 pid_tgid = bpf_get_current_pid_tgid();
    struct fd_key key = {
        .pid_tgid = pid_tgid,
        .fd = sockfd
    };
    
    // 首先尝试从缓存的映射中获取
    struct sock **cached_sk = bpf_map_lookup_elem(&fd_to_sock_map, &key);
    if (cached_sk && *cached_sk) {
        *sk_out = *cached_sk;
        bpf_printk("DEBUG: get_socket_from_fd - found cached sock=%p for fd=%u", *cached_sk, sockfd);
        return 0;
    }
    
    bpf_printk("DEBUG: get_socket_from_fd - no cached socket for fd=%u", sockfd);
    return -1;
}

// 新增：使用 kprobe 监控 sock_sendmsg 来获取 socket 结构体
SEC("kprobe/sock_sendmsg")
int kprobe_sock_sendmsg(struct pt_regs *ctx) {
    __u64 pid_tgid = bpf_get_current_pid_tgid();
    __u32 pid = pid_tgid >> 32;
    
    if (should_filter_pid(pid)) {
        return 0;
    }
    
    // 检查是否在 SSL 操作中
    __u8 *flag = bpf_map_lookup_elem(&ssl_operation_flag, &pid_tgid);
    if (!flag || *flag != 1) {
        return 0;
    }
    
    // 从 kprobe 参数中获取 socket 结构体
    struct socket *sock = (struct socket *)PT_REGS_PARM1(ctx);
    if (!sock) {
        return 0;
    }
    
    // 从 socket 结构体中获取 sock 结构体
    struct sock *sk;
    if (bpf_probe_read_kernel(&sk, sizeof(sk), &sock->sk) != 0) {
        return 0;
    }
    
    if (!sk) {
        return 0;
    }
    
    // 获取当前的 SSL 指针
    __u64 *ssl_ptr = bpf_map_lookup_elem(&current_ssl_ptr, &pid_tgid);
    if (ssl_ptr) {
        struct ssl_conn_key key = {
            .pid_tgid = pid_tgid,
            .ssl_ptr = *ssl_ptr
        };
        
        // 存储 socket 结构体到 sock_storage
        bpf_map_update_elem(&sock_storage, &key, &sk, BPF_ANY);
        bpf_printk("DEBUG: kprobe_sock_sendmsg - stored sock=%p for SSL=%llx", sk, *ssl_ptr);
    }
    
    return 0;
}

// 新增：使用 kprobe 监控 sock_recvmsg 来获取 socket 结构体
SEC("kprobe/sock_recvmsg")
int kprobe_sock_recvmsg(struct pt_regs *ctx) {
    __u64 pid_tgid = bpf_get_current_pid_tgid();
    __u32 pid = pid_tgid >> 32;
    
    if (should_filter_pid(pid)) {
        return 0;
    }
    
    // 检查是否在 SSL 操作中
    __u8 *flag = bpf_map_lookup_elem(&ssl_operation_flag, &pid_tgid);
    if (!flag || *flag != 1) {
        return 0;
    }
    
    // 从 kprobe 参数中获取 socket 结构体
    struct socket *sock = (struct socket *)PT_REGS_PARM1(ctx);
    if (!sock) {
        return 0;
    }
    
    // 从 socket 结构体中获取 sock 结构体
    struct sock *sk;
    if (bpf_probe_read_kernel(&sk, sizeof(sk), &sock->sk) != 0) {
        return 0;
    }
    
    if (!sk) {
        return 0;
    }
    
    // 获取当前的 SSL 指针
    __u64 *ssl_ptr = bpf_map_lookup_elem(&current_ssl_ptr, &pid_tgid);
    if (ssl_ptr) {
        struct ssl_conn_key key = {
            .pid_tgid = pid_tgid,
            .ssl_ptr = *ssl_ptr
        };
        
        // 存储 socket 结构体到 sock_storage
        bpf_map_update_elem(&sock_storage, &key, &sk, BPF_ANY);
        bpf_printk("DEBUG: kprobe_sock_recvmsg - stored sock=%p for SSL=%llx", sk, *ssl_ptr);
    }
    
    return 0;
}

// 增强版 sendto 系统调用监控
SEC("tracepoint/syscalls/sys_enter_sendto")
int trace_enter_sendto(struct trace_event_raw_sys_enter *ctx) {
    __u64 pid_tgid = bpf_get_current_pid_tgid();
    __u32 pid = pid_tgid >> 32;
    
    // PID过滤检查
    if (should_filter_pid(pid)) {
        return 0; // 跳过此进程
    }
    
    // Check if this process is currently in SSL operation
    __u8 *flag = bpf_map_lookup_elem(&ssl_operation_flag, &pid_tgid);
    if (flag && *flag == 1) {
        __u32 sockfd = (__u32)ctx->args[0];
        bpf_printk("DEBUG: sys_enter_sendto - SSL active, sockfd=%u", sockfd);
        
        // 尝试通过系统调用参数获取 socket 信息
        __u64 *ssl_ptr = bpf_map_lookup_elem(&current_ssl_ptr, &pid_tgid);
        if (ssl_ptr) {
            // 在系统调用上下文中，我们可以尝试从参数中获取socket信息
            // 对于 sendto 系统调用，第一个参数是 socket 文件描述符
            // 我们可以尝试使用 BPF 辅助函数来获取相关信息
            
            // 注意：由于 eBPF 的限制，直接从文件描述符获取 socket 结构体比较困难
            // 这里我们记录文件描述符，后续可能需要通过其他方式关联
            bpf_printk("DEBUG: sys_enter_sendto - SSL active, sockfd=%u, ssl_ptr=%llx", sockfd, *ssl_ptr);
            
            // 存储文件描述符信息，用于后续关联
            struct fd_key fd_key = {
                .pid_tgid = pid_tgid,
                .fd = sockfd
            };
            
            // 这里我们暂时无法直接获取 sock 结构体
            // 但可以记录 fd 信息用于调试
            bpf_printk("DEBUG: sys_enter_sendto - Recorded fd=%d for SSL=%llx", sockfd, *ssl_ptr);
        }
        
        // Store socket fd for this SSL operation
        bpf_map_update_elem(&active_ssl_sockets, &pid_tgid, &sockfd, BPF_ANY);
    }
    
    return 0;
}

// 增强版 sendmsg 系统调用监控
SEC("tracepoint/syscalls/sys_enter_sendmsg")
int trace_enter_sendmsg(struct trace_event_raw_sys_enter *ctx) {
    __u64 pid_tgid = bpf_get_current_pid_tgid();
    __u32 pid = pid_tgid >> 32;
    
    if (should_filter_pid(pid)) {
        return 0;
    }
    
    __u8 *flag = bpf_map_lookup_elem(&ssl_operation_flag, &pid_tgid);
    if (flag && *flag == 1) {
        __u32 sockfd = (__u32)ctx->args[0];
        bpf_printk("DEBUG: sys_enter_sendmsg - SSL active, sockfd=%u", sockfd);
        
        // 尝试通过系统调用参数获取 socket 信息
        __u64 *ssl_ptr = bpf_map_lookup_elem(&current_ssl_ptr, &pid_tgid);
        if (ssl_ptr) {
            bpf_printk("DEBUG: sys_enter_sendmsg - SSL active, sockfd=%u, ssl_ptr=%llx", sockfd, *ssl_ptr);
            
            // 存储文件描述符信息
            struct fd_key fd_key = {
                .pid_tgid = pid_tgid,
                .fd = sockfd
            };
            
            bpf_printk("DEBUG: sys_enter_sendmsg - Recorded fd=%d for SSL=%llx", sockfd, *ssl_ptr);
        }
        
        bpf_map_update_elem(&active_ssl_sockets, &pid_tgid, &sockfd, BPF_ANY);
    }
    
    return 0;
}

// ========== 方案A：多SSL库uprobe支持 ==========

// SSL操作时间戳记录，用于扩展时间窗口
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(key_size, sizeof(__u64));  // pid_tgid
    __uint(value_size, sizeof(__u64)); // timestamp
    __uint(max_entries, 102400);
} ssl_operation_timestamp SEC(".maps");

// 扩展SSL操作时间窗口，提高socket关联成功率
static int extend_ssl_operation_window(__u64 pid_tgid) {
    __u64 current_time = bpf_ktime_get_ns();
    __u64 *start_time = bpf_map_lookup_elem(&ssl_operation_timestamp, &pid_tgid);
    
    if (!start_time) {
        // 首次SSL操作，记录开始时间
        bpf_map_update_elem(&ssl_operation_timestamp, &pid_tgid, &current_time, BPF_ANY);
        return 1; // 在窗口内
    }
    
    // 检查是否在时间窗口内（例如：500ms）
    __u64 window_ns = 500000000ULL; // 500ms
    if (current_time - *start_time < window_ns) {
        return 1; // 在窗口内
    }
    
    // 超出窗口，清理并重新开始
    bpf_map_delete_elem(&ssl_operation_timestamp, &pid_tgid);
    bpf_map_update_elem(&ssl_operation_timestamp, &pid_tgid, &current_time, BPF_ANY);
    return 1;
}

// GnuTLS库支持
// GnuTLS发送数据探针
SEC("uprobe/gnutls_record_send")
int probe_gnutls_record_send(struct pt_regs *ctx) {
    __u64 pid_tgid = bpf_get_current_pid_tgid();
    __u32 pid = pid_tgid >> 32;
    
    if (should_filter_pid(pid)) {
        return 0;
    }
    
    // GnuTLS session pointer
    void *session = (void *)PT_REGS_PARM1(ctx);
    __attribute__((unused)) void *data = (void *)PT_REGS_PARM2(ctx);
    size_t data_size = (size_t)PT_REGS_PARM3(ctx);
    
    bpf_printk("DEBUG: gnutls_record_send - session=%p, size=%lu", session, data_size);
    
    // 设置SSL操作标志
    __u8 flag = 1;
    bpf_map_update_elem(&ssl_operation_flag, &pid_tgid, &flag, BPF_ANY);
    
    // 存储GnuTLS session指针
    __u64 session_ptr = (__u64)session;
    bpf_map_update_elem(&current_ssl_ptr, &pid_tgid, &session_ptr, BPF_ANY);
    
    // 扩展时间窗口
    extend_ssl_operation_window(pid_tgid);
    
    return 0;
}

// GnuTLS接收数据探针
SEC("uprobe/gnutls_record_recv")
int probe_gnutls_record_recv(struct pt_regs *ctx) {
    __u64 pid_tgid = bpf_get_current_pid_tgid();
    __u32 pid = pid_tgid >> 32;
    
    if (should_filter_pid(pid)) {
        return 0;
    }
    
    void *session = (void *)PT_REGS_PARM1(ctx);
    __attribute__((unused)) void *data = (void *)PT_REGS_PARM2(ctx);
    size_t data_size = (size_t)PT_REGS_PARM3(ctx);
    
    bpf_printk("DEBUG: gnutls_record_recv - session=%p, size=%lu", session, data_size);
    
    __u8 flag = 1;
    bpf_map_update_elem(&ssl_operation_flag, &pid_tgid, &flag, BPF_ANY);
    
    __u64 session_ptr = (__u64)session;
    bpf_map_update_elem(&current_ssl_ptr, &pid_tgid, &session_ptr, BPF_ANY);
    
    extend_ssl_operation_window(pid_tgid);
    
    return 0;
}

// BoringSSL库支持（与OpenSSL API兼容，但可能有不同的符号）
// BoringSSL写入探针
SEC("uprobe/SSL_write_ex")
int probe_ssl_write_ex(struct pt_regs *ctx) {
    __u64 pid_tgid = bpf_get_current_pid_tgid();
    __u32 pid = pid_tgid >> 32;
    
    if (should_filter_pid(pid)) {
        return 0;
    }
    
    void *ssl = (void *)PT_REGS_PARM1(ctx);
    __attribute__((unused)) void *buf = (void *)PT_REGS_PARM2(ctx);
    size_t num = (size_t)PT_REGS_PARM3(ctx);
    
    bpf_printk("DEBUG: SSL_write_ex - ssl=%p, size=%lu", ssl, num);
    
    __u8 flag = 1;
    bpf_map_update_elem(&ssl_operation_flag, &pid_tgid, &flag, BPF_ANY);
    
    __u64 ssl_ptr = (__u64)ssl;
    bpf_map_update_elem(&current_ssl_ptr, &pid_tgid, &ssl_ptr, BPF_ANY);
    
    extend_ssl_operation_window(pid_tgid);
    
    return 0;
}

// BoringSSL读取探针
SEC("uprobe/SSL_read_ex")
int probe_ssl_read_ex(struct pt_regs *ctx) {
    __u64 pid_tgid = bpf_get_current_pid_tgid();
    __u32 pid = pid_tgid >> 32;
    
    if (should_filter_pid(pid)) {
        return 0;
    }
    
    void *ssl = (void *)PT_REGS_PARM1(ctx);
    __attribute__((unused)) void *buf = (void *)PT_REGS_PARM2(ctx);
    size_t num = (size_t)PT_REGS_PARM3(ctx);
    
    bpf_printk("DEBUG: SSL_read_ex - ssl=%p, size=%lu", ssl, num);
    
    __u8 flag = 1;
    bpf_map_update_elem(&ssl_operation_flag, &pid_tgid, &flag, BPF_ANY);
    
    __u64 ssl_ptr = (__u64)ssl;
    bpf_map_update_elem(&current_ssl_ptr, &pid_tgid, &ssl_ptr, BPF_ANY);
    
    extend_ssl_operation_window(pid_tgid);
    
    return 0;
}

// Go crypto/tls库支持
// Go TLS连接写入探针
SEC("uprobe/crypto/tls.(*Conn).Write")
int probe_go_tls_write(struct pt_regs *ctx) {
    __u64 pid_tgid = bpf_get_current_pid_tgid();
    __u32 pid = pid_tgid >> 32;
    
    if (should_filter_pid(pid)) {
        return 0;
    }
    
    // Go接口参数获取比较复杂，这里简化处理
    void *conn = (void *)PT_REGS_PARM1(ctx);
    
    bpf_printk("DEBUG: go_tls_write - conn=%p", conn);
    
    __u8 flag = 1;
    bpf_map_update_elem(&ssl_operation_flag, &pid_tgid, &flag, BPF_ANY);
    
    __u64 conn_ptr = (__u64)conn;
    bpf_map_update_elem(&current_ssl_ptr, &pid_tgid, &conn_ptr, BPF_ANY);
    
    extend_ssl_operation_window(pid_tgid);
    
    return 0;
}

// Go TLS连接读取探针
SEC("uprobe/crypto/tls.(*Conn).Read")
int probe_go_tls_read(struct pt_regs *ctx) {
    __u64 pid_tgid = bpf_get_current_pid_tgid();
    __u32 pid = pid_tgid >> 32;
    
    if (should_filter_pid(pid)) {
        return 0;
    }
    
    void *conn = (void *)PT_REGS_PARM1(ctx);
    
    bpf_printk("DEBUG: go_tls_read - conn=%p", conn);
    
    __u8 flag = 1;
    bpf_map_update_elem(&ssl_operation_flag, &pid_tgid, &flag, BPF_ANY);
    
    __u64 conn_ptr = (__u64)conn;
    bpf_map_update_elem(&current_ssl_ptr, &pid_tgid, &conn_ptr, BPF_ANY);
    
    extend_ssl_operation_window(pid_tgid);
    
    return 0;
}

// 监控write系统调用入口
SEC("tracepoint/syscalls/sys_enter_write")
int trace_enter_write(struct trace_event_raw_sys_enter *ctx) {
    __u64 pid_tgid = bpf_get_current_pid_tgid();
    __u32 pid = pid_tgid >> 32;
    
    if (should_filter_pid(pid)) {
        return 0;
    }
    
    __u8 *flag = bpf_map_lookup_elem(&ssl_operation_flag, &pid_tgid);
    if (flag && *flag == 1) {
        __u32 sockfd = (__u32)ctx->args[0];
        bpf_printk("DEBUG: sys_enter_write - SSL active, sockfd=%u", sockfd);
        bpf_map_update_elem(&active_ssl_sockets, &pid_tgid, &sockfd, BPF_ANY);
    }
    
    return 0;
}

// Hook into socket-related kernel functions to capture sock structures

SEC("kprobe/tcp_sendmsg")
int trace_tcp_sendmsg(struct pt_regs *ctx) {
    __u64 pid_tgid = bpf_get_current_pid_tgid();
    __u32 pid = pid_tgid >> 32;
    
    // PID过滤检查
    if (should_filter_pid(pid)) {
        return 0; // 跳过此进程
    }
    
    // Check if this process is currently in an SSL operation
    __u8 *flag = bpf_map_lookup_elem(&ssl_operation_flag, &pid_tgid);
    if (flag && *flag == 1) {
        bpf_printk("DEBUG: tcp_sendmsg - SSL operation active for pid_tgid=%llx", pid_tgid);
        // Get the current SSL pointer for this process
        __u64 *ssl_ptr = bpf_map_lookup_elem(&current_ssl_ptr, &pid_tgid);
        if (ssl_ptr) {
            // Get sock structure from first argument of tcp_sendmsg
            struct sock *sk = (struct sock *)PT_REGS_PARM1(ctx);
            if (sk) {
                // 构造SSL连接key
                struct ssl_conn_key key = {
                    .pid_tgid = pid_tgid,
                    .ssl_ptr = *ssl_ptr
                };
                bpf_printk("DEBUG: tcp_sendmsg - Storing sock=%p for SSL=%llx, pid_tgid=%llx", sk, *ssl_ptr, pid_tgid);
                // Store the sock structure in sock_storage with SSL-specific key
                int ret = bpf_map_update_elem(&sock_storage, &key, &sk, BPF_ANY);
                if (ret != 0) {
                    bpf_printk("DEBUG: tcp_sendmsg - Failed to store sock, ret=%d", ret);
                } else {
                    bpf_printk("DEBUG: tcp_sendmsg - Successfully stored sock");
                }
            } else {
                bpf_printk("DEBUG: tcp_sendmsg - sk is NULL");
            }
        } else {
            bpf_printk("DEBUG: tcp_sendmsg - ssl_ptr not found");
        }
    }
    
    return 0;
}

SEC("kprobe/tcp_recvmsg")
int trace_tcp_recvmsg(struct pt_regs *ctx) {
    __u64 pid_tgid = bpf_get_current_pid_tgid();
    __u32 pid = pid_tgid >> 32;
    
    // PID过滤检查
    if (should_filter_pid(pid)) {
        return 0; // 跳过此进程
    }
    
    // Check if this process is currently in an SSL operation
    __u8 *flag = bpf_map_lookup_elem(&ssl_operation_flag, &pid_tgid);
    if (flag && *flag == 1) {
        bpf_printk("DEBUG: tcp_recvmsg - SSL operation active for pid_tgid=%llx", pid_tgid);
        // Get the current SSL pointer for this process
        __u64 *ssl_ptr = bpf_map_lookup_elem(&current_ssl_ptr, &pid_tgid);
        if (ssl_ptr) {
            // Get sock structure from first argument of tcp_recvmsg
            struct sock *sk = (struct sock *)PT_REGS_PARM1(ctx);
            if (sk) {
                // 构造SSL连接key
                struct ssl_conn_key key = {
                    .pid_tgid = pid_tgid,
                    .ssl_ptr = *ssl_ptr
                };
                bpf_printk("DEBUG: tcp_recvmsg - Storing sock=%p for SSL=%llx, pid_tgid=%llx", sk, *ssl_ptr, pid_tgid);
                // Store the sock structure in sock_storage with SSL-specific key
                int ret = bpf_map_update_elem(&sock_storage, &key, &sk, BPF_ANY);
                if (ret != 0) {
                    bpf_printk("DEBUG: tcp_recvmsg - Failed to store sock, ret=%d", ret);
                } else {
                    bpf_printk("DEBUG: tcp_recvmsg - Successfully stored sock");
                }
            } else {
                bpf_printk("DEBUG: tcp_recvmsg - sk is NULL");
            }
        } else {
            bpf_printk("DEBUG: tcp_recvmsg - ssl_ptr not found");
        }
    }
    
    return 0;
}

// 方案A第二层：更多TCP层探针，提高socket捕获的稳定性
// TCP数据队列探针 - 捕获更底层的TCP操作
SEC("kprobe/tcp_data_queue")
int trace_tcp_data_queue(struct pt_regs *ctx) {
    __u64 pid_tgid = bpf_get_current_pid_tgid();
    __u32 pid = pid_tgid >> 32;
    
    if (should_filter_pid(pid)) {
        return 0;
    }
    
    __u8 *flag = bpf_map_lookup_elem(&ssl_operation_flag, &pid_tgid);
    if (flag && *flag == 1) {
        __u64 *ssl_ptr = bpf_map_lookup_elem(&current_ssl_ptr, &pid_tgid);
        if (ssl_ptr) {
            struct sock *sk = (struct sock *)PT_REGS_PARM1(ctx);
            if (sk) {
                struct ssl_conn_key key = {
                    .pid_tgid = pid_tgid,
                    .ssl_ptr = *ssl_ptr
                };
                bpf_printk("DEBUG: tcp_data_queue - Storing sock=%p for SSL=%llx", sk, *ssl_ptr);
                bpf_map_update_elem(&sock_storage, &key, &sk, BPF_ANY);
            }
        }
    }
    
    return 0;
}

// TCP写入传输探针
SEC("kprobe/tcp_write_xmit")
int trace_tcp_write_xmit(struct pt_regs *ctx) {
    __u64 pid_tgid = bpf_get_current_pid_tgid();
    __u32 pid = pid_tgid >> 32;
    
    if (should_filter_pid(pid)) {
        return 0;
    }
    
    __u8 *flag = bpf_map_lookup_elem(&ssl_operation_flag, &pid_tgid);
    if (flag && *flag == 1) {
        __u64 *ssl_ptr = bpf_map_lookup_elem(&current_ssl_ptr, &pid_tgid);
        if (ssl_ptr) {
            struct sock *sk = (struct sock *)PT_REGS_PARM1(ctx);
            if (sk) {
                struct ssl_conn_key key = {
                    .pid_tgid = pid_tgid,
                    .ssl_ptr = *ssl_ptr
                };
                bpf_printk("DEBUG: tcp_write_xmit - Storing sock=%p for SSL=%llx", sk, *ssl_ptr);
                bpf_map_update_elem(&sock_storage, &key, &sk, BPF_ANY);
            }
        }
    }
    
    return 0;
}

// TCP推送待发送帧探针
SEC("kprobe/__tcp_push_pending_frames")
int trace_tcp_push_pending_frames(struct pt_regs *ctx) {
    __u64 pid_tgid = bpf_get_current_pid_tgid();
    __u32 pid = pid_tgid >> 32;
    
    if (should_filter_pid(pid)) {
        return 0;
    }
    
    __u8 *flag = bpf_map_lookup_elem(&ssl_operation_flag, &pid_tgid);
    if (flag && *flag == 1) {
        __u64 *ssl_ptr = bpf_map_lookup_elem(&current_ssl_ptr, &pid_tgid);
        if (ssl_ptr) {
            struct sock *sk = (struct sock *)PT_REGS_PARM1(ctx);
            if (sk) {
                struct ssl_conn_key key = {
                    .pid_tgid = pid_tgid,
                    .ssl_ptr = *ssl_ptr
                };
                bpf_printk("DEBUG: tcp_push_pending_frames - Storing sock=%p for SSL=%llx", sk, *ssl_ptr);
                bpf_map_update_elem(&sock_storage, &key, &sk, BPF_ANY);
            }
        }
    }
    
    return 0;
}

// 增强版 recvfrom 系统调用监控
SEC("tracepoint/syscalls/sys_enter_recvfrom")
int trace_enter_recvfrom(struct trace_event_raw_sys_enter *ctx) {
    __u64 pid_tgid = bpf_get_current_pid_tgid();
    __u32 pid = pid_tgid >> 32;
    
    // PID过滤检查
    if (should_filter_pid(pid)) {
        return 0; // 跳过此进程
    }
    
    // Check if this process is currently in SSL operation
    __u8 *flag = bpf_map_lookup_elem(&ssl_operation_flag, &pid_tgid);
    if (flag && *flag == 1) {
        __u32 sockfd = (__u32)ctx->args[0];
        bpf_printk("DEBUG: sys_enter_recvfrom - SSL active, sockfd=%u", sockfd);
        
        // 尝试从 sockfd 获取 socket 信息并存储到 sock_storage
        __u64 *ssl_ptr = bpf_map_lookup_elem(&current_ssl_ptr, &pid_tgid);
        if (ssl_ptr) {
            struct sock *sk = NULL;
            if (get_socket_from_fd(sockfd, &sk) == 0 && sk) {
                struct ssl_conn_key key = {
                    .pid_tgid = pid_tgid,
                    .ssl_ptr = *ssl_ptr
                };
                bpf_printk("DEBUG: sys_enter_recvfrom - Storing sock=%p for SSL=%llx", sk, *ssl_ptr);
                bpf_map_update_elem(&sock_storage, &key, &sk, BPF_ANY);
            } else {
                bpf_printk("DEBUG: sys_enter_recvfrom - Failed to get socket from fd=%u", sockfd);
            }
        }
        
        // Store socket fd for this SSL operation
        bpf_map_update_elem(&active_ssl_sockets, &pid_tgid, &sockfd, BPF_ANY);
    }
    
    return 0;
}

// 增强版 recvmsg 系统调用监控
SEC("tracepoint/syscalls/sys_enter_recvmsg")
int trace_enter_recvmsg(struct trace_event_raw_sys_enter *ctx) {
    __u64 pid_tgid = bpf_get_current_pid_tgid();
    __u32 pid = pid_tgid >> 32;
    
    if (should_filter_pid(pid)) {
        return 0;
    }
    
    __u8 *flag = bpf_map_lookup_elem(&ssl_operation_flag, &pid_tgid);
    if (flag && *flag == 1) {
        __u32 sockfd = (__u32)ctx->args[0];
        bpf_printk("DEBUG: sys_enter_recvmsg - SSL active, sockfd=%u", sockfd);
        
        // 尝试从 sockfd 获取 socket 信息并存储到 sock_storage
        __u64 *ssl_ptr = bpf_map_lookup_elem(&current_ssl_ptr, &pid_tgid);
        if (ssl_ptr) {
            struct sock *sk = NULL;
            if (get_socket_from_fd(sockfd, &sk) == 0 && sk) {
                struct ssl_conn_key key = {
                    .pid_tgid = pid_tgid,
                    .ssl_ptr = *ssl_ptr
                };
                bpf_printk("DEBUG: sys_enter_recvmsg - Storing sock=%p for SSL=%llx", sk, *ssl_ptr);
                bpf_map_update_elem(&sock_storage, &key, &sk, BPF_ANY);
            }
        }
        
        bpf_map_update_elem(&active_ssl_sockets, &pid_tgid, &sockfd, BPF_ANY);
    }
    
    return 0;
}

// 增强版 read 系统调用监控
SEC("tracepoint/syscalls/sys_enter_read")
int trace_enter_read(struct trace_event_raw_sys_enter *ctx) {
    __u64 pid_tgid = bpf_get_current_pid_tgid();
    __u32 pid = pid_tgid >> 32;
    
    if (should_filter_pid(pid)) {
        return 0;
    }
    
    __u8 *flag = bpf_map_lookup_elem(&ssl_operation_flag, &pid_tgid);
    if (flag && *flag == 1) {
        __u32 sockfd = (__u32)ctx->args[0];
        bpf_printk("DEBUG: sys_enter_read - SSL active, sockfd=%u", sockfd);
        
        // 尝试从 sockfd 获取 socket 信息并存储到 sock_storage
        __u64 *ssl_ptr = bpf_map_lookup_elem(&current_ssl_ptr, &pid_tgid);
        if (ssl_ptr) {
            struct sock *sk = NULL;
            if (get_socket_from_fd(sockfd, &sk) == 0 && sk) {
                struct ssl_conn_key key = {
                    .pid_tgid = pid_tgid,
                    .ssl_ptr = *ssl_ptr
                };
                bpf_printk("DEBUG: sys_enter_read - Storing sock=%p for SSL=%llx", sk, *ssl_ptr);
                bpf_map_update_elem(&sock_storage, &key, &sk, BPF_ANY);
            }
        }
        
        bpf_map_update_elem(&active_ssl_sockets, &pid_tgid, &sockfd, BPF_ANY);
    }
    
    return 0;
}

// 新增：socket系统调用hook，用于在socket创建时就建立fd到sock的映射
// 这样可以避免后续通过SSL提取fd时找不到对应sock的问题

// socket系统调用hook
SEC("tracepoint/syscalls/sys_enter_socket")
int trace_enter_socket(struct trace_event_raw_sys_enter *ctx) {
    __u64 pid_tgid = bpf_get_current_pid_tgid();
    __u32 pid = pid_tgid >> 32;
    
    if (should_filter_pid(pid)) {
        return 0;
    }
    
    // 记录socket调用的进程ID，用于后续在返回探针中关联fd和sock
    __u8 flag = 1;
    bpf_map_update_elem(&ssl_operation_flag, &pid_tgid, &flag, BPF_ANY);
    
    bpf_printk("DEBUG: sys_enter_socket - pid=%u, tracking for fd-sock mapping", pid);
    return 0;
}

// socket系统调用返回hook
SEC("tracepoint/syscalls/sys_exit_socket")
int trace_exit_socket(struct trace_event_raw_sys_exit *ctx) {
    __u64 pid_tgid = bpf_get_current_pid_tgid();
    __u32 pid = pid_tgid >> 32;
    
    if (should_filter_pid(pid)) {
        return 0;
    }
    
    // 获取socket系统调用返回的文件描述符
    int sockfd = ctx->ret;
    if (sockfd < 0) {
        return 0; // socket创建失败
    }
    
    bpf_printk("DEBUG: sys_exit_socket - pid=%u, new sockfd=%d", pid, sockfd);
    
    // 尝试获取这个新创建的socket对应的sock结构体
    struct sock *sk = NULL;
    if (get_socket_from_fd(sockfd, &sk) == 0 && sk) {
        // 创建fd到sock的映射
        bpf_printk("DEBUG: sys_exit_socket - SUCCESS: mapped sockfd=%d to sock=%p", sockfd, sk);
        
        // 存储到fd_to_sock映射表中
        // 注意：需要新增一个BPF map用于存储fd到sock的映射
        struct fd_key key = {
            .pid_tgid = pid_tgid,
            .fd = sockfd
        };
        bpf_map_update_elem(&fd_to_sock_map, &key, &sk, BPF_ANY);
    } else {
        bpf_printk("DEBUG: sys_exit_socket - FAILED: could not get sock for sockfd=%d", sockfd);
    }
    
    return 0;
}

// connect系统调用hook
SEC("tracepoint/syscalls/sys_enter_connect")
int trace_enter_connect(struct trace_event_raw_sys_enter *ctx) {
    __u64 pid_tgid = bpf_get_current_pid_tgid();
    __u32 pid = pid_tgid >> 32;
    
    if (should_filter_pid(pid)) {
        return 0;
    }
    
    // 获取connect的文件描述符
    int sockfd = ctx->args[0];
    bpf_printk("DEBUG: sys_enter_connect - pid=%u, sockfd=%d", pid, sockfd);
    
    // 尝试获取这个socket对应的sock结构体
    struct sock *sk = NULL;
    if (get_socket_from_fd(sockfd, &sk) == 0 && sk) {
        // 创建fd到sock的映射
        bpf_printk("DEBUG: sys_enter_connect - SUCCESS: mapped sockfd=%d to sock=%p", sockfd, sk);
        
        // 存储到fd_to_sock映射表中
        struct fd_key key = {
            .pid_tgid = pid_tgid,
            .fd = sockfd
        };
        bpf_map_update_elem(&fd_to_sock_map, &key, &sk, BPF_ANY);
        
        // 如果当前进程正在进行SSL操作，也更新sock_storage
        __u8 *flag = bpf_map_lookup_elem(&ssl_operation_flag, &pid_tgid);
        if (flag && *flag == 1) {
            __u64 *ssl_ptr = bpf_map_lookup_elem(&current_ssl_ptr, &pid_tgid);
            if (ssl_ptr) {
                struct ssl_conn_key ssl_key = {
                    .pid_tgid = pid_tgid,
                    .ssl_ptr = *ssl_ptr
                };
                bpf_printk("DEBUG: sys_enter_connect - Updating sock_storage for SSL=%llx", *ssl_ptr);
                bpf_map_update_elem(&sock_storage, &ssl_key, &sk, BPF_ANY);
            }
        }
    }
    
    return 0;
}

// accept系统调用返回hook
SEC("tracepoint/syscalls/sys_exit_accept")
int trace_exit_accept(struct trace_event_raw_sys_exit *ctx) {
    __u64 pid_tgid = bpf_get_current_pid_tgid();
    __u32 pid = pid_tgid >> 32;
    
    if (should_filter_pid(pid)) {
        return 0;
    }
    
    // 获取accept返回的新文件描述符
    int sockfd = ctx->ret;
    if (sockfd < 0) {
        return 0; // accept失败
    }
    
    bpf_printk("DEBUG: sys_exit_accept - pid=%u, new sockfd=%d", pid, sockfd);
    
    // 尝试获取这个新接受的socket对应的sock结构体
    struct sock *sk = NULL;
    if (get_socket_from_fd(sockfd, &sk) == 0 && sk) {
        // 创建fd到sock的映射
        bpf_printk("DEBUG: sys_exit_accept - SUCCESS: mapped sockfd=%d to sock=%p", sockfd, sk);
        
        // 存储到fd_to_sock映射表中
        struct fd_key key = {
            .pid_tgid = pid_tgid,
            .fd = sockfd
        };
        bpf_map_update_elem(&fd_to_sock_map, &key, &sk, BPF_ANY);
    }
    
    return 0;
}

char LICENSE[] SEC("license") = "GPL";