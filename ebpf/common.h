// common.h - 公共头文件和数据结构定义
#ifndef __COMMON_H__
#define __COMMON_H__

#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_endian.h>

// 调试模式控制
// 设置为1启用调试输出，设置为0禁用调试输出
#ifndef DEBUG_MODE
#define DEBUG_MODE 0
#endif

// 调试打印宏 - 仅在DEBUG_MODE为1时启用
#if DEBUG_MODE
#define DEBUG_PRINT(fmt, ...) bpf_printk(fmt, ##__VA_ARGS__)
#else
#define DEBUG_PRINT(fmt, ...) do { } while (0)
#endif

// 字节序转换宏定义
#ifndef bpf_ntohl
#define bpf_ntohl(x) __bpf_ntohl(x)
#endif

#ifndef bpf_ntohs
#define bpf_ntohs(x) __bpf_ntohs(x)
#endif

#define MAX_DATA_SIZE 16384
#define MAX_ENTRIES 102400
#define COMM_LEN 16
#define MIN_DATA_SIZE 1   // 最小数据长度过滤（数据包抓取场景）
#define TASK_COMM_LEN 16  // 进程名长度

// TCP连接四元组信息
struct tcp_tuple {
    __u32 saddr;   // 源IP地址
    __u32 daddr;   // 目标IP地址
    __u16 sport;   // 源端口
    __u16 dport;   // 目标端口
    __u16 family;  // 地址族 (AF_INET)
} __attribute__((packed));

// 统一的TLS元数据结构
struct meta {
    __u64 timestamp_ns;
    __u32 pid;
    __u32 tid;
    __u32 data_len;
    __u8 is_read;           // 0 for write, 1 for read
    __u8 tuple_valid;       // 1 if tuple is valid, 0 otherwise
    __u8 _pad[2];           // 对齐填充
    char comm[COMM_LEN];
    __u64 ssl_ptr;
    __u64 conn_id;
    struct tcp_tuple tuple;
} __attribute__((packed));

struct tls_event {
    struct meta meta;
    __u8 _pad[2]; // 对齐填充
    __u8 data[MAX_DATA_SIZE];
} __attribute__((packed));

// 参数缓存结构
struct ssl_args {
    const void *ssl;
    const void *buf;
    int num;
} __attribute__((packed));

// SSL连接标识结构体 - 用作更精确的key
struct ssl_conn_key {
    __u64 pid_tgid;    // 进程/线程ID
    __u64 ssl_ptr;     // SSL结构体指针
} __attribute__((packed));

// 文件描述符到sock结构体的映射key
struct fd_key {
    __u64 pid_tgid;    // 进程/线程ID
    __u32 fd;          // 文件描述符
    __u32 pad;         // 显式填充到8字节对齐
} __attribute__((packed));

// TCP连接信息结构
struct tcp_fd_info {
    __u64 sock;           // socket指针
    __u32 fd;             // 文件描述符
    __u16 family;         // 地址族（AF_INET/AF_INET6）
    __u32 saddr, daddr;   // 源/目标IP地址
    __u16 sport, dport;   // 源/目标端口
    __u64 timestamp;      // 连接建立时间戳
};

// 存储sys_connect/accept调用的参数
struct connect_args {
    __u64 sock_addr;      // socket地址
    __u32 fd;
    __u64 timestamp;
};

// 连接事件结构
struct connect_event_t {
    __u64 timestamp_ns;
    __u32 pid;
    __u64 tid;
    __u32 fd;
    __u16 family;
    __u16 sport, dport;
    __u32 saddr, daddr;
    char comm[16];
    __u64 sock;
    __u8 is_destroy;      // 是否为连接销毁事件
    __u8 pad[7];          // 对齐填充
};

// PID过滤函数
static int should_filter_pid(__u32 pid);

// 尝试从 fd_to_sock_map 中获取已缓存的 socket 结构体
static int get_socket_from_fd(__u32 sockfd, struct sock **sk_out);

#endif // __COMMON_H__