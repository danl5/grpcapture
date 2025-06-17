// maps.h - BPF Maps定义
#ifndef __MAPS_H__
#define __MAPS_H__

#include "common.h"

// 活跃SSL缓冲区结构
struct active_ssl_buf {
    s32 version;
    u32 fd;
    const char* buf;
    u64 ssl_ptr;  // SSL结构体指针
};

// 读写参数缓存Map
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(key_size, sizeof(__u64));
    __uint(value_size, sizeof(struct active_ssl_buf));
    __uint(max_entries, MAX_ENTRIES);
} ssl_read_args SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(key_size, sizeof(__u64));
    __uint(value_size, sizeof(struct active_ssl_buf));
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

// SSL对象到文件描述符的映射已移至用户态管理
// 通过ssl_set_fd_events事件进行映射维护

// 文件描述符到TCP连接信息的映射
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(key_size, sizeof(__u32));    // 文件描述符
    __uint(value_size, sizeof(struct tcp_fd_info));
    __uint(max_entries, 10240);
} tcp_fd_infos SEC(".maps");

// 存储sys_connect/accept调用的参数
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(key_size, sizeof(__u64));    // pid_tgid
    __uint(value_size, sizeof(struct connect_args));
    __uint(max_entries, 10240);
} active_connect_args SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(key_size, sizeof(__u64));    // pid_tgid
    __uint(value_size, sizeof(struct connect_args));
    __uint(max_entries, 10240);
} active_accept_args SEC(".maps");

// sock_storage映射已移除，映射管理已移至用户态

// 文件描述符到sock结构体的映射
// 使用pid_tgid+fd作为key，直接映射到sock结构体
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(key_size, sizeof(struct fd_key));
    __uint(value_size, sizeof(struct sock *));
    __uint(max_entries, 102400);
} fd_to_sock_map SEC(".maps");



// 连接事件输出（可选：如果需要单独跟踪连接事件）
struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 64 * 1024 * 1024); // 64MB
} connect_events SEC(".maps");

// SSL设置FD事件输出
struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 16 * 1024 * 1024); // 16MB
} ssl_set_fd_events SEC(".maps");

// 每CPU数据缓冲区（用于减少内存分配开销）
struct {
    __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
    __uint(key_size, sizeof(__u32));
    __uint(value_size, MAX_DATA_SIZE);  // 16KB数据缓冲区
    __uint(max_entries, 1);
} data_buffer_heap SEC(".maps");

#endif // __MAPS_H__