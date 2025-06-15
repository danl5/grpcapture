// maps.h - BPF Maps定义
#ifndef __MAPS_H__
#define __MAPS_H__

#include "common.h"

// 活跃SSL缓冲区结构
struct active_ssl_buf {
    s32 version;
    u32 fd;
    const char* buf;
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

// SSL对象到文件描述符的映射（参考ecapture的ssl_st_fd）
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(key_size, sizeof(__u64));    // SSL指针
    __uint(value_size, sizeof(__u64));  // 文件描述符
    __uint(max_entries, 10240);
} ssl_st_fd SEC(".maps");

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

// 用于存储从网络系统调用中获取的sock结构体
// 使用SSL连接标识作为key，支持一个进程内的多个SSL连接
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(key_size, sizeof(struct ssl_conn_key));
    __uint(value_size, sizeof(struct sock *));
    __uint(max_entries, 20480);  // 调整大小更合理
} sock_storage SEC(".maps");

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

// 每CPU数据缓冲区（用于减少内存分配开销）
struct {
    __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
    __uint(key_size, sizeof(__u32));
    __uint(value_size, MAX_DATA_SIZE);  // 16KB数据缓冲区
    __uint(max_entries, 1);
} data_buffer_heap SEC(".maps");

#endif // __MAPS_H__