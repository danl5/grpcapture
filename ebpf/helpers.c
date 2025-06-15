// helpers.c - 辅助函数实现
#include "common.h"
#include "maps.h"

// PID过滤检查函数
static inline int should_filter_pid(__u32 pid) {
    // 检查PID过滤映射
    __u8 *filter_enabled = bpf_map_lookup_elem(&pid_filter, &pid);
    if (filter_enabled && *filter_enabled == 1) {
        return 0; // 不过滤，允许通过
    }
    
    // 如果映射为空或者PID不在映射中，检查是否启用了过滤
    __u32 zero = 0;
    __u8 *global_filter = bpf_map_lookup_elem(&filter_config, &zero);
    if (global_filter && *global_filter == 1) {
        return 1; // 启用了过滤且PID不在白名单中，过滤掉
    }
    
    return 0; // 默认不过滤
}



// 查找并删除fd信息
static struct tcp_fd_info* lookup_and_delete_fd_info(struct pt_regs* ctx) {
    __u64 pid_tgid = bpf_get_current_pid_tgid();
    
    struct tcp_fd_info *fd_info = bpf_map_lookup_elem(&tcp_fd_infos, &pid_tgid);
    if (fd_info) {
        bpf_map_delete_elem(&tcp_fd_infos, &pid_tgid);
        return fd_info;
    }
    
    return NULL;
}



// 尝试从 fd_to_sock_map 中获取已缓存的 socket 结构体
static int get_socket_from_fd(__u32 sockfd, struct sock **sk_out) {
    if (!sk_out) {
        return -1;
    }
    
    __u64 pid_tgid = bpf_get_current_pid_tgid();
    struct fd_key key = {
        .pid_tgid = pid_tgid,
        .fd = sockfd,
        .pad = 0
    };
    
    // 首先尝试从缓存的映射中获取
    struct sock **cached_sk = bpf_map_lookup_elem(&fd_to_sock_map, &key);
    if (cached_sk && *cached_sk) {
        *sk_out = *cached_sk;
        DEBUG_PRINT("DEBUG: get_socket_from_fd - found cached sock=%p for fd=%u", *cached_sk, sockfd);
        return 0;
    }
    
    DEBUG_PRINT("DEBUG: get_socket_from_fd - no cached socket for fd=%u", sockfd);
    return -1;
}