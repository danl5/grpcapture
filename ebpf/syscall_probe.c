// syscall_probe.c - 系统调用和内核挂载点
#include "common.h"
#include "maps.h"

// 系统调用探针
// sendto系统调用入口探针
SEC("tracepoint/syscalls/sys_enter_sendto")
int trace_enter_sendto(struct trace_event_raw_sys_enter *ctx) {
    __u64 pid_tgid = bpf_get_current_pid_tgid();
    __u32 pid = pid_tgid >> 32;
    
    if (should_filter_pid(pid)) {
        return 0;
    }
    
    __u8 *flag = bpf_map_lookup_elem(&ssl_operation_flag, &pid_tgid);
    if (!flag || *flag != 1) {
        return 0;
    }
    
    __u32 fd = (__u32)ctx->args[0];
    bpf_map_update_elem(&active_ssl_sockets, &pid_tgid, &fd, BPF_ANY);
    
    return 0;
}

// sendmsg系统调用入口探针
SEC("tracepoint/syscalls/sys_enter_sendmsg")
int trace_enter_sendmsg(struct trace_event_raw_sys_enter *ctx) {
    __u64 pid_tgid = bpf_get_current_pid_tgid();
    __u32 pid = pid_tgid >> 32;
    
    if (should_filter_pid(pid)) {
        return 0;
    }
    
    __u8 *flag = bpf_map_lookup_elem(&ssl_operation_flag, &pid_tgid);
    if (!flag || *flag != 1) {
        return 0;
    }
    
    __u32 fd = (__u32)ctx->args[0];
    bpf_map_update_elem(&active_ssl_sockets, &pid_tgid, &fd, BPF_ANY);
    
    return 0;
}

// write系统调用入口探针
SEC("tracepoint/syscalls/sys_enter_write")
int trace_enter_write(struct trace_event_raw_sys_enter *ctx) {
    __u64 pid_tgid = bpf_get_current_pid_tgid();
    __u32 pid = pid_tgid >> 32;
    
    if (should_filter_pid(pid)) {
        return 0;
    }
    
    __u8 *flag = bpf_map_lookup_elem(&ssl_operation_flag, &pid_tgid);
    if (!flag || *flag != 1) {
        return 0;
    }
    
    __u32 fd = (__u32)ctx->args[0];
    bpf_map_update_elem(&active_ssl_sockets, &pid_tgid, &fd, BPF_ANY);
    
    return 0;
}

// recvfrom系统调用入口探针
SEC("tracepoint/syscalls/sys_enter_recvfrom")
int trace_enter_recvfrom(struct trace_event_raw_sys_enter *ctx) {
    __u64 pid_tgid = bpf_get_current_pid_tgid();
    __u32 pid = pid_tgid >> 32;
    
    if (should_filter_pid(pid)) {
        return 0;
    }
    
    __u8 *flag = bpf_map_lookup_elem(&ssl_operation_flag, &pid_tgid);
    if (!flag || *flag != 1) {
        return 0;
    }
    
    __u32 fd = (__u32)ctx->args[0];
    
    struct sock *sk = NULL;
    if (get_socket_from_fd(fd, &sk) == 0 && sk) {
        __u64 *ssl_ptr = bpf_map_lookup_elem(&current_ssl_ptr, &pid_tgid);
        if (ssl_ptr) {
            struct ssl_conn_key key = {
                .pid_tgid = pid_tgid,
                .ssl_ptr = *ssl_ptr
            };
            bpf_map_update_elem(&sock_storage, &key, &sk, BPF_ANY);
        }
    }
    
    bpf_map_update_elem(&active_ssl_sockets, &pid_tgid, &fd, BPF_ANY);
    
    return 0;
}

// recvmsg系统调用入口探针
SEC("tracepoint/syscalls/sys_enter_recvmsg")
int trace_enter_recvmsg(struct trace_event_raw_sys_enter *ctx) {
    __u64 pid_tgid = bpf_get_current_pid_tgid();
    __u32 pid = pid_tgid >> 32;
    
    if (should_filter_pid(pid)) {
        return 0;
    }
    
    __u8 *flag = bpf_map_lookup_elem(&ssl_operation_flag, &pid_tgid);
    if (!flag || *flag != 1) {
        return 0;
    }
    
    __u32 fd = (__u32)ctx->args[0];
    
    struct sock *sk = NULL;
    if (get_socket_from_fd(fd, &sk) == 0 && sk) {
        __u64 *ssl_ptr = bpf_map_lookup_elem(&current_ssl_ptr, &pid_tgid);
        if (ssl_ptr) {
            struct ssl_conn_key key = {
                .pid_tgid = pid_tgid,
                .ssl_ptr = *ssl_ptr
            };
            bpf_map_update_elem(&sock_storage, &key, &sk, BPF_ANY);
        }
    }
    
    bpf_map_update_elem(&active_ssl_sockets, &pid_tgid, &fd, BPF_ANY);
    
    return 0;
}

// read系统调用入口探针
SEC("tracepoint/syscalls/sys_enter_read")
int trace_enter_read(struct trace_event_raw_sys_enter *ctx) {
    __u64 pid_tgid = bpf_get_current_pid_tgid();
    __u32 pid = pid_tgid >> 32;
    
    if (should_filter_pid(pid)) {
        return 0;
    }
    
    __u8 *flag = bpf_map_lookup_elem(&ssl_operation_flag, &pid_tgid);
    if (!flag || *flag != 1) {
        return 0;
    }
    
    __u32 fd = (__u32)ctx->args[0];
    
    struct sock *sk = NULL;
    if (get_socket_from_fd(fd, &sk) == 0 && sk) {
        __u64 *ssl_ptr = bpf_map_lookup_elem(&current_ssl_ptr, &pid_tgid);
        if (ssl_ptr) {
            struct ssl_conn_key key = {
                .pid_tgid = pid_tgid,
                .ssl_ptr = *ssl_ptr
            };
            bpf_map_update_elem(&sock_storage, &key, &sk, BPF_ANY);
        }
    }
    
    bpf_map_update_elem(&active_ssl_sockets, &pid_tgid, &fd, BPF_ANY);
    
    return 0;
}

// socket系统调用入口探针
SEC("tracepoint/syscalls/sys_enter_socket")
int trace_enter_socket(struct trace_event_raw_sys_enter *ctx) {
    __u64 pid_tgid = bpf_get_current_pid_tgid();
    __u32 pid = pid_tgid >> 32;
    
    if (should_filter_pid(pid)) {
        return 0;
    }
    
    // 记录socket创建，为后续fd到sock的映射做准备
    DEBUG_PRINT("DEBUG: socket creation by pid=%u", pid);
    
    return 0;
}

// socket系统调用退出探针
SEC("tracepoint/syscalls/sys_exit_socket")
int sys_exit_socket(struct trace_event_raw_sys_exit *ctx) {
    __u64 pid_tgid = bpf_get_current_pid_tgid();
    __u32 pid = pid_tgid >> 32;
    
    if (should_filter_pid(pid)) {
        return 0;
    }
    
    __u32 fd = (__u32)ctx->ret;
    if ((int)fd < 0) {
        return 0;
    }
    
    // 尝试获取socket结构并建立fd到sock的映射
    struct sock *sk = NULL;
    if (get_socket_from_fd(fd, &sk) == 0 && sk) {
        struct fd_key key = {
            .pid_tgid = pid_tgid,
            .fd = fd,
            .pad = 0
        };
        bpf_map_update_elem(&fd_to_sock_map, &key, &sk, BPF_ANY);
        DEBUG_PRINT("DEBUG: mapped fd=%d to sock=%p", fd, sk);
    }
    
    return 0;
}

// connect系统调用入口探针
SEC("tracepoint/syscalls/sys_enter_connect")
int trace_enter_connect(struct trace_event_raw_sys_enter *ctx) {
    __u64 pid_tgid = bpf_get_current_pid_tgid();
    __u32 pid = pid_tgid >> 32;
    
    if (should_filter_pid(pid)) {
        return 0;
    }
    
    __u32 fd = (__u32)ctx->args[0];
    
    // 更新fd到sock的映射
    struct sock *sk = NULL;
    if (get_socket_from_fd(fd, &sk) == 0 && sk) {
        struct fd_key key = {
            .pid_tgid = pid_tgid,
            .fd = fd,
            .pad = 0
        };
        bpf_map_update_elem(&fd_to_sock_map, &key, &sk, BPF_ANY);
        
        // 如果当前在SSL操作中，也更新sock_storage
        __u8 *flag = bpf_map_lookup_elem(&ssl_operation_flag, &pid_tgid);
        if (flag && *flag == 1) {
            __u64 *ssl_ptr = bpf_map_lookup_elem(&current_ssl_ptr, &pid_tgid);
            if (ssl_ptr) {
                struct ssl_conn_key ssl_key = {
                    .pid_tgid = pid_tgid,
                    .ssl_ptr = *ssl_ptr
                };
                bpf_map_update_elem(&sock_storage, &ssl_key, &sk, BPF_ANY);
            }
        }
    }
    
    return 0;
}

// accept系统调用退出探针
SEC("tracepoint/syscalls/sys_exit_accept")
int trace_exit_accept(struct trace_event_raw_sys_exit *ctx) {
    __u64 pid_tgid = bpf_get_current_pid_tgid();
    __u32 pid = pid_tgid >> 32;
    
    if (should_filter_pid(pid)) {
        return 0;
    }
    
    int fd = (int)ctx->ret;
    if (fd < 0) {
        return 0;
    }
    
    // 建立新接受的连接的fd到sock映射
    struct sock *sk = NULL;
    if (get_socket_from_fd(fd, &sk) == 0 && sk) {
        struct fd_key key = {
            .pid_tgid = pid_tgid,
            .fd = fd,
            .pad = 0
        };
        bpf_map_update_elem(&fd_to_sock_map, &key, &sk, BPF_ANY);
        DEBUG_PRINT("DEBUG: accepted connection fd=%d mapped to sock=%p", fd, sk);
    }
    
    return 0;
}