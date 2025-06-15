// kernel_probe.c - 内核网络栈挂载点
#include "common.h"
#include "maps.h"

// 内核网络栈探针
// socket消息发送探针
SEC("kprobe/sock_sendmsg")
int kprobe_sock_sendmsg(struct pt_regs *ctx) {
    __u64 pid_tgid = bpf_get_current_pid_tgid();
    __u32 pid = pid_tgid >> 32;
    
    if (should_filter_pid(pid)) {
        return 0;
    }
    
    __u8 *flag = bpf_map_lookup_elem(&ssl_operation_flag, &pid_tgid);
    if (!flag || *flag != 1) {
        return 0;
    }
    
    struct socket *socket = (struct socket *)PT_REGS_PARM1(ctx);
    if (!socket) {
        return 0;
    }
    
    struct sock *sk;
    bpf_probe_read_kernel(&sk, sizeof(sk), &socket->sk);
    if (!sk) {
        return 0;
    }
    
    __u64 *ssl_ptr = bpf_map_lookup_elem(&current_ssl_ptr, &pid_tgid);
    if (ssl_ptr) {
        struct ssl_conn_key key = {
            .pid_tgid = pid_tgid,
            .ssl_ptr = *ssl_ptr
        };
        bpf_map_update_elem(&sock_storage, &key, &sk, BPF_ANY);
    }
    
    return 0;
}

// socket消息接收探针
SEC("kprobe/sock_recvmsg")
int kprobe_sock_recvmsg(struct pt_regs *ctx) {
    __u64 pid_tgid = bpf_get_current_pid_tgid();
    __u32 pid = pid_tgid >> 32;
    
    if (should_filter_pid(pid)) {
        return 0;
    }
    
    __u8 *flag = bpf_map_lookup_elem(&ssl_operation_flag, &pid_tgid);
    if (!flag || *flag != 1) {
        return 0;
    }
    
    struct socket *socket = (struct socket *)PT_REGS_PARM1(ctx);
    if (!socket) {
        return 0;
    }
    
    struct sock *sk;
    bpf_probe_read_kernel(&sk, sizeof(sk), &socket->sk);
    if (!sk) {
        return 0;
    }
    
    __u64 *ssl_ptr = bpf_map_lookup_elem(&current_ssl_ptr, &pid_tgid);
    if (ssl_ptr) {
        struct ssl_conn_key key = {
            .pid_tgid = pid_tgid,
            .ssl_ptr = *ssl_ptr
        };
        bpf_map_update_elem(&sock_storage, &key, &sk, BPF_ANY);
    }
    
    return 0;
}

// TCP消息发送探针
SEC("kprobe/tcp_sendmsg")
int trace_tcp_sendmsg(struct pt_regs *ctx) {
    __u64 pid_tgid = bpf_get_current_pid_tgid();
    __u32 pid = pid_tgid >> 32;
    
    if (should_filter_pid(pid)) {
        return 0;
    }
    
    __u8 *flag = bpf_map_lookup_elem(&ssl_operation_flag, &pid_tgid);
    if (!flag || *flag != 1) {
        return 0;
    }
    
    struct sock *sk = (struct sock *)PT_REGS_PARM1(ctx);
    if (!sk) {
        return 0;
    }
    
    __u64 *ssl_ptr = bpf_map_lookup_elem(&current_ssl_ptr, &pid_tgid);
    if (ssl_ptr) {
        struct ssl_conn_key key = {
            .pid_tgid = pid_tgid,
            .ssl_ptr = *ssl_ptr
        };
        bpf_map_update_elem(&sock_storage, &key, &sk, BPF_ANY);
    }
    
    return 0;
}

// TCP消息接收探针
SEC("kprobe/tcp_recvmsg")
int trace_tcp_recvmsg(struct pt_regs *ctx) {
    __u64 pid_tgid = bpf_get_current_pid_tgid();
    __u32 pid = pid_tgid >> 32;
    
    if (should_filter_pid(pid)) {
        return 0;
    }
    
    __u8 *flag = bpf_map_lookup_elem(&ssl_operation_flag, &pid_tgid);
    if (!flag || *flag != 1) {
        return 0;
    }
    
    struct sock *sk = (struct sock *)PT_REGS_PARM1(ctx);
    if (!sk) {
        return 0;
    }
    
    __u64 *ssl_ptr = bpf_map_lookup_elem(&current_ssl_ptr, &pid_tgid);
    if (ssl_ptr) {
        struct ssl_conn_key key = {
            .pid_tgid = pid_tgid,
            .ssl_ptr = *ssl_ptr
        };
        bpf_map_update_elem(&sock_storage, &key, &sk, BPF_ANY);
    }
    
    return 0;
}

// TCP数据队列探针
SEC("kprobe/tcp_data_queue")
int trace_tcp_data_queue(struct pt_regs *ctx) {
    __u64 pid_tgid = bpf_get_current_pid_tgid();
    __u32 pid = pid_tgid >> 32;
    
    if (should_filter_pid(pid)) {
        return 0;
    }
    
    __u8 *flag = bpf_map_lookup_elem(&ssl_operation_flag, &pid_tgid);
    if (!flag || *flag != 1) {
        return 0;
    }
    
    struct sock *sk = (struct sock *)PT_REGS_PARM1(ctx);
    if (!sk) {
        return 0;
    }
    
    __u64 *ssl_ptr = bpf_map_lookup_elem(&current_ssl_ptr, &pid_tgid);
    if (ssl_ptr) {
        struct ssl_conn_key key = {
            .pid_tgid = pid_tgid,
            .ssl_ptr = *ssl_ptr
        };
        bpf_map_update_elem(&sock_storage, &key, &sk, BPF_ANY);
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
    if (!flag || *flag != 1) {
        return 0;
    }
    
    struct sock *sk = (struct sock *)PT_REGS_PARM1(ctx);
    if (!sk) {
        return 0;
    }
    
    __u64 *ssl_ptr = bpf_map_lookup_elem(&current_ssl_ptr, &pid_tgid);
    if (ssl_ptr) {
        struct ssl_conn_key key = {
            .pid_tgid = pid_tgid,
            .ssl_ptr = *ssl_ptr
        };
        bpf_map_update_elem(&sock_storage, &key, &sk, BPF_ANY);
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
    if (!flag || *flag != 1) {
        return 0;
    }
    
    struct sock *sk = (struct sock *)PT_REGS_PARM1(ctx);
    if (!sk) {
        return 0;
    }
    
    __u64 *ssl_ptr = bpf_map_lookup_elem(&current_ssl_ptr, &pid_tgid);
    if (ssl_ptr) {
        struct ssl_conn_key key = {
            .pid_tgid = pid_tgid,
            .ssl_ptr = *ssl_ptr
        };
        bpf_map_update_elem(&sock_storage, &key, &sk, BPF_ANY);
    }
    
    return 0;
}

// 网络设备传输探针（可选，用于更底层的网络监控）
SEC("kprobe/dev_queue_xmit")
int kprobe_dev_queue_xmit(struct pt_regs *ctx) {
    __u64 pid_tgid = bpf_get_current_pid_tgid();
    __u32 pid = pid_tgid >> 32;
    
    if (should_filter_pid(pid)) {
        return 0;
    }
    
    __u8 *flag = bpf_map_lookup_elem(&ssl_operation_flag, &pid_tgid);
    if (!flag || *flag != 1) {
        return 0;
    }
    
    // 这里可以添加更详细的网络包分析逻辑
    DEBUG_PRINT("DEBUG: dev_queue_xmit during SSL operation, pid=%u", pid);
    
    return 0;
}