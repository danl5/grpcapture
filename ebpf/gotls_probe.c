// gotls_probe.c - Go crypto/tls库挂载点
#include "common.h"
#include "maps.h"

// Go crypto/tls库支持
// Go TLS连接写入探针
SEC("uprobe/crypto/tls.(*Conn).Write")
int probe_entry_go_tls_write(struct pt_regs *ctx) {
    __u64 pid_tgid = bpf_get_current_pid_tgid();
    __u32 pid = pid_tgid >> 32;
    
    if (should_filter_pid(pid)) {
        return 0;
    }
    
    // Go接口参数获取比较复杂，这里简化处理
    DEBUG_PRINT("DEBUG: go_tls_write");
    
    __u8 flag = 1;
    bpf_map_update_elem(&ssl_operation_flag, &pid_tgid, &flag, BPF_ANY);
    

    
    return 0;
}

// Go TLS连接读取探针
SEC("uprobe/crypto/tls.(*Conn).Read")
int probe_entry_go_tls_read(struct pt_regs *ctx) {
    __u64 pid_tgid = bpf_get_current_pid_tgid();
    __u32 pid = pid_tgid >> 32;
    
    if (should_filter_pid(pid)) {
        return 0;
    }
    
    DEBUG_PRINT("DEBUG: go_tls_read");
    
    __u8 flag = 1;
    bpf_map_update_elem(&ssl_operation_flag, &pid_tgid, &flag, BPF_ANY);
    
    return 0;
}

// Go TLS握手探针
SEC("uprobe/crypto/tls.(*Conn).Handshake")
int probe_go_tls_handshake(struct pt_regs *ctx) {
    __u64 pid_tgid = bpf_get_current_pid_tgid();
    __u32 pid = pid_tgid >> 32;
    
    if (should_filter_pid(pid)) {
        return 0;
    }
    
    DEBUG_PRINT("DEBUG: go_tls_handshake");
    
    __u8 flag = 1;
    bpf_map_update_elem(&ssl_operation_flag, &pid_tgid, &flag, BPF_ANY);
    
    return 0;
}

// Go TLS连接关闭探针
SEC("uprobe/crypto/tls.(*Conn).Close")
int probe_go_tls_close(struct pt_regs *ctx) {
    __u64 pid_tgid = bpf_get_current_pid_tgid();
    __u32 pid = pid_tgid >> 32;
    
    if (should_filter_pid(pid)) {
        return 0;
    }
    
    DEBUG_PRINT("DEBUG: go_tls_close");
    
    // 清理相关的映射条目
    bpf_map_delete_elem(&ssl_operation_flag, &pid_tgid);
    bpf_map_delete_elem(&current_ssl_ptr, &pid_tgid);
    bpf_map_delete_elem(&active_ssl_sockets, &pid_tgid);

    
    return 0;
}

// Go net包的连接操作探针
SEC("uprobe/net.(*TCPConn).Write")
int probe_go_net_tcp_write(struct pt_regs *ctx) {
    __u64 pid_tgid = bpf_get_current_pid_tgid();
    __u32 pid = pid_tgid >> 32;
    
    if (should_filter_pid(pid)) {
        return 0;
    }
    
    // 检查是否在TLS操作中
    __u8 *flag = bpf_map_lookup_elem(&ssl_operation_flag, &pid_tgid);
    if (!flag || *flag != 1) {
        return 0;
    }
    
    DEBUG_PRINT("DEBUG: go_net_tcp_write (during TLS operation)");
    
    return 0;
}

SEC("uprobe/net.(*TCPConn).Read")
int probe_go_net_tcp_read(struct pt_regs *ctx) {
    __u64 pid_tgid = bpf_get_current_pid_tgid();
    __u32 pid = pid_tgid >> 32;
    
    if (should_filter_pid(pid)) {
        return 0;
    }
    
    // 检查是否在TLS操作中
    __u8 *flag = bpf_map_lookup_elem(&ssl_operation_flag, &pid_tgid);
    if (!flag || *flag != 1) {
        return 0;
    }
    
    DEBUG_PRINT("DEBUG: go_net_tcp_read (during TLS operation)");
    
    return 0;
}