// gnutls_probe.c - GnuTLS库挂载点
#include "common.h"
#include "maps.h"

// GnuTLS库支持
// GnuTLS发送数据探针
SEC("uprobe/gnutls_record_send")
int probe_entry_gnutls_record_send(struct pt_regs *ctx) {
    __u64 pid_tgid = bpf_get_current_pid_tgid();
    __u32 pid = pid_tgid >> 32;
    
    if (should_filter_pid(pid)) {
        return 0;
    }
    
    // GnuTLS session pointer
    void *session __attribute__((unused)) = (void *)PT_REGS_PARM1(ctx);
    
    DEBUG_PRINT("DEBUG: gnutls_record_send - session=%p", session);
    
    // 设置SSL操作标志
    __u8 flag = 1;
    bpf_map_update_elem(&ssl_operation_flag, &pid_tgid, &flag, BPF_ANY);
    
    // 存储GnuTLS session指针
    // current_ssl_ptr映射已移除，功能移至用户态
    

    
    return 0;
}

// GnuTLS接收数据探针
SEC("uprobe/gnutls_record_recv")
int probe_entry_gnutls_record_recv(struct pt_regs *ctx) {
    __u64 pid_tgid = bpf_get_current_pid_tgid();
    __u32 pid = pid_tgid >> 32;
    
    if (should_filter_pid(pid)) {
        return 0;
    }
    
    void *session __attribute__((unused)) = (void *)PT_REGS_PARM1(ctx);
    
    DEBUG_PRINT("DEBUG: gnutls_record_recv - session=%p", session);
    
    __u8 flag = 1;
    bpf_map_update_elem(&ssl_operation_flag, &pid_tgid, &flag, BPF_ANY);
    
    // current_ssl_ptr映射已移除，功能移至用户态
    

    
    return 0;
}

// GnuTLS握手探针 - 用于捕获连接建立
SEC("uprobe/gnutls_handshake")
int probe_gnutls_handshake(struct pt_regs *ctx) {
    __u64 pid_tgid = bpf_get_current_pid_tgid();
    __u32 pid = pid_tgid >> 32;
    
    if (should_filter_pid(pid)) {
        return 0;
    }
    
    void *session __attribute__((unused)) = (void *)PT_REGS_PARM1(ctx);
    
    DEBUG_PRINT("DEBUG: gnutls_handshake - session=%p", session);
    
    __u8 flag = 1;
    bpf_map_update_elem(&ssl_operation_flag, &pid_tgid, &flag, BPF_ANY);
    
    // current_ssl_ptr映射已移除，功能移至用户态

    
    return 0;
}

// GnuTLS关闭连接探针
SEC("uprobe/gnutls_bye")
int probe_gnutls_bye(struct pt_regs *ctx) {
    __u64 pid_tgid = bpf_get_current_pid_tgid();
    __u32 pid = pid_tgid >> 32;
    
    if (should_filter_pid(pid)) {
        return 0;
    }
    
    void *session __attribute__((unused)) = (void *)PT_REGS_PARM1(ctx);
    
    DEBUG_PRINT("DEBUG: gnutls_bye - session=%p", session);
    
    // 清理相关的映射条目
    bpf_map_delete_elem(&ssl_operation_flag, &pid_tgid);
    // sock_storage, current_ssl_ptr, active_ssl_sockets映射已移除
    
    return 0;
}