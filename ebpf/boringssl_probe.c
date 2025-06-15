// boringssl_probe.c - BoringSSL TLS库挂载点
#include "common.h"
#include "maps.h"

// BoringSSL库支持（与OpenSSL API兼容，但可能有不同的符号）
// BoringSSL写入探针
SEC("uprobe/SSL_write_ex")
int probe_entry_ssl_write_ex(struct pt_regs *ctx) {
    __u64 pid_tgid = bpf_get_current_pid_tgid();
    __u32 pid = pid_tgid >> 32;
    
    if (should_filter_pid(pid)) {
        return 0;
    }
    
    void *ssl = (void *)PT_REGS_PARM1(ctx);
    
    DEBUG_PRINT("DEBUG: SSL_write_ex - ssl=%p", ssl);
    
    __u8 flag = 1;
    bpf_map_update_elem(&ssl_operation_flag, &pid_tgid, &flag, BPF_ANY);
    
    __u64 ssl_ptr = (__u64)ssl;
    bpf_map_update_elem(&current_ssl_ptr, &pid_tgid, &ssl_ptr, BPF_ANY);
    
    return 0;
}

// BoringSSL读取探针
SEC("uprobe/SSL_read_ex")
int probe_entry_ssl_read_ex(struct pt_regs *ctx) {
    __u64 pid_tgid = bpf_get_current_pid_tgid();
    __u32 pid = pid_tgid >> 32;
    
    if (should_filter_pid(pid)) {
        return 0;
    }
    
    void *ssl = (void *)PT_REGS_PARM1(ctx);
    
    DEBUG_PRINT("DEBUG: SSL_read_ex - ssl=%p", ssl);
    
    __u8 flag = 1;
    bpf_map_update_elem(&ssl_operation_flag, &pid_tgid, &flag, BPF_ANY);
    
    __u64 ssl_ptr = (__u64)ssl;
    bpf_map_update_elem(&current_ssl_ptr, &pid_tgid, &ssl_ptr, BPF_ANY);
    
    return 0;
}