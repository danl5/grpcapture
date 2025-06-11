// tls_probe.c
#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_core_read.h>
#include <bpf/bpf_tracing.h>

#define MAX_DATA_SIZE 16384
#define MAX_ENTRIES 102400
#define COMM_LEN 16
#define MIN_DATA_SIZE 1   // 最小数据长度过滤（数据包抓取场景）

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

// 辅助函数：填充元数据
static void fill_meta(struct meta *m, __u64 pid_tgid, int is_read, const struct ssl_args *args) {
    m->pid = pid_tgid >> 32;
    m->tid = (__u32)pid_tgid;
    m->timestamp = bpf_ktime_get_ns();
    m->is_read = is_read;
    m->ssl_ptr = (__u64)args->ssl;
    m->conn_id = ((__u64)m->pid << 32) | (m->ssl_ptr & 0xFFFFFFFF);
    bpf_get_current_comm(&m->comm, COMM_LEN);
}

// SSL_write 入口探针
SEC("uprobe/SSL_write")
int probe_entry_ssl_write(struct pt_regs *ctx) {
    __u64 pid_tgid = bpf_get_current_pid_tgid();
    struct ssl_args args;
    args.ssl = (void *)PT_REGS_PARM1(ctx);
    args.buf = (void *)PT_REGS_PARM2(ctx);
    args.num = (int)PT_REGS_PARM3(ctx);
    bpf_map_update_elem(&ssl_write_args, &pid_tgid, &args, BPF_ANY);
    return 0;
}

// SSL_write 返回探针（RINGBUF 优化版）
SEC("uretprobe/SSL_write")
int probe_return_ssl_write(struct pt_regs *ctx) {
    long ret = PT_REGS_RC(ctx);
    if (ret <= 0) return 0;

    __u64 pid_tgid = bpf_get_current_pid_tgid();
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
    bpf_map_delete_elem(&ssl_write_args, &pid_tgid);
    return 0;
}

// SSL_read 入口探针
SEC("uprobe/SSL_read")
int probe_entry_ssl_read(struct pt_regs *ctx) {
    __u64 pid_tgid = bpf_get_current_pid_tgid();
    struct ssl_args args;
    args.ssl = (void *)PT_REGS_PARM1(ctx);
    args.buf = (void *)PT_REGS_PARM2(ctx);
    args.num = (int)PT_REGS_PARM3(ctx);
    bpf_map_update_elem(&ssl_read_args, &pid_tgid, &args, BPF_ANY);
    return 0;
}

// SSL_read 返回探针（对称逻辑）
SEC("uretprobe/SSL_read")
int probe_return_ssl_read(struct pt_regs *ctx) {
    long ret = PT_REGS_RC(ctx);
    if (ret <= 0) return 0;

    __u64 pid_tgid = bpf_get_current_pid_tgid();
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
    return 0;
}

char LICENSE[] SEC("license") = "GPL";