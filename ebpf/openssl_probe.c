// openssl_probe.c - OpenSSL TLS库挂载点
#include "common.h"
#include "maps.h"

// SSL结构体偏移量定义 (基于OpenSSL 1.1.1)
#define SSL_ST_VERSION 0x0
#define SSL_ST_RBIO 0x10
#define SSL_ST_WBIO 0x18
#define BIO_ST_NUM 0x30

// 常量定义
const u32 invalidFD = 0;

// SSL数据事件类型
enum ssl_data_event_type { kSSLRead, kSSLWrite };

// 活跃SSL缓冲区结构定义在maps.h中

/***********************************************************
 * 辅助函数
 ***********************************************************/

// SSL数据处理参数结构
struct ssl_data_args {
    enum ssl_data_event_type type;
    const char* buf;
    u32 fd;
    s32 version;
};

// 处理SSL数据
static int process_SSL_data(struct pt_regs* ctx, u64 id, struct ssl_data_args* args) {
    int len = (int)PT_REGS_RC(ctx);
    if (len < 0) {
        return 0;
    }

    // 数据长度过滤
    if (len < MIN_DATA_SIZE) {
        return 0;
    }

    u32 data_len = (len > MAX_DATA_SIZE) ? MAX_DATA_SIZE : (u32)len;
    
    // 使用ringbuf分配事件
    struct tls_event *e = bpf_ringbuf_reserve(&tls_events, sizeof(struct tls_event), 0);
    if (!e) {
        return 0;
    }

    // 填充基本元数据
    const u32 kMask32b = 0xffffffff;
    e->meta.timestamp_ns = bpf_ktime_get_ns();
    e->meta.pid = id >> 32;
    e->meta.tid = id & kMask32b;
    e->meta.is_read = (args->type == kSSLRead) ? 1 : 0;
    e->meta.data_len = 0;
    bpf_get_current_comm(&e->meta.comm, sizeof(e->meta.comm));
    
    // 设置连接信息
    e->meta.conn_id = args->fd; // 使用fd作为连接ID
    
    // DEBUG: 第三层映射 - 通过FD查找TCP连接信息
    u32 fd = args->fd;
    DEBUG_PRINT("[LAYER3] Looking up TCP info for FD=%u, PID=%u", fd, e->meta.pid);
    
    struct tcp_fd_info *tcp_info = bpf_map_lookup_elem(&tcp_fd_infos, &fd);
    if (tcp_info) {
        // 填充TCP四元组信息
        e->meta.tuple_valid = 1;
        e->meta.tuple.saddr = bpf_ntohl(tcp_info->saddr);
        e->meta.tuple.daddr = bpf_ntohl(tcp_info->daddr);
        e->meta.tuple.sport = tcp_info->sport;
        e->meta.tuple.dport = tcp_info->dport;
        e->meta.tuple.family = tcp_info->family;
        DEBUG_PRINT("[LAYER3] SUCCESS: Found TCP info for FD=%u: %u.%u.%u.%u:%u->%u.%u.%u.%u:%u", 
                   fd,
                   (tcp_info->saddr >> 24) & 0xFF, (tcp_info->saddr >> 16) & 0xFF,
                   (tcp_info->saddr >> 8) & 0xFF, tcp_info->saddr & 0xFF, tcp_info->sport,
                   (tcp_info->daddr >> 24) & 0xFF, (tcp_info->daddr >> 16) & 0xFF,
                   (tcp_info->daddr >> 8) & 0xFF, tcp_info->daddr & 0xFF, tcp_info->dport);
    } else {
        e->meta.tuple_valid = 0;
        DEBUG_PRINT("[LAYER3] FAILED: No TCP info found for FD=%u, PID=%u", fd, e->meta.pid);
    }

    // 复制数据
    if (data_len > 0 && args->buf) {
        long res = bpf_probe_read_user(e->data, data_len, args->buf);
        e->meta.data_len = (res >= 0) ? data_len : 0;
        
        // Debug: 打印data的前八个字符
        if (res >= 0 && data_len >= 8) {
            DEBUG_PRINT("[DEBUG] Data first 8 bytes: %02x %02x %02x %02x %02x %02x %02x %02x",
                       (unsigned char)e->data[0], (unsigned char)e->data[1],
                       (unsigned char)e->data[2], (unsigned char)e->data[3],
                       (unsigned char)e->data[4], (unsigned char)e->data[5],
                       (unsigned char)e->data[6], (unsigned char)e->data[7]);
        } else if (res >= 0 && data_len > 0) {
            DEBUG_PRINT("[DEBUG] Data length %d < 8, showing available bytes:", data_len);
            for (int i = 0; i < data_len && i < 8; i++) {
                DEBUG_PRINT("[DEBUG] data[%d]: %02x", i, (unsigned char)e->data[i]);
            }
        }
    }

    bpf_ringbuf_submit(e, 0);
    return 0;
}

// SSL_write 入口探针
SEC("uprobe/SSL_write")
int probe_entry_ssl_write(struct pt_regs *ctx) {
    u64 current_pid_tgid = bpf_get_current_pid_tgid();
    u32 pid = current_pid_tgid >> 32;

    // PID过滤检查
    if (should_filter_pid(pid)) {
        return 0;
    }
    
    DEBUG_PRINT("openssl uprobe/SSL_write pid: %d", pid);

    void* ssl = (void*)PT_REGS_PARM1(ctx);
    
    u64 *ssl_ver_ptr, *ssl_wbio_ptr, *ssl_wbio_num_ptr;
    u64 ssl_version, ssl_wbio_addr, ssl_wbio_num_addr;
    int ret;

    // 读取SSL版本
    ssl_ver_ptr = (u64 *)(ssl + SSL_ST_VERSION);
    ret = bpf_probe_read_user(&ssl_version, sizeof(ssl_version), ssl_ver_ptr);
    if (ret) {
        DEBUG_PRINT("bpf_probe_read ssl_ver_ptr failed, ret: %d", ret);
        return 0;
    }

    // 读取SSL写BIO地址
    ssl_wbio_ptr = (u64 *)(ssl + SSL_ST_WBIO);
    ret = bpf_probe_read_user(&ssl_wbio_addr, sizeof(ssl_wbio_addr), ssl_wbio_ptr);
    if (ret) {
        DEBUG_PRINT("bpf_probe_read ssl_wbio_addr failed, ret: %d", ret);
        return 0;
    }

    // 获取文件描述符
    ssl_wbio_num_ptr = (u64 *)(ssl_wbio_addr + BIO_ST_NUM);
    ret = bpf_probe_read_user(&ssl_wbio_num_addr, sizeof(ssl_wbio_num_addr), ssl_wbio_num_ptr);
    if (ret) {
        DEBUG_PRINT("bpf_probe_read ssl_wbio_num_ptr failed, ret: %d", ret);
        return 0;
    }
    
    u32 fd = (u32)ssl_wbio_num_addr;
    DEBUG_PRINT("[LAYER2] SSL_write: SSL=%p, BIO_fd=%u", ssl, fd);
    
    if (fd == 0) {
        u64 ssl_addr = (u64)ssl;
        DEBUG_PRINT("[LAYER2] BIO_fd=0, looking up ssl_st_fd map for SSL=%p", ssl);
        u64 *fd_ptr = bpf_map_lookup_elem(&ssl_st_fd, &ssl_addr);
        if (fd_ptr) {
            fd = (u64)*fd_ptr;
            DEBUG_PRINT("[LAYER2] SUCCESS: Found FD=%u for SSL=%p in ssl_st_fd map", fd, ssl);
        } else {
            DEBUG_PRINT("[LAYER2] FAILED: No FD found for SSL=%p in ssl_st_fd map", ssl);
        }
    }
    
    DEBUG_PRINT("openssl uprobe/SSL_write final fd: %d, version: %d", fd, ssl_version);

    const char* buf = (const char*)PT_REGS_PARM2(ctx);
    
    struct active_ssl_buf active_ssl_buf_t;
    __builtin_memset(&active_ssl_buf_t, 0, sizeof(active_ssl_buf_t));
    active_ssl_buf_t.fd = fd;
    active_ssl_buf_t.version = ssl_version;
    active_ssl_buf_t.buf = buf;

    bpf_map_update_elem(&ssl_write_args, &current_pid_tgid, &active_ssl_buf_t, BPF_ANY);

    return 0;
}

// SSL_write 返回探针
SEC("uretprobe/SSL_write")
int probe_return_ssl_write(struct pt_regs *ctx) {
    u64 current_pid_tgid = bpf_get_current_pid_tgid();
    u32 pid = current_pid_tgid >> 32;

    // PID过滤检查
    if (should_filter_pid(pid)) {
        return 0;
    }
    
    DEBUG_PRINT("openssl uretprobe/SSL_write pid: %d", pid);
    
    struct active_ssl_buf* active_ssl_buf_t = bpf_map_lookup_elem(&ssl_write_args, &current_pid_tgid);
    if (active_ssl_buf_t != NULL) {
        // Debug: 打印取出后的buf指针和前几个字节
        DEBUG_PRINT("[DEBUG] SSL_write return - retrieved buf pointer: %p", active_ssl_buf_t->buf);
        struct ssl_data_args args = {
            .type = kSSLWrite,
            .fd = active_ssl_buf_t->fd,
            .version = active_ssl_buf_t->version
        };
        args.buf = active_ssl_buf_t->buf;
        process_SSL_data(ctx, current_pid_tgid, &args);
    }
    bpf_map_delete_elem(&ssl_write_args, &current_pid_tgid);
    return 0;
}
// SSL_read 入口探针
SEC("uprobe/SSL_read")
int probe_entry_ssl_read(struct pt_regs *ctx) {
    u64 current_pid_tgid = bpf_get_current_pid_tgid();
    u32 pid = current_pid_tgid >> 32;
    
    DEBUG_PRINT("openssl uprobe/SSL_read pid: %d", pid);

    // PID过滤检查
    if (should_filter_pid(pid)) {
        return 0;
    }

    void* ssl = (void*)PT_REGS_PARM1(ctx);
    
    u64 *ssl_ver_ptr, *ssl_rbio_ptr, *ssl_rbio_num_ptr;
    u64 ssl_version, ssl_rbio_addr, ssl_rbio_num_addr;
    int ret;

    // 读取SSL版本
    ssl_ver_ptr = (u64 *)(ssl + SSL_ST_VERSION);
    ret = bpf_probe_read_user(&ssl_version, sizeof(ssl_version), ssl_ver_ptr);
    if (ret) {
        DEBUG_PRINT("bpf_probe_read ssl_ver_ptr failed, ret: %d", ret);
        return 0;
    }

    // 读取SSL读BIO地址
    ssl_rbio_ptr = (u64 *)(ssl + SSL_ST_RBIO);
    ret = bpf_probe_read_user(&ssl_rbio_addr, sizeof(ssl_rbio_addr), ssl_rbio_ptr);
    if (ret) {
        DEBUG_PRINT("bpf_probe_read ssl_rbio_ptr failed, ret: %d", ret);
        return 0;
    }

    // 获取文件描述符
    ssl_rbio_num_ptr = (u64 *)(ssl_rbio_addr + BIO_ST_NUM);
    ret = bpf_probe_read_user(&ssl_rbio_num_addr, sizeof(ssl_rbio_num_addr), ssl_rbio_num_ptr);
    if (ret) {
        DEBUG_PRINT("bpf_probe_read ssl_rbio_num_ptr failed, ret: %d", ret);
        return 0;
    }
    
    u32 fd = (u32)ssl_rbio_num_addr;
    DEBUG_PRINT("[LAYER2] SSL_read: SSL=%p, BIO_fd=%u", ssl, fd);
    
    if (fd == 0) {
        u64 ssl_addr = (u64)ssl;
        DEBUG_PRINT("[LAYER2] BIO_fd=0, looking up ssl_st_fd map for SSL=%p", ssl);
        u64 *fd_ptr = bpf_map_lookup_elem(&ssl_st_fd, &ssl_addr);
        if (fd_ptr) {
            fd = (u64)*fd_ptr;
            DEBUG_PRINT("[LAYER2] SUCCESS: Found FD=%u for SSL=%p in ssl_st_fd map", fd, ssl);
        } else {
            DEBUG_PRINT("[LAYER2] FAILED: No FD found for SSL=%p in ssl_st_fd map", ssl);
        }
    }
    
    DEBUG_PRINT("openssl uprobe/SSL_read final fd: %d, version: %d", fd, ssl_version);

    const char* buf = (const char*)PT_REGS_PARM2(ctx);
    
    // Debug: 只记录buf指针，不读取数据内容（entry时可能是垃圾数据）
    DEBUG_PRINT("[DEBUG] SSL_read entry - buf pointer: %p (data will be valid after function execution)", buf);
    
    struct active_ssl_buf active_ssl_buf_t;
    __builtin_memset(&active_ssl_buf_t, 0, sizeof(active_ssl_buf_t));
    active_ssl_buf_t.fd = fd;
    active_ssl_buf_t.version = ssl_version;
    active_ssl_buf_t.buf = buf;

    bpf_map_update_elem(&ssl_read_args, &current_pid_tgid, &active_ssl_buf_t, BPF_ANY);
    
    return 0;
}

// SSL_read 返回探针
SEC("uretprobe/SSL_read")
int probe_return_ssl_read(struct pt_regs *ctx) {
    u64 current_pid_tgid = bpf_get_current_pid_tgid();
    u32 pid = current_pid_tgid >> 32;
    
    DEBUG_PRINT("openssl uretprobe/SSL_read pid: %d", pid);

    // PID过滤检查
    if (should_filter_pid(pid)) {
        return 0;
    }

    // 获取SSL_read的返回值（读取的字节数）
    int bytes_read = PT_REGS_RC(ctx);
    DEBUG_PRINT("[DEBUG] SSL_read return - bytes_read: %d", bytes_read);

    struct active_ssl_buf* active_ssl_buf_t = bpf_map_lookup_elem(&ssl_read_args, &current_pid_tgid);
    if (active_ssl_buf_t != NULL && bytes_read > 0) {
        // Debug: 打印取出后的buf指针和实际读取的数据
        DEBUG_PRINT("[DEBUG] SSL_read return - retrieved buf pointer: %p, processing %d bytes", active_ssl_buf_t->buf, bytes_read);
        
        struct ssl_data_args args = {
            .type = kSSLRead,
            .fd = active_ssl_buf_t->fd,
            .version = active_ssl_buf_t->version
        };
        args.buf = active_ssl_buf_t->buf;
        process_SSL_data(ctx, current_pid_tgid, &args);
    } else if (active_ssl_buf_t != NULL && bytes_read <= 0) {
        DEBUG_PRINT("[DEBUG] SSL_read return - skipping processing, bytes_read=%d", bytes_read);
    }
    bpf_map_delete_elem(&ssl_read_args, &current_pid_tgid);
    return 0;
}

// SSL_set_fd探针 - 建立SSL->FD映射
SEC("uprobe/SSL_set_fd")
int probe_SSL_set_fd(struct pt_regs* ctx) {
    u64 ssl_addr = (u64)PT_REGS_PARM1(ctx);
    u64 fd = (u64)PT_REGS_PARM2(ctx);
    
    DEBUG_PRINT("[LAYER1] SSL_set_fd called: SSL=%p, FD=%u, PID=%u", (void*)ssl_addr, (u32)fd, (u32)(bpf_get_current_pid_tgid() >> 32));
    
    int ret = bpf_map_update_elem(&ssl_st_fd, &ssl_addr, &fd, BPF_ANY);
    if (ret == 0) {
        DEBUG_PRINT("[LAYER1] SUCCESS: SSL->FD mapping stored: SSL=%p -> FD=%u", (void*)ssl_addr, (u32)fd);
    } else {
        DEBUG_PRINT("[LAYER1] FAILED: Could not store SSL->FD mapping, ret=%d", ret);
    }
    
    return 0;
}

// SSL_set_rfd探针
SEC("uprobe/SSL_set_rfd")
int probe_SSL_set_rfd(struct pt_regs* ctx) {
    return probe_SSL_set_fd(ctx);
}

// SSL_set_wfd探针
SEC("uprobe/SSL_set_wfd")
int probe_SSL_set_wfd(struct pt_regs* ctx) {
    return probe_SSL_set_fd(ctx);
}