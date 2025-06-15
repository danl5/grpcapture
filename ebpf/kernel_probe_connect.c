// kernel_probe_connect.c - 系统调用级别的连接跟踪
#include "common.h"
#include "maps.h"

// 处理连接建立的通用函数
static int kretprobe_connect(struct pt_regs* ctx, __u32 fd, struct sock *sk, bool active) {
    __u64 current_pid_tgid = bpf_get_current_pid_tgid();
    __u32 pid = current_pid_tgid >> 32;

    __u16 address_family = 0;
    __u32 saddr = 0, daddr = 0;
    __u32 ports = 0;

    // PID过滤检查
    if (should_filter_pid(pid)) {
        return 0;
    }

    // 读取地址族
    bpf_probe_read_kernel(&address_family, sizeof(address_family), &sk->__sk_common.skc_family);
    DEBUG_PRINT("DEBUG: sockaddr family: %d", address_family);

    if (address_family == 2) { // AF_INET = 2
        __u64 addrs;
        bpf_probe_read_kernel(&addrs, sizeof(addrs), &sk->__sk_common.skc_addrpair);
        // skc_addrpair中，高32位是源地址，低32位是目标地址，都是网络字节序
        saddr = (__be32)(addrs >> 32);
        daddr = (__be32)addrs;
    } else if (address_family == 10) { // AF_INET6 = 10
        // 检查是否为IPv6映射的IPv4地址 (::ffff:x.x.x.x)
        struct in6_addr v6_saddr, v6_daddr;
        bpf_probe_read_kernel(&v6_saddr, sizeof(v6_saddr), &sk->__sk_common.skc_v6_rcv_saddr);
        bpf_probe_read_kernel(&v6_daddr, sizeof(v6_daddr), &sk->__sk_common.skc_v6_daddr);
        
        // 检查源地址是否为IPv4映射地址 (前96位为0或::ffff:)
        bool is_v4_mapped_src = (v6_saddr.in6_u.u6_addr32[0] == 0 && v6_saddr.in6_u.u6_addr32[1] == 0 && 
                                (v6_saddr.in6_u.u6_addr32[2] == 0 || v6_saddr.in6_u.u6_addr32[2] == bpf_htonl(0x0000ffff)));
        bool is_v4_mapped_dst = (v6_daddr.in6_u.u6_addr32[0] == 0 && v6_daddr.in6_u.u6_addr32[1] == 0 && 
                                (v6_daddr.in6_u.u6_addr32[2] == 0 || v6_daddr.in6_u.u6_addr32[2] == bpf_htonl(0x0000ffff)));
        
        if (is_v4_mapped_src && is_v4_mapped_dst) {
            // 提取IPv4地址（在最后32位）
            saddr = v6_saddr.in6_u.u6_addr32[3];
            daddr = v6_daddr.in6_u.u6_addr32[3];
            DEBUG_PRINT("DEBUG: IPv6-mapped IPv4 addresses - saddr: %u, daddr: %u", saddr, daddr);
        } else {
            // 纯IPv6地址，暂不支持
            DEBUG_PRINT("DEBUG: Pure IPv6 address, not supported yet");
            return 0;
        }
    } else {
        return 0;
    }

    DEBUG_PRINT("saddr: %u, daddr: %u", saddr, daddr);
    // 读取端口信息
    bpf_probe_read_kernel(&ports, sizeof(ports), &sk->__sk_common.skc_portpair);
    if (ports == 0 || saddr == 0 || daddr == 0) {
        return 0;
    }

    // 创建TCP连接信息
    struct tcp_fd_info conn_info = {0};
    conn_info.sock = (__u64)sk;
    conn_info.fd = fd;
    conn_info.family = address_family;
    conn_info.timestamp = bpf_ktime_get_ns();
    
    if (active) {
        // 客户端连接
        conn_info.dport = bpf_ntohs((__u16)ports);
        conn_info.sport = ports >> 16;
        conn_info.saddr = saddr;
        conn_info.daddr = daddr;
    } else {
        // 服务端接受连接
        conn_info.sport = bpf_ntohs((__u16)ports);
        conn_info.dport = ports >> 16;
        conn_info.saddr = daddr;
        conn_info.daddr = saddr;
    }

    // 存储连接信息
    DEBUG_PRINT("[LAYER0] Storing TCP connection info for FD=%u, PID=%u", fd, pid);
    
    int ret = bpf_map_update_elem(&tcp_fd_infos, &fd, &conn_info, BPF_ANY);
    if (ret == 0) {
        DEBUG_PRINT("[LAYER0] SUCCESS: Stored TCP info for FD=%u: %u.%u.%u.%u:%u -> %u.%u.%u.%u:%u",
                    fd,
                    (conn_info.saddr >> 24) & 0xFF, (conn_info.saddr >> 16) & 0xFF,
                    (conn_info.saddr >> 8) & 0xFF, conn_info.saddr & 0xFF, conn_info.sport,
                    (conn_info.daddr >> 24) & 0xFF, (conn_info.daddr >> 16) & 0xFF,
                    (conn_info.daddr >> 8) & 0xFF, conn_info.daddr & 0xFF, conn_info.dport);
    } else {
        DEBUG_PRINT("[LAYER0] FAILED: Could not store TCP info for FD=%u, ret=%d", fd, ret);
    }

    // 可选：发送连接事件
    struct connect_event_t *event = bpf_ringbuf_reserve(&connect_events, sizeof(struct connect_event_t), 0);
    if (event) {
        event->timestamp_ns = conn_info.timestamp;
        event->pid = pid;
        event->tid = current_pid_tgid;
        event->fd = fd;
        event->family = address_family;
        event->sport = conn_info.sport;
        event->dport = conn_info.dport;
        event->saddr = conn_info.saddr;
        event->daddr = conn_info.daddr;
        event->sock = (__u64)sk;
        event->is_destroy = 0;
        bpf_get_current_comm(&event->comm, sizeof(event->comm));
        
        bpf_ringbuf_submit(event, 0);
    }

    return 0;
}

// sys_connect kprobe
SEC("kprobe/sys_connect")
int probe_connect(struct pt_regs* ctx) {
    __u64 pid_tgid = bpf_get_current_pid_tgid();
    struct tcp_fd_info fd_info = {};

    fd_info.fd = PT_REGS_PARM1(ctx);
    bpf_map_update_elem(&tcp_fd_infos, &pid_tgid, &fd_info, BPF_ANY);
    return 0;
}

// sys_connect kretprobe
SEC("kretprobe/sys_connect")
int retprobe_connect(struct pt_regs* ctx) {
    struct tcp_fd_info *fd_info;
    struct socket *sock;
    struct sock *sk;

    fd_info = lookup_and_delete_fd_info(ctx);
    if (fd_info) {
        sock = (typeof(sock)) fd_info->sock;
        bpf_probe_read_kernel(&sk, sizeof(sk), &sock->sk);
        if (sk) {
            return kretprobe_connect(ctx, fd_info->fd, sk, true);
        }
    }
    return 0;
}

// inet_accept kprobe
SEC("kprobe/inet_accept")
int probe_inet_accept(struct pt_regs* ctx) {
    __u64 pid_tgid = bpf_get_current_pid_tgid();
    struct tcp_fd_info fd_info = {};
    struct socket *sock;

    // Extract socket from inet_accept parameters (ecapture uses PARM2)
    sock = (struct socket *)PT_REGS_PARM2(ctx);
    fd_info.sock = (__u64)sock;
    
    bpf_map_update_elem(&tcp_fd_infos, &pid_tgid, &fd_info, BPF_ANY);
    return 0;
}

// accept4 kretprobe
SEC("kretprobe/sys_accept4")
int retprobe_accept4(struct pt_regs* ctx) {
    struct tcp_fd_info *fd_info;
    struct socket *sock;
    struct sock *sk;
    long ret = PT_REGS_RC(ctx);

    fd_info = lookup_and_delete_fd_info(ctx);
    if (fd_info) {
        sock = (typeof(sock)) fd_info->sock;
        bpf_probe_read_kernel(&sk, sizeof(sk), &sock->sk);
        if (sk) {
            fd_info->fd = ret;
            return kretprobe_connect(ctx, ret, sk, false);
        }
    }
    return 0;
}

// TCP socket销毁跟踪
SEC("kprobe/tcp_v4_destroy_sock")
int probe_tcp_v4_destroy_sock(struct pt_regs* ctx) {
    __u64 current_pid_tgid = bpf_get_current_pid_tgid();
    __u32 pid = current_pid_tgid >> 32;
    
    // PID过滤检查
    if (should_filter_pid(pid)) {
        return 0;
    }
    
    struct sock *sk = (struct sock *)PT_REGS_PARM1(ctx);
    
    // 发送销毁事件
    struct connect_event_t *event = bpf_ringbuf_reserve(&connect_events, sizeof(struct connect_event_t), 0);
    if (event) {
        __builtin_memset(event, 0, sizeof(*event));
        event->sock = (__u64)sk;
        event->is_destroy = 1;
        event->timestamp_ns = bpf_ktime_get_ns();
        
        bpf_ringbuf_submit(event, 0);
    }
    
    return 0;
}