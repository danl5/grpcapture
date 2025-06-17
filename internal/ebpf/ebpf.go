package ebpf

import (
	"context"
	"errors"
	"fmt"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/ringbuf"
	"github.com/cilium/ebpf/rlimit"

	"github.com/danl5/grpcapture/internal/logger"
)

// TLS元数据结构体
type TlsMeta struct {
	Timestamp uint64    // timestamp_ns (8字节)
	Pid       uint32    // pid (4字节)
	Tid       uint32    // tid (4字节)
	DataLen   uint32    // data_len (4字节)
	IsRead    uint8     // is_read (1字节)
	Pad       [3]uint8  // _pad[3] (3字节，用于对齐)
	Comm      [16]uint8 // comm[COMM_LEN] (16字节)
	SslPtr    uint64    // ssl_ptr (8字节)
	ConnId    uint64    // conn_id (8字节)
	Fd        uint32    // fd (4字节)
	Pad2      [4]uint8  // pad2[4] (4字节对齐)
	// 总计: 8+4+4+4+1+3+16+8+8+4+4 = 64字节
}

type TlsTlsEvent struct {
	Meta TlsMeta
	Data [16384]uint8
}

// SSL设置FD事件结构体
type SslSetFdEvent struct {
	Timestamp uint64   // timestamp_ns (8字节)
	Pid       uint32   // pid (4字节)
	Tid       uint32   // tid (4字节)
	SslPtr    uint64   // ssl_ptr (8字节)
	Fd        uint32   // fd (4字节)
	Pad       [4]uint8 // pad[4] (4字节对齐)
}

// 连接事件结构体
type ConnectEvent struct {
	Timestamp uint64    // timestamp_ns (8字节)
	Pid       uint32    // pid (4字节)
	Tid       uint64    // tid (8字节)
	Fd        uint32    // fd (4字节)
	Family    uint16    // family (2字节)
	Sport     uint16    // sport (2字节)
	Dport     uint16    // dport (2字节)
	Saddr     uint32    // saddr (4字节)
	Daddr     uint32    // daddr (4字节)
	Comm      [16]uint8 // comm[16] (16字节)
	Sock      uint64    // sock (8字节)
	IsDestroy uint8     // is_destroy (1字节)
	Pad       [7]uint8  // pad[7] (7字节对齐)
}

// EBPFSetup 结构体优化
type EBPFSetup struct {
	coll          *ebpf.Collection
	rd            *ringbuf.Reader
	writeProbe    link.Link
	readProbe     link.Link
	writeRetProbe link.Link
	readRetProbe  link.Link

	tracepointLinks []link.Link
	kprobeLinks     []link.Link

	// PID过滤相关
	pidFilter    *ebpf.Map
	filterConfig *ebpf.Map
}

// Getter 方法
func (e *EBPFSetup) GetCollection() *ebpf.Collection {
	return e.coll
}

func (e *EBPFSetup) GetRingBuffer() *ringbuf.Reader {
	return e.rd
}

// PID过滤管理方法

// 启用PID过滤
func (e *EBPFSetup) EnablePIDFilter() error {
	key := uint32(0)
	value := uint8(1)
	return e.filterConfig.Update(key, value, ebpf.UpdateAny)
}

// 禁用PID过滤
func (e *EBPFSetup) DisablePIDFilter() error {
	key := uint32(0)
	value := uint8(0)
	return e.filterConfig.Update(key, value, ebpf.UpdateAny)
}

// 添加允许的PID
func (e *EBPFSetup) AddPID(pid uint32) error {
	value := uint8(1)
	return e.pidFilter.Update(pid, value, ebpf.UpdateAny)
}

// 移除PID
func (e *EBPFSetup) RemovePID(pid uint32) error {
	return e.pidFilter.Delete(pid)
}

// 批量添加PID
func (e *EBPFSetup) AddPIDs(pids []uint32) error {
	for _, pid := range pids {
		if err := e.AddPID(pid); err != nil {
			return fmt.Errorf("failed to add PID %d: %v", pid, err)
		}
	}
	return nil
}

// 设置PID过滤器
func (e *EBPFSetup) SetPIDFilter(pids []uint32) error {
	if len(pids) == 0 {
		return e.DisablePIDFilter()
	}

	if err := e.EnablePIDFilter(); err != nil {
		return fmt.Errorf("failed to enable PID filter: %v", err)
	}

	return e.AddPIDs(pids)
}

// Close 方法优化
func (e *EBPFSetup) Close() {
	// 关闭uprobe链接
	if e.writeProbe != nil {
		if err := e.writeProbe.Close(); err != nil {
			logger.Error("Error closing writeProbe: %v", err)
		}
	}
	if e.readProbe != nil {
		if err := e.readProbe.Close(); err != nil {
			logger.Error("Error closing readProbe: %v", err)
		}
	}
	if e.writeRetProbe != nil {
		if err := e.writeRetProbe.Close(); err != nil {
			logger.Error("Error closing writeRetProbe: %v", err)
		}
	}
	if e.readRetProbe != nil {
		if err := e.readRetProbe.Close(); err != nil {
			logger.Error("Error closing readRetProbe: %v", err)
		}
	}

	// 关闭ringbuf reader
	if e.rd != nil {
		if err := e.rd.Close(); err != nil {
			logger.Error("Error closing ringbuf reader: %v", err)
		}
	}

	// 关闭tracepoint链接
	for _, tpLink := range e.tracepointLinks {
		if tpLink != nil {
			if err := tpLink.Close(); err != nil {
				logger.Error("Error closing tracepoint link: %v", err)
			}
		}
	}

	// 关闭kprobe链接
	for _, kpLink := range e.kprobeLinks {
		if kpLink != nil {
			if err := kpLink.Close(); err != nil {
				logger.Error("Error closing kprobe link: %v", err)
			}
		}
	}

	if e.coll != nil {
		e.coll.Close()
	}
}

// 判断是否为可选探针
func isOptionalProbe(probeName string) bool {
	optionalProbes := []string{
		"gnutls_record_send",
		"gnutls_record_recv",
		"SSL_write_ex",
		"SSL_read_ex",
		"crypto/tls.(*Conn).Write",
		"crypto/tls.(*Conn).Read",
		"__sys_accept4",
		"tcp_sendmsg",
		"tcp_recvmsg",
		"tcp_data_queue",
		"tcp_write_xmit",
		"__tcp_push_pending_frames",
		"sys_connect",
		"inet_accept",
		"tcp_v4_destroy_sock",
	}

	for _, optional := range optionalProbes {
		if probeName == optional {
			return true
		}
	}
	return false
}

func Setup(soFilePath string) (*EBPFSetup, error) {
	if err := rlimit.RemoveMemlock(); err != nil {
		return nil, fmt.Errorf("failed to remove memory limit: %v", err)
	}

	spec, err := loadTls()
	if err != nil {
		return nil, fmt.Errorf("failed to load eBPF program: %v", err)
	}

	opts := ebpf.CollectionOptions{
		Programs: ebpf.ProgramOptions{
			LogLevel: ebpf.LogLevelInstruction, // 输出每条指令的验证状态
		},
	}

	// 使用 opts 加载 eBPF 程序集合
	coll, err := ebpf.NewCollectionWithOptions(spec, opts)
	if err != nil {
		return nil, fmt.Errorf("failed to create collection: %v", err)
	}

	sslLib, err := link.OpenExecutable(soFilePath)
	if err != nil {
		coll.Close()
		return nil, fmt.Errorf("failed to open executable: %v", err)
	}

	setup := &EBPFSetup{coll: coll}

	// 定义挂载点配置结构
	type attachConfig struct {
		name        string
		programName string
		attachType  string     // "uprobe", "uretprobe", "tracepoint", "kprobe"
		group       string     // 仅用于tracepoint
		target      *link.Link // 存储链接的指针
	}

	// 统一配置所有挂载点
	// 注意：暂时禁用tracepoint和kprobe探针，只保留SSL uprobe/uretprobe
	// 用于单独测试从SSL结构体获取socket的新功能
	attachConfigs := []attachConfig{
		// SSL uprobe/uretprobe - 保持启用
		{"SSL_write", "probe_entry_ssl_write", "uprobe", "", &setup.writeProbe},
		{"SSL_read", "probe_entry_ssl_read", "uprobe", "", &setup.readProbe},
		{"SSL_write", "probe_return_ssl_write", "uretprobe", "", &setup.writeRetProbe},
		{"SSL_read", "probe_return_ssl_read", "uretprobe", "", &setup.readRetProbe},
		// SSL extended functions
		{"SSL_write_ex", "probe_entry_ssl_write_ex", "uprobe", "", nil},
		{"SSL_read_ex", "probe_entry_ssl_read_ex", "uprobe", "", nil},
		// GnuTLS functions
		{"gnutls_record_send", "probe_entry_gnutls_record_send", "uprobe", "", nil},
		{"gnutls_record_recv", "probe_entry_gnutls_record_recv", "uprobe", "", nil},
		// Go TLS functions
		{"crypto/tls.(*Conn).Write", "probe_entry_go_tls_write", "uprobe", "", nil},
		{"crypto/tls.(*Conn).Read", "probe_entry_go_tls_read", "uprobe", "", nil},
		// Syscalls tracepoints
		{"sys_enter_sendto", "trace_enter_sendto", "tracepoint", "syscalls", nil},
		{"sys_enter_sendmsg", "trace_enter_sendmsg", "tracepoint", "syscalls", nil},
		{"sys_enter_write", "trace_enter_write", "tracepoint", "syscalls", nil},
		{"sys_enter_recvfrom", "trace_enter_recvfrom", "tracepoint", "syscalls", nil},
		{"sys_enter_recvmsg", "trace_enter_recvmsg", "tracepoint", "syscalls", nil},
		{"sys_enter_read", "trace_enter_read", "tracepoint", "syscalls", nil},
		// Socket syscalls
		{"sys_enter_socket", "trace_enter_socket", "tracepoint", "syscalls", nil},
		{"sys_exit_socket", "sys_exit_socket", "tracepoint", "syscalls", nil},
		{"sys_enter_connect", "trace_enter_connect", "tracepoint", "syscalls", nil},
		{"sys_exit_accept", "trace_exit_accept", "tracepoint", "syscalls", nil},
		// TCP kprobes
		{"tcp_sendmsg", "trace_tcp_sendmsg", "kprobe", "", nil},
		{"tcp_recvmsg", "trace_tcp_recvmsg", "kprobe", "", nil},
		{"tcp_data_queue", "trace_tcp_data_queue", "kprobe", "", nil},
		{"tcp_write_xmit", "trace_tcp_write_xmit", "kprobe", "", nil},
		{"__tcp_push_pending_frames", "trace_tcp_push_pending_frames", "kprobe", "", nil},
		// 新增连接跟踪探针
		{"sys_connect", "probe_connect", "kprobe", "", nil},
		{"sys_connect", "retprobe_connect", "kretprobe", "", nil},
		{"inet_accept", "probe_inet_accept", "kprobe", "", nil},
		{"__sys_accept4", "retprobe_accept4", "kretprobe", "", nil},
		{"tcp_v4_destroy_sock", "probe_tcp_v4_destroy_sock", "kprobe", "", nil},
		// SSL连接映射探针
		{"SSL_set_fd", "probe_SSL_set_fd", "uprobe", "", nil},
		{"SSL_set_rfd", "probe_SSL_set_rfd", "uprobe", "", nil},
		{"SSL_set_wfd", "probe_SSL_set_wfd", "uprobe", "", nil},
	}

	// 统一处理所有挂载点
	for _, config := range attachConfigs {
		prog, exists := coll.Programs[config.programName]
		if !exists {
			logger.Warn("Warning: program %s not found", config.programName)
			continue
		}

		var attachLink link.Link

		switch config.attachType {
		case "uprobe":
			attachLink, err = sslLib.Uprobe(config.name, prog, nil)
		case "uretprobe":
			attachLink, err = sslLib.Uretprobe(config.name, prog, nil)
		case "tracepoint":
			attachLink, err = link.Tracepoint(config.group, config.name, prog, nil)
		case "kprobe":
			attachLink, err = link.Kprobe(config.name, prog, nil)
		case "kretprobe":
			attachLink, err = link.Kretprobe(config.name, prog, nil)
		default:
			logger.Warn("Warning: unknown attach type %s for %s", config.attachType, config.name)
			continue
		}

		if err != nil {
			// 对于可选的探针（如 GnuTLS, BoringSSL, Go TLS），只记录警告而不退出
			if isOptionalProbe(config.name) {
				logger.Warn("Warning: failed to attach optional %s %s: %v", config.attachType, config.name, err)
				continue
			}
			setup.Close()
			return nil, fmt.Errorf("failed to attach %s %s: %v", config.attachType, config.name, err)
		}

		// 根据类型存储链接
		if config.target != nil {
			*config.target = attachLink
		} else {
			// 对于tracepoint和kprobe，添加到相应的切片中
			switch config.attachType {
			case "tracepoint":
				setup.tracepointLinks = append(setup.tracepointLinks, attachLink)
			case "kprobe", "kretprobe":
				setup.kprobeLinks = append(setup.kprobeLinks, attachLink)
			}
		}

		logger.Debug("Successfully attached %s: %s", config.attachType, config.name)
	}

	// 创建ringbuf reader
	setup.rd, err = ringbuf.NewReader(coll.Maps["tls_events"])
	if err != nil {
		setup.Close()
		return nil, fmt.Errorf("failed to create ringbuf reader: %v", err)
	}

	// 初始化PID过滤相关Map
	setup.pidFilter = coll.Maps["pid_filter"]
	setup.filterConfig = coll.Maps["filter_config"]
	if setup.pidFilter == nil || setup.filterConfig == nil {
		setup.Close()
		return nil, fmt.Errorf("failed to find PID filter maps")
	}

	return setup, nil
}

func ReadEventRecords(ctx context.Context, rd *ringbuf.Reader) chan ringbuf.Record {
	eventCh := make(chan ringbuf.Record, 100)

	go func() {
		defer close(eventCh)
		for {
			select {
			case <-ctx.Done():
				return
			default:
				record, err := rd.Read()
				if err != nil {
					if errors.Is(err, ringbuf.ErrClosed) {
						logger.Debug("Ringbuf reader closed")
						return
					}
					logger.Error("Reading from ringbuf failed: %v", err)
					continue
				}
				eventCh <- record
			}
		}
	}()
	return eventCh
}
