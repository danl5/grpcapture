package main

import (
	"context"
	"errors"
	"fmt"
	"log"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/ringbuf"
	"github.com/cilium/ebpf/rlimit"
)

// TCP四元组结构体
type tcpTuple struct {
	Saddr uint32 // 源IP地址
	Daddr uint32 // 目标IP地址
	Sport uint16 // 源端口
	Dport uint16 // 目标端口
}

type tlsMeta struct {
	Pid        uint32
	Tid        uint32
	Timestamp  uint64
	DataLen    uint32
	IsRead     uint8
	Pad        [3]uint8
	Comm       [16]int8
	SslPtr     uint64
	ConnId     uint64   // 保留原有的conn_id
	Tuple      tcpTuple // 新增TCP四元组
	TupleValid uint8    // 四元组是否有效
	Pad2       [3]uint8 // 对齐填充
}

type tlsTlsEvent struct {
	Meta tlsMeta
	Data [16384]uint8
}

// eBPFSetup 结构体优化
type eBPFSetup struct {
	coll          *ebpf.Collection
	rd            *ringbuf.Reader
	writeProbe    link.Link
	readProbe     link.Link
	writeRetProbe link.Link
	readRetProbe  link.Link

	tracepointLinks []link.Link
	kprobeLinks     []link.Link
}

// Close 方法优化
func (e *eBPFSetup) Close() {
	// 关闭uprobe链接
	if e.writeProbe != nil {
		if err := e.writeProbe.Close(); err != nil {
			log.Printf("Error closing writeProbe: %v", err)
		}
	}
	if e.readProbe != nil {
		if err := e.readProbe.Close(); err != nil {
			log.Printf("Error closing readProbe: %v", err)
		}
	}
	if e.writeRetProbe != nil {
		if err := e.writeRetProbe.Close(); err != nil {
			log.Printf("Error closing writeRetProbe: %v", err)
		}
	}
	if e.readRetProbe != nil {
		if err := e.readRetProbe.Close(); err != nil {
			log.Printf("Error closing readRetProbe: %v", err)
		}
	}

	// 关闭ringbuf reader
	if e.rd != nil {
		if err := e.rd.Close(); err != nil {
			log.Printf("Error closing ringbuf reader: %v", err)
		}
	}

	// 关闭tracepoint链接
	for _, tpLink := range e.tracepointLinks {
		if tpLink != nil {
			if err := tpLink.Close(); err != nil {
				log.Printf("Error closing tracepoint link: %v", err)
			}
		}
	}

	// 关闭kprobe链接
	for _, kpLink := range e.kprobeLinks {
		if kpLink != nil {
			if err := kpLink.Close(); err != nil {
				log.Printf("Error closing kprobe link: %v", err)
			}
		}
	}

	if e.coll != nil {
		e.coll.Close()
	}
}

func setupBpf() (*eBPFSetup, error) {
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

	ex := "/usr/lib/x86_64-linux-gnu/libssl.so.3"
	sslLib, err := link.OpenExecutable(ex)
	if err != nil {
		coll.Close()
		return nil, fmt.Errorf("failed to open executable: %v", err)
	}

	setup := &eBPFSetup{coll: coll}

	// 定义挂载点配置结构
	type attachConfig struct {
		name        string
		programName string
		attachType  string     // "uprobe", "uretprobe", "tracepoint", "kprobe"
		group       string     // 仅用于tracepoint
		target      *link.Link // 存储链接的指针
	}

	// 统一配置所有挂载点
	attachConfigs := []attachConfig{
		// SSL uprobe/uretprobe
		{"SSL_write", "probe_entry_ssl_write", "uprobe", "", &setup.writeProbe},
		{"SSL_read", "probe_entry_ssl_read", "uprobe", "", &setup.readProbe},
		{"SSL_write", "probe_return_ssl_write", "uretprobe", "", &setup.writeRetProbe},
		{"SSL_read", "probe_return_ssl_read", "uretprobe", "", &setup.readRetProbe},
		// Tracepoint
		{"sys_enter_sendto", "trace_enter_sendto", "tracepoint", "syscalls", nil},
		{"sys_enter_recvfrom", "trace_enter_recvfrom", "tracepoint", "syscalls", nil},
		{"sys_enter_sendmsg", "trace_enter_send", "tracepoint", "syscalls", nil},
		{"sys_enter_recvmsg", "trace_enter_recv", "tracepoint", "syscalls", nil},
		// Kprobe
		{"tcp_sendmsg", "trace_tcp_sendmsg", "kprobe", "", nil},
		{"tcp_recvmsg", "trace_tcp_recvmsg", "kprobe", "", nil},
	}

	// 统一处理所有挂载点
	for _, config := range attachConfigs {
		prog, exists := coll.Programs[config.programName]
		if !exists {
			log.Printf("Warning: program %s not found", config.programName)
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
		default:
			log.Printf("Warning: unknown attach type %s for %s", config.attachType, config.name)
			continue
		}

		if err != nil {
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
			case "kprobe":
				setup.kprobeLinks = append(setup.kprobeLinks, attachLink)
			}
		}

		log.Printf("Successfully attached %s: %s", config.attachType, config.name)
	}

	// 创建ringbuf reader
	setup.rd, err = ringbuf.NewReader(coll.Maps["tls_events"])
	if err != nil {
		setup.Close()
		return nil, fmt.Errorf("failed to create ringbuf reader: %v", err)
	}

	return setup, nil
}

func readEventRecords(ctx context.Context, rd *ringbuf.Reader) chan ringbuf.Record {
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
						log.Println("Ringbuf reader closed")
						return
					}
					log.Printf("Reading from ringbuf failed: %v", err)
					continue
				}
				eventCh <- record
			}
		}
	}()
	return eventCh
}
