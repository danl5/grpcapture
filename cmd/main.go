package main

//go:generate make -C .. generate

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"log"
	"os"
	"os/signal"
	"sync"
	"syscall"
	"time"
	"unsafe"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/ringbuf"
	"github.com/cilium/ebpf/rlimit"
	"github.com/danl5/htrack"
	"github.com/danl5/htrack/types"
)

// ConnectionInfo 存储连接的详细信息
type ConnectionInfo struct {
	ID              string
	OriginalSSLPtr  uint64
	PID             uint32
	Comm            string
	CreatedAt       time.Time
	LastActivity    time.Time
	SequenceNumber  uint64
	DataPacketCount int
	mutex           sync.RWMutex
}

func main() {
	ebpfSetup, err := setupBpf()
	if err != nil {
		log.Fatalf("eBPF setup failed: %v", err)
	}
	defer ebpfSetup.Close()

	// 初始化 HTTP 解析器
	hTracker := initHTTPParser()

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	// 启动HTTP数据处理
	go processHTTPData(ctx, hTracker)

	// 创建事件channel
	eventCh := make(chan ringbuf.Record, 100)

	// 启动ringbuf事件读取goroutine
	go func() {
		defer close(eventCh)
		for {
			record, err := ebpfSetup.rd.Read()
			if err != nil {
				if errors.Is(err, ringbuf.ErrClosed) {
					log.Println("Ringbuf reader closed")
					return
				}
				log.Printf("Reading from ringbuf failed: %v", err)
				continue
			}
			select {
			case eventCh <- record:
			case <-ctx.Done():
				return
			}
		}
	}()

	// 信号处理
	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, os.Interrupt, syscall.SIGTERM)
	go func() {
		<-sigCh
		fmt.Println("\nStopping...")
		cancel()
	}()

	fmt.Println("Capturing TLS data... Press Ctrl+C to stop.")

	// 事件处理循环
	for {
		select {
		case <-ctx.Done():
			// printStats(ebpfSetup.coll)
			return
		case record, ok := <-eventCh:
			if !ok {
				log.Println("Event channel closed, exiting")
				return
			}
			if err := processRecord(record, hTracker); err != nil {
				log.Printf("Error processing event: %v", err)
			}
		}
	}
}

// 初始化 HTTP 解析器
func initHTTPParser() *htrack.HTrack {
	log.Println("HTTP parser initialized")
	return htrack.New(&htrack.Config{
		MaxSessions:       10000,
		MaxTransactions:   10000,
		BufferSize:        64 * 1024, // 64KB
		EnableHTTP1:       true,
		EnableHTTP2:       true,
		AutoCleanup:       true,
		CleanupInterval:   5 * time.Minute,
		ChannelBufferSize: 100,
		EnableChannels:    true,
	})
}

// HTTP数据处理协程
func processHTTPData(ctx context.Context, hTracker *htrack.HTrack) {
	for {
		select {
		case <-ctx.Done():
			return
		case req := <-hTracker.GetRequestChan():
			printHTTPData(req, nil)
		case resp := <-hTracker.GetResponseChan():
			printHTTPData(nil, resp)
		}
	}
}

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

// 辅助函数：将uint32 IP地址转换为字符串
func uint32ToIP(ip uint32) string {
	return fmt.Sprintf("%d.%d.%d.%d",
		(ip>>24)&0xFF,
		(ip>>16)&0xFF,
		(ip>>8)&0xFF,
		ip&0xFF)
}

// 处理ringbuf记录
func processRecord(record ringbuf.Record, hTracker *htrack.HTrack) error {

	event := (*tlsTlsEvent)(unsafe.Pointer(&record.RawSample[0]))
	meta := event.Meta
	metaSize := unsafe.Sizeof(meta)

	// 优化方向判断逻辑
	direction := types.DirectionServerToClient
	if meta.IsRead == 1 {
		direction = types.DirectionClientToServer
	}

	// 提取元数据
	commBytes := *(*[16]byte)(unsafe.Pointer(&meta.Comm[0]))
	comm := bytes.TrimRight(commBytes[:], "\x00")

	// 提取数据部分 - 从meta之后开始提取实际数据
	dataLen := int(meta.DataLen)
	if dataLen <= 0 || dataLen > len(record.RawSample)-int(metaSize) {
		return fmt.Errorf("invalid data length: %d, available: %d", dataLen, len(record.RawSample)-int(metaSize))
	}
	// 数据从meta结构体之后开始
	rawData := record.RawSample[metaSize : metaSize+uintptr(dataLen)]

	// 构造会话ID - 优先使用TCP四元组，回退到原有方案
	var sessionID string
	if meta.TupleValid == 1 {
		fmt.Println("connid", meta.ConnId)
		sessionID = fmt.Sprintf("%d", meta.ConnId)

		// 根据isRead字段调整四元组显示方向
		var srcIP, dstIP string
		var srcPort, dstPort uint16

		if meta.IsRead == 1 {
			// 读取操作：数据从远程流向本地（客户端 -> 服务端）
			srcIP = uint32ToIP(meta.Tuple.Daddr) // 远程地址作为源
			srcPort = meta.Tuple.Dport           // 远程端口作为源
			dstIP = uint32ToIP(meta.Tuple.Saddr) // 本地地址作为目标
			dstPort = meta.Tuple.Sport           // 本地端口作为目标
			fmt.Printf("[DEBUG] TCP Tuple (READ): %s:%d -> %s:%d (PID: %d, SSL: 0x%x)\n",
				srcIP, srcPort, dstIP, dstPort, meta.Pid, meta.SslPtr)
		} else {
			// 写入操作：数据从本地流向远程（服务端 -> 客户端）
			srcIP = uint32ToIP(meta.Tuple.Saddr) // 本地地址作为源
			srcPort = meta.Tuple.Sport           // 本地端口作为源
			dstIP = uint32ToIP(meta.Tuple.Daddr) // 远程地址作为目标
			dstPort = meta.Tuple.Dport           // 远程端口作为目标
			fmt.Printf("[DEBUG] TCP Tuple (WRITE): %s:%d -> %s:%d (PID: %d, SSL: 0x%x)\n",
				srcIP, srcPort, dstIP, dstPort, meta.Pid, meta.SslPtr)
		}
	} else {
		// 回退到原有的PID+TID+ConnID方案
		sessionID = fmt.Sprintf("%s-%d-%d-%d", comm, meta.Pid, meta.Tid, meta.ConnId)
		fmt.Printf("[DEBUG] Fallback to legacy ConnID: %d (PID: %d, SSL: 0x%x)\n",
			meta.ConnId, meta.Pid, meta.SslPtr)
	}

	if err := hTracker.ProcessPacket(sessionID, rawData, direction); err != nil {
		return fmt.Errorf("parse data failed: %w", err)
	}

	return nil
}

// 优化打印函数
func printHTTPData(req *types.HTTPRequest, resp *types.HTTPResponse) {
	timestamp := time.Now().Format("2006-01-02 15:04:05")

	if req != nil {
		fmt.Printf("\n=== HTTP REQUEST === %s\n", timestamp)
		fmt.Printf("Method: %s\nURL: %s\nVersion: %d.%d\n",
			req.Method, req.URL, req.ProtoMajor, req.ProtoMinor)

		if req.StreamID != nil {
			fmt.Printf("Stream ID: %d\n", *req.StreamID)
		}

		printHeaders(req.Headers)
		if len(req.Body) > 0 {
			fmt.Printf("Body: %s\n", string(req.Body))
		}
		fmt.Printf("==================\n\n")
	}

	if resp != nil {
		fmt.Printf("\n=== HTTP RESPONSE === %s\n", timestamp)
		fmt.Printf("Status: %s\nVersion: %d.%d\n",
			resp.Status, resp.ProtoMajor, resp.ProtoMinor)

		if resp.StreamID != nil {
			fmt.Printf("Stream ID: %d\n", *resp.StreamID)
		}

		printHeaders(resp.Headers)
		if len(resp.Body) > 0 {
			fmt.Printf("Body: %s\n", string(resp.Body))
		}
		fmt.Printf("===================\n\n")
	}
}

// 提取公共头部打印逻辑
func printHeaders(headers map[string][]string) {
	fmt.Println("Headers:")
	for key, values := range headers {
		for _, value := range values {
			fmt.Printf("  %s: %s\n", key, value)
		}
	}
}

// eBPFSetup 结构体优化
type eBPFSetup struct {
	coll          *ebpf.Collection
	rd            *ringbuf.Reader
	writeProbe    link.Link
	readProbe     link.Link
	writeRetProbe link.Link
	readRetProbe  link.Link
	// 新增的监测点
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

// 打印统计信息
func printStats(coll *ebpf.Collection) {
	statsMap := coll.Maps["stats"]
	if statsMap == nil {
		log.Println("Stats map not found")
		return
	}

	// 读取write事件计数
	var writeKey uint32 = 0
	var writeCount uint64
	if err := statsMap.Lookup(&writeKey, &writeCount); err != nil {
		log.Printf("Failed to read write stats: %v", err)
		writeCount = 0
	}

	// 读取read事件计数
	var readKey uint32 = 1
	var readCount uint64
	if err := statsMap.Lookup(&readKey, &readCount); err != nil {
		log.Printf("Failed to read read stats: %v", err)
		readCount = 0
	}

	fmt.Printf("\n=== Ring Buffer 统计信息 ===\n")
	fmt.Printf("SSL_write 事件提交次数: %d\n", writeCount)
	fmt.Printf("SSL_read 事件提交次数: %d\n", readCount)
	fmt.Printf("总提交次数: %d\n", writeCount+readCount)
}
