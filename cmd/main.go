package main

//go:generate make -C .. generate

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
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
	// 设置 eBPF
	ebpfSetup, err := setupEBPF()
	if err != nil {
		log.Fatalf("eBPF setup failed: %v", err)
	}
	defer ebpfSetup.Close()

	// 初始化 HTTP 解析器
	hTracker := initHTTPParser()

	// 使用context管理goroutine生命周期
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	// 启动HTTP数据处理
	go processHTTPData(ctx, hTracker)

	// 创建事件channel
	eventCh := make(chan ringbuf.Record, 100) // 带缓冲的channel提高吞吐量[1,2](@ref)

	// 启动ringbuf事件读取goroutine
	go func() {
		defer close(eventCh) // 确保退出时关闭channel
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

type tlsMeta struct {
	Pid       uint32
	Tid       uint32
	Timestamp uint64
	DataLen   uint32
	IsRead    uint8
	Pad       [3]uint8
	Comm      [16]int8
	SslPtr    uint64
	ConnId    uint64
}

type tlsTlsEvent struct {
	Meta tlsMeta
	Data [16384]uint8
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

	// 使用PID+TID+ConnID作为唯一标识符
	sessionID := fmt.Sprintf("%s-%d-%d-%d", comm, meta.Pid, meta.Tid, meta.ConnId)
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
}

// Close 方法优化
func (e *eBPFSetup) Close() {
	closers := []io.Closer{
		e.writeProbe,
		e.readProbe,
		e.writeRetProbe,
		e.readRetProbe,
		e.rd,
	}

	for _, closer := range closers {
		if closer != nil {
			if err := closer.Close(); err != nil {
				log.Printf("Error closing resource: %v", err)
			}
		}
	}

	if e.coll != nil {
		e.coll.Close()
	}
}

// eBPF设置优化
func setupEBPF() (*eBPFSetup, error) {
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

	// 2. 使用 opts 加载 eBPF 程序集合
	coll, err := ebpf.NewCollectionWithOptions(spec, opts)
	if err != nil {
		return nil, fmt.Errorf("failed to create collection: %v", err)
	}

	ex := "/usr/lib/x86_64-linux-gnu/libssl.so.3"
	sslWrite, err := link.OpenExecutable(ex)
	if err != nil {
		coll.Close()
		return nil, fmt.Errorf("failed to open executable: %v", err)
	}

	setup := &eBPFSetup{coll: coll}

	attachUprobe := func(fnName string, prog *ebpf.Program) (link.Link, error) {
		return sslWrite.Uprobe(fnName, prog, nil)
	}

	attachUretprobe := func(fnName string, prog *ebpf.Program) (link.Link, error) {
		return sslWrite.Uretprobe(fnName, prog, nil)
	}

	// 附加探针
	if setup.writeProbe, err = attachUprobe("SSL_write", coll.Programs["probe_entry_ssl_write"]); err != nil {
		setup.Close()
		return nil, err
	}
	if setup.readProbe, err = attachUprobe("SSL_read", coll.Programs["probe_entry_ssl_read"]); err != nil {
		setup.Close()
		return nil, err
	}
	if setup.writeRetProbe, err = attachUretprobe("SSL_write", coll.Programs["probe_return_ssl_write"]); err != nil {
		setup.Close()
		return nil, err
	}
	if setup.readRetProbe, err = attachUretprobe("SSL_read", coll.Programs["probe_return_ssl_read"]); err != nil {
		setup.Close()
		return nil, err
	}

	// 创建ringbuf reader替换perf reader
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
