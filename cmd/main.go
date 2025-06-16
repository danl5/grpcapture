package main

import (
	"context"
	"fmt"
	"net"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"
	"unsafe"

	"github.com/cilium/ebpf/ringbuf"
	htrack "github.com/danl5/htrack"
	"github.com/danl5/htrack/types"

	"github.com/danl5/grpcapture/internal/config"
	"github.com/danl5/grpcapture/internal/ebpf"
	"github.com/danl5/grpcapture/internal/events"
	"github.com/danl5/grpcapture/internal/formatter"
	"github.com/danl5/grpcapture/internal/logger"
	"github.com/danl5/grpcapture/internal/mapping"
)

func main() {
	// 解析命令行参数
	cfg := config.ParseFlags()
	pidFilter := cfg.TargetPIDs
	sslLibPath := cfg.SOFile

	// 设置日志模式
	logger.SetVerbose(cfg.Verbose)

	// 初始化格式化器
	var bodyFormat formatter.OutputFormat
	if cfg.HexOutput {
		bodyFormat = formatter.FormatHex
	} else {
		bodyFormat = formatter.FormatText
	}
	formatterInstance := formatter.NewDefaultFormatter(bodyFormat)

	// 设置eBPF程序
	logger.Debug("Setting up eBPF with SSL library: %s", sslLibPath)
	ebpfSetup, err := ebpf.Setup(sslLibPath)
	if err != nil {
		logger.Fatal("Failed to setup eBPF: %v", err)
	}
	defer ebpfSetup.Close()
	logger.Debug("eBPF setup completed successfully")

	// 配置PID过滤
	if len(pidFilter) > 0 {
		logger.Debug("Setting PID filter: %v", pidFilter)
		if err := ebpfSetup.SetPIDFilter(pidFilter); err != nil {
			logger.Fatal("Failed to set PID filter: %v", err)
		}
		logger.Info("PID filter set: %v", pidFilter)
	} else {
		logger.Info("No PID filter specified, monitoring all processes")
	}

	// 初始化组件
	mappingManager := mapping.NewMappingManager()
	defer mappingManager.Stop()

	eventDispatcher := events.NewEventDispatcher()
	defer eventDispatcher.Stop()

	// 初始化TLS解析器
	hTracker := initTLSParser()

	// 创建数据包处理通道
	packetCh := make(chan *types.PacketInfo, 1000)

	// 注册事件处理器
	tlsHandler := events.NewTLSEventHandler(mappingManager, nil, packetCh)
	sslSetFDHandler := events.NewSSLSetFDEventHandler(mappingManager)
	connectHandler := events.NewConnectEventHandler(mappingManager)
	statsHandler := events.NewStatsEventHandler(mappingManager)

	eventDispatcher.RegisterHandler(tlsHandler)
	eventDispatcher.RegisterHandler(sslSetFDHandler)
	eventDispatcher.RegisterHandler(connectHandler)
	eventDispatcher.RegisterHandler(statsHandler)

	// 启动事件分发器
	eventDispatcher.Start()

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	// 启动HTTP数据处理
	go processHTTPDataRefactored(ctx, hTracker, packetCh, formatterInstance)

	// 启动事件读取器
	go startEventReaders(ctx, ebpfSetup, eventDispatcher)

	// 启动统计信息打印
	go printStatsRefactored(ctx, eventDispatcher, mappingManager)

	// 信号处理
	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, os.Interrupt, syscall.SIGTERM)
	go func() {
		<-sigCh
		fmt.Println("\nStopping...")
		cancel()
	}()

	fmt.Println("Capturing TLS data with refactored architecture... Press Ctrl+C to stop.")

	// 等待退出信号
	<-ctx.Done()
	logger.Info("Shutdown complete")
}

// 启动所有事件读取器
func startEventReaders(ctx context.Context, ebpfSetup *ebpf.EBPFSetup, dispatcher *events.EventDispatcher) {
	// TLS事件读取器
	go func() {
		tlsEventCh := ebpf.ReadEventRecords(ctx, ebpfSetup.GetRingBuffer())
		for {
			select {
			case <-ctx.Done():
				return
			case record, ok := <-tlsEventCh:
				if !ok {
					logger.Debug("TLS event channel closed")
					return
				}
				if err := processTLSRecord(record, dispatcher); err != nil {
					logger.Error("Error processing TLS record: %v", err)
				}
			}
		}
	}()

	// SSL设置FD事件读取器
	go func() {
		sslSetFdReader, err := ringbuf.NewReader(ebpfSetup.GetCollection().Maps["ssl_set_fd_events"])
		if err != nil {
			logger.Error("Failed to create SSL set FD event reader: %v", err)
			return
		}
		logger.Debug("SSL set FD event reader created successfully")
		defer sslSetFdReader.Close()

		for {
			select {
			case <-ctx.Done():
				return
			default:
				record, err := sslSetFdReader.Read()
				if err != nil {
					if ctx.Err() != nil {
						return
					}
					logger.Error("Reading SSL set FD event failed: %v", err)
					continue
				}
				if err := processSSLSetFDRecord(record, dispatcher); err != nil {
					logger.Error("Error processing SSL set FD record: %v", err)
				}
			}
		}
	}()

	// 连接事件读取器
	go func() {
		connectReader, err := ringbuf.NewReader(ebpfSetup.GetCollection().Maps["connect_events"])
		if err != nil {
			logger.Error("Failed to create connect event reader: %v", err)
			return
		}
		logger.Debug("Connect event reader created successfully")
		defer connectReader.Close()

		for {
			select {
			case <-ctx.Done():
				return
			default:
				record, err := connectReader.Read()
				if err != nil {
					if ctx.Err() != nil {
						return
					}
					logger.Error("Reading connect event failed: %v", err)
					continue
				}
				if err := processConnectRecord(record, dispatcher); err != nil {
					logger.Error("Error processing connect record: %v", err)
				}
			}
		}
	}()
}

// 处理TLS记录
func processTLSRecord(record ringbuf.Record, dispatcher *events.EventDispatcher) error {
	event := (*ebpf.TlsTlsEvent)(unsafe.Pointer(&record.RawSample[0]))
	meta := event.Meta

	dataLen := int(meta.DataLen)
	if dataLen <= 0 || dataLen > len(event.Data) {
		return fmt.Errorf("invalid data length: %d, available: %d", dataLen, len(event.Data))
	}

	rawData := make([]byte, dataLen)
	copy(rawData, event.Data[:dataLen])

	// 创建TLS事件
	tlsEvent := &events.TLSEvent{
		Meta: meta,
		Data: rawData,
	}

	// 分发事件
	dispatcher.DispatchEvent(tlsEvent)
	return nil
}

// 处理SSL设置FD记录
func processSSLSetFDRecord(record ringbuf.Record, dispatcher *events.EventDispatcher) error {
	event := (*ebpf.SslSetFdEvent)(unsafe.Pointer(&record.RawSample[0]))

	// 创建SSL设置FD事件
	sslSetFDEvent := &events.SSLSetFDEvent{
		PID:    event.Pid,
		TID:    event.Tid,
		SSLPtr: uintptr(event.SslPtr),
		FD:     int32(event.Fd),
	}

	// 分发事件
	dispatcher.DispatchEvent(sslSetFDEvent)
	return nil
}

// 处理连接记录
func processConnectRecord(record ringbuf.Record, dispatcher *events.EventDispatcher) error {
	event := (*ebpf.ConnectEvent)(unsafe.Pointer(&record.RawSample[0]))

	// 创建连接事件
	connectEvent := &events.ConnectEvent{
		PID:       event.Pid,
		TID:       uint32(event.Tid),
		FD:        int32(event.Fd),
		SockPtr:   uintptr(event.Sock),
		SrcIP:     [4]byte{byte(event.Saddr), byte(event.Saddr >> 8), byte(event.Saddr >> 16), byte(event.Saddr >> 24)},
		DstIP:     [4]byte{byte(event.Daddr), byte(event.Daddr >> 8), byte(event.Daddr >> 16), byte(event.Daddr >> 24)},
		SrcPort:   event.Sport,
		DstPort:   event.Dport,
		IsDestroy: event.IsDestroy == 1,
	}

	// 分发事件
	dispatcher.DispatchEvent(connectEvent)
	return nil
}

// HTTP数据处理协程（重构版）
func processHTTPDataRefactored(ctx context.Context, hTracker *htrack.HTrack, packetCh <-chan *types.PacketInfo, formatter *formatter.DefaultFormatter) {
	for {
		select {
		case <-ctx.Done():
			return
		case packetInfo := <-packetCh:
			// 处理数据包
			connID := fmt.Sprintf("%s:%d-%s:%d",
				net.IP(packetInfo.TCPTuple.SrcIP[:]).String(), packetInfo.TCPTuple.SrcPort,
				net.IP(packetInfo.TCPTuple.DstIP[:]).String(), packetInfo.TCPTuple.DstPort)
			if err := hTracker.ProcessPacket(connID, packetInfo); err != nil {
				logger.Debug("Parse data failed: %v", err)
				continue
			}

			// 处理解析结果
			select {
			case req := <-hTracker.GetRequestChan():
				switch {
				case req.Proto == "TLS/Other":
					fmt.Print(formatter.FormatTLSData(req, nil))
				case strings.HasPrefix(req.Proto, "HTTP/1.0"),
					strings.HasPrefix(req.Proto, "HTTP/1.1"),
					strings.HasPrefix(req.Proto, "HTTP/2"):
					fmt.Print(formatter.FormatHTTPData(req, nil))
				}
			case resp := <-hTracker.GetResponseChan():
				switch {
				case resp.Proto == "TLS/Other":
					fmt.Print(formatter.FormatTLSData(nil, resp))
				case strings.HasPrefix(resp.Proto, "HTTP/1.0"),
					strings.HasPrefix(resp.Proto, "HTTP/1.1"),
					strings.HasPrefix(resp.Proto, "HTTP/2"):
					fmt.Print(formatter.FormatHTTPData(nil, resp))
				}
			default:
				// 没有新的解析结果
			}
		}
	}
}

// 打印统计信息（重构版）
func printStatsRefactored(ctx context.Context, dispatcher *events.EventDispatcher, mappingManager *mapping.MappingManager) {
	ticker := time.NewTicker(30 * time.Second)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			// 打印事件分发器统计
			eventStats := dispatcher.GetStats()
			logger.VerboseLog("=== Event Dispatcher Stats ===")
			for eventType, stats := range eventStats {
				logger.VerboseLog("%s: Processed=%d, Errors=%d", eventType, stats.Processed, stats.Errors)
			}

			// 打印映射管理器统计
			mappingStats := mappingManager.GetStats()
			logger.VerboseLog("=== Mapping Manager Stats ===")
			for name, count := range mappingStats {
				logger.VerboseLog("%s: %d", name, count)
			}
		}
	}
}

// 初始化 TLS 解析器
func initTLSParser() *htrack.HTrack {
	logger.Debug("Initializing TLS parser")
	parser := htrack.New(&htrack.Config{
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
	logger.Debug("TLS parser initialized successfully")
	return parser
}
