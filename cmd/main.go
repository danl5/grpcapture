package main

//go:generate make -C .. generate

import (
	"bytes"
	"encoding/binary"
	"errors"
	"fmt"
	"log"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/perf"
	"github.com/cilium/ebpf/rlimit"
	"github.com/danl5/htrack"
	"github.com/danl5/htrack/types"
)

type TLSDataEvent struct {
	PID       uint32
	TID       uint32
	Timestamp uint64
	DataLen   uint32
	IsRead    uint8
	_         [3]byte // padding
	Comm      [16]byte
	SSLPtr    uint64 // SSL 结构体指针，用作连接标识
	Data      [16384]byte
}

// HTTPSession 表示一个HTTP会话
type HTTPSession struct {
	htrack *htrack.HTrack
}

// httpSessions 存储所有活跃的HTTP会话
var httpSessions = make(map[string]*HTTPSession)

// initHTTPTracker 初始化HTTP跟踪器
func initHTTPTracker() *htrack.HTrack {
	config := htrack.DefaultConfig()
	return htrack.New(config)
}

func main() {
	// 移除内存限制
	if err := rlimit.RemoveMemlock(); err != nil {
		log.Fatal(err)
	}

	// 加载 eBPF 程序
	spec, err := loadTls()
	if err != nil {
		log.Fatalf("Failed to load eBPF program: %v", err)
	}

	coll, err := ebpf.NewCollection(spec)
	if err != nil {
		log.Fatalf("Failed to create collection: %v", err)
	}
	defer coll.Close()

	// 附加 uprobes
	ex := "/usr/lib/x86_64-linux-gnu/libssl.so.3"

	// SSL_write uprobe
	sslWrite, err := link.OpenExecutable(ex)
	if err != nil {
		log.Fatalf("Failed to open executable: %v", err)
	}

	writeProbe, err := sslWrite.Uprobe("SSL_write", coll.Programs["probe_entry_ssl_write"], nil)
	if err != nil {
		log.Fatalf("Failed to attach SSL_write uprobe: %v", err)
	}
	defer writeProbe.Close()

	readProbe, err := sslWrite.Uprobe("SSL_read", coll.Programs["probe_entry_ssl_read"], nil)
	if err != nil {
		log.Fatalf("Failed to attach SSL_read uretprobe: %v", err)
	}
	defer readProbe.Close()

	// SSL_write uretprobe
	writeRetProbe, err := sslWrite.Uretprobe("SSL_write", coll.Programs["probe_return_ssl_write"], nil)
	if err != nil {
		log.Fatalf("Failed to attach SSL_write uretprobe: %v", err)
	}
	defer writeRetProbe.Close()

	// SSL_read uretprobe
	readRetProbe, err := sslWrite.Uretprobe("SSL_read", coll.Programs["probe_return_ssl_read"], nil)
	if err != nil {
		log.Fatalf("Failed to attach SSL_read uretprobe: %v", err)
	}
	defer readRetProbe.Close()

	// 创建 perf reader
	rd, err := perf.NewReader(coll.Maps["tls_events"], os.Getpagesize())
	if err != nil {
		log.Fatalf("Failed to create perf reader: %v", err)
	}
	defer rd.Close()

	// 初始化 HTTP 解析器
	initHTTPParser()

	// 信号处理
	sig := make(chan os.Signal, 1)
	signal.Notify(sig, os.Interrupt, syscall.SIGTERM)

	fmt.Println("Capturing TLS data... Press Ctrl+C to stop.")

	go func() {
		<-sig
		fmt.Println("\nStopping...")
		os.Exit(0)
	}()

	for {
		if err := processEvent(rd); err != nil {
			if errors.Is(err, perf.ErrClosed) {
				return
			}
			log.Printf("Error processing event: %v", err)
		}
	}
}

// 动态查找 TLS 库
func findTLSLibraries() []string {
	libraries := []string{}

	// OpenSSL
	openssl := []string{
		"/usr/lib/x86_64-linux-gnu/libssl.so.3",
	}

	// GnuTLS
	gnutls := []string{
		"/usr/lib/x86_64-linux-gnu/libgnutls.so.30",
	}

	// 检查库是否存在
	for _, lib := range append(openssl, gnutls...) {
		if _, err := os.Stat(lib); err == nil {
			libraries = append(libraries, lib)
		}
	}

	return libraries
}

// 初始化 HTTP 解析器
func initHTTPParser() {
	log.Println("HTTP parser initialized")
}

// 在 main.go 中更新 processEvent 函数
func processEvent(rd *perf.Reader) error {
	// 读取事件元数据
	record, err := rd.Read()
	if err != nil {
		return err
	}

	if record.LostSamples != 0 {
		log.Printf("Lost %d samples", record.LostSamples)
		return nil
	}

	var event tlsTlsDataEvent
	if err := binary.Read(bytes.NewBuffer(record.RawSample), binary.LittleEndian, &event); err != nil {
		log.Printf("Failed to decode event: %v", err)
		return nil
	}

	direction := types.DirectionServerToClient
	if event.IsRead == 1 {
		direction = types.DirectionClientToServer
	}

	commBytes := make([]byte, len(event.Comm))
	for i, v := range event.Comm {
		commBytes[i] = byte(v)
	}
	comm := string(bytes.TrimRight(commBytes, "\x00"))

	// 如果有数据，读取数据部分
	if event.DataLen > 0 {
		dataRecord, err := rd.Read()
		if err != nil {
			log.Printf("Failed to read data: %v", err)
			return nil
		}

		// 获取原始数据
		rawData := dataRecord.RawSample[:min(int(event.DataLen), len(dataRecord.RawSample))]

		// 创建连接级别的会话ID（基于PID、进程名和SSL指针）
		sessionID := fmt.Sprintf("%d-%s-%x", event.Pid, comm, event.SslPtr)

		// 使用htrack解析数据
		req, resp, err := htrack.ProcessHTTPPacket(sessionID, rawData, direction)
		printHTTPData(req, resp, err, rawData)
	}
	return nil
}

// printHTTPData 打印HTTP数据的函数
func printHTTPData(req *types.HTTPRequest, resp *types.HTTPResponse, parseErr error, rawData []byte) {
	if parseErr != nil {
		// 如果解析失败，打印原始数据
		fmt.Printf("Failed to parse HTTP data: %v\n", parseErr)
		// 清理不可打印字符
		data := string(rawData)
		data = strings.Map(func(r rune) rune {
			if r >= 32 && r < 127 {
				return r
			}
			return '.'
		}, data)
		fmt.Printf("Raw Data: %s\n", data)
		return
	}

	timestamp := time.Now()

	// 打印解析结果
	if req != nil {
		fmt.Printf("\n=== HTTP REQUEST === %s\n", timestamp)
		fmt.Printf("Method: %s\n", req.Method)
		fmt.Printf("URL: %s\n", req.URL)
		fmt.Printf("Version: %d.%d\n", req.ProtoMajor, req.ProtoMinor)
		
		// 打印HTTP/2相关信息
		if req.StreamID != nil {
			fmt.Printf("Stream ID: %d\n", *req.StreamID)
		}
		
		fmt.Printf("Headers:\n")
		for key, values := range req.Headers {
			for _, value := range values {
				fmt.Printf("  %s: %s\n", key, value)
			}
		}
		if len(req.Body) > 0 {
			fmt.Printf("Body: %s\n", string(req.Body))
		}
		fmt.Printf("==================\n\n")
	}
	if resp != nil {
		fmt.Printf("\n=== HTTP RESPONSE === %s\n", timestamp)
		fmt.Printf("Status: %s\n", resp.Status)
		fmt.Printf("Version: %d.%d\n", resp.ProtoMajor, resp.ProtoMinor)
		
		// 打印HTTP/2相关信息
		if resp.StreamID != nil {
			fmt.Printf("Stream ID: %d\n", *resp.StreamID)
		}
		
		fmt.Printf("Headers:\n")
		for key, values := range resp.Headers {
			for _, value := range values {
				fmt.Printf("  %s: %s\n", key, value)
			}
		}
		if len(resp.Body) > 0 {
			fmt.Printf("Body: %s\n", string(resp.Body))
		}
		fmt.Printf("===================\n\n")
	}
}
