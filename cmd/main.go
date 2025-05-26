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
)

type TLSDataEvent struct {
	PID       uint32
	TID       uint32
	Timestamp uint64
	DataLen   uint32
	IsRead    uint8
	_         [3]byte // padding
	Data      [16384]byte
	Comm      [16]byte
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

	direction := "WRITE"
	if event.IsRead == 1 {
		direction = "READ"
	}

	commBytes := make([]byte, len(event.Comm))
	for i, v := range event.Comm {
		commBytes[i] = byte(v)
	}
	comm := string(bytes.TrimRight(commBytes, "\x00"))
	timestamp := time.Unix(0, int64(event.Timestamp))

	fmt.Printf("[%s] PID: %d, Process: %s, %s %d bytes\n",
		timestamp.Format("15:04:05.000000"),
		event.Pid,
		comm,
		direction,
		event.DataLen)

	// 如果有数据，读取数据部分
	if event.DataLen > 0 {
		dataRecord, err := rd.Read()
		if err != nil {
			log.Printf("Failed to read data: %v", err)
			return nil
		}

		data := string(dataRecord.RawSample[:min(int(event.DataLen), len(dataRecord.RawSample))])
		// 清理不可打印字符
		data = strings.Map(func(r rune) rune {
			if r >= 32 && r < 127 {
				return r
			}
			return '.'
		}, data)

		fmt.Printf("Data: %s\n", data)
	}

	fmt.Println(strings.Repeat("-", 80))
	return nil
}
