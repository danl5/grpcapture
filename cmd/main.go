package main

//go:generate make -C .. generate

import (
	"bytes"
	"context"
	"flag"
	"fmt"
	"io/ioutil"
	"log"
	"os"
	"os/signal"
	"strconv"
	"strings"
	"syscall"
	"time"
	"unsafe"

	"github.com/cilium/ebpf/ringbuf"
	"github.com/danl5/htrack"
	"github.com/danl5/htrack/types"
)

var (
	targetPIDs []uint32
	soFilePath string
)

func main() {
	// 解析命令行参数
	parseCmdArgs()

	ebpfSetup, err := setupBpf(soFilePath)
	if err != nil {
		log.Fatalf("eBPF setup failed: %v", err)
	}
	defer ebpfSetup.Close()

	// 配置PID过滤
	if len(targetPIDs) > 0 {
		log.Printf("Enabling PID filter for PIDs: %v", targetPIDs)
		if err := ebpfSetup.EnablePIDFilter(); err != nil {
			log.Fatalf("Failed to enable PID filter: %v", err)
		}
		if err := ebpfSetup.AddPIDs(targetPIDs); err != nil {
			log.Fatalf("Failed to add target PIDs: %v", err)
		}
		log.Printf("PID filter configured successfully")
	} else {
		log.Printf("No PID filter specified, monitoring all processes")
	}

	// 初始化 HTTP 解析器
	hTracker := initTLSParser()

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	// 启动HTTP数据处理
	go processHTTPData(ctx, hTracker)

	eventCh := readEventRecords(ctx, ebpfSetup.rd)

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

// 初始化 TLS 解析器
func initTLSParser() *htrack.HTrack {
	log.Println("TLS parser initialized")
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

	// 添加调试信息
	log.Printf("DEBUG: Received event - PID=%d, SSL=%x, IsRead=%t, TupleValid=%t, DataLen=%d",
		meta.Pid, meta.SslPtr, meta.IsRead == 1, meta.TupleValid == 1, meta.DataLen)

	if meta.TupleValid == 1 {
		log.Printf("DEBUG: Tuple - %s:%d -> %s:%d",
			uint32ToIP(meta.Tuple.Saddr), meta.Tuple.Sport,
			uint32ToIP(meta.Tuple.Daddr), meta.Tuple.Dport)
	} else {
		log.Printf("DEBUG: No valid tuple for this event")
	}

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

	rawData := event.Data[:dataLen]

	// 构造会话ID - 优先使用TCP四元组，回退到原有方案
	var sessionID string
	var srcIP, dstIP string
	var srcPort, dstPort uint16

	if meta.TupleValid == 1 {
		sessionID = fmt.Sprintf("%d", meta.ConnId)

		// 根据isRead字段调整四元组显示方向
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

	packetInfo := types.PacketInfo{
		Direction: direction,
		Data:      rawData,
		TimeDiff:  meta.Timestamp,
		TCPTuple: &types.TCPTuple{
			SrcIP:   srcIP,
			SrcPort: srcPort,
			DstIP:   dstIP,
			DstPort: dstPort,
		},
	}
	if err := hTracker.ProcessPacket(sessionID, &packetInfo); err != nil {
		return fmt.Errorf("parse data failed: %w", err)
	}

	return nil
}

// 解析命令行参数
func parseCmdArgs() {
	var pidStr = flag.String("pid", "", "Target PID to monitor")
	var pidsStr = flag.String("pids", "", "Comma-separated list of PIDs to monitor")
	var pidFile = flag.String("pid-file", "", "File containing PIDs to monitor (one per line)")
	var soFile = flag.String("so-file", "/usr/lib/x86_64-linux-gnu/libssl.so.3", "Path to the SSL library file to monitor")

	flag.Parse()

	// 解析单个PID参数
	if *pidStr != "" {
		if pid, err := strconv.ParseUint(*pidStr, 10, 32); err == nil {
			targetPIDs = append(targetPIDs, uint32(pid))
		} else {
			log.Printf("Warning: invalid PID format: %s", *pidStr)
		}
	}

	// 解析多个PID参数
	if *pidsStr != "" {
		for _, pidStr := range strings.Split(*pidsStr, ",") {
			pidStr = strings.TrimSpace(pidStr)
			if pidStr != "" {
				if pid, err := strconv.ParseUint(pidStr, 10, 32); err == nil {
					targetPIDs = append(targetPIDs, uint32(pid))
				} else {
					log.Printf("Warning: invalid PID format: %s", pidStr)
				}
			}
		}
	}

	// 从文件读取PID列表
	if *pidFile != "" {
		if data, err := ioutil.ReadFile(*pidFile); err == nil {
			for _, line := range strings.Split(string(data), "\n") {
				line = strings.TrimSpace(line)
				// 跳过空行和注释行
				if line != "" && !strings.HasPrefix(line, "#") {
					if pid, err := strconv.ParseUint(line, 10, 32); err == nil {
						targetPIDs = append(targetPIDs, uint32(pid))
					} else {
						log.Printf("Warning: invalid PID format in file: %s", line)
					}
				}
			}
		} else {
			log.Printf("Warning: failed to read PID file %s: %v", *pidFile, err)
		}
	}

	// 去重PID列表
	if len(targetPIDs) > 0 {
		pidMap := make(map[uint32]bool)
		uniquePIDs := make([]uint32, 0)
		for _, pid := range targetPIDs {
			if !pidMap[pid] {
				pidMap[pid] = true
				uniquePIDs = append(uniquePIDs, pid)
			}
		}
		targetPIDs = uniquePIDs
	}

	// 设置so文件路径
	soFilePath = *soFile
}
