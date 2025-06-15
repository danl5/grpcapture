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
	printHex   bool
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
			switch {
			case req.Proto == "TLS/Other":
				printTLSData(req, nil)
			case strings.HasPrefix(req.Proto, "HTTP/1.0"):
				fallthrough
			case strings.HasPrefix(req.Proto, "HTTP/1.1"):
				fallthrough
			case strings.HasPrefix(req.Proto, "HTTP/2"):
				printHTTPData(req, nil)
			}

		case resp := <-hTracker.GetResponseChan():
			switch {
			case resp.Proto == "TLS/Other":
				printTLSData(nil, resp)
			case strings.HasPrefix(resp.Proto, "HTTP/1.0"):
				fallthrough
			case strings.HasPrefix(resp.Proto, "HTTP/1.1"):
				fallthrough
			case strings.HasPrefix(resp.Proto, "HTTP/2"):
				printHTTPData(nil, resp)
			}
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

	dataLen := int(meta.DataLen)
	if dataLen <= 0 || dataLen > len(event.Data) {
		return fmt.Errorf("invalid data length: %d, available: %d", dataLen, len(event.Data))
	}

	rawData := event.Data[:dataLen]

	var sessionID string
	if meta.TupleValid == 1 {
		// 使用规范化的TCP四元组生成会话ID，确保同一连接的双向流量使用相同ID
		sessionID = generateNormalizedConnID(
			meta.Tuple.Saddr, meta.Tuple.Daddr,
			meta.Tuple.Sport, meta.Tuple.Dport)
	} else {
		// 回退到原有的PID+TID方案
		sessionID = fmt.Sprintf("%d-%d-%d", meta.Pid, meta.Tid, meta.SslPtr)
	}

	fmt.Println(rawData)

	packetInfo := buildPacketInfo(&meta, rawData)
	if err := hTracker.ProcessPacket(sessionID, packetInfo); err != nil {
		return fmt.Errorf("parse data failed: %w", err)
	}

	return nil
}

func buildPacketInfo(meta *tlsMeta, data []byte) *types.PacketInfo {
	// 提取元数据
	commBytes := *(*[16]byte)(unsafe.Pointer(&meta.Comm[0]))
	comm := bytes.TrimRight(commBytes[:], "\x00")

	// 提取方向信息
	direction := types.DirectionServerToClient
	if meta.IsRead == 1 {
		direction = types.DirectionClientToServer
	}

	// 提取四元组信息
	var srcIP, dstIP string
	var srcPort, dstPort uint16
	if meta.TupleValid == 1 {
		srcIP = uint32ToIP(meta.Tuple.Saddr)
		srcPort = meta.Tuple.Sport
		dstIP = uint32ToIP(meta.Tuple.Daddr)
		dstPort = meta.Tuple.Dport
	}

	// 构造PacketInfo
	packetInfo := &types.PacketInfo{
		Direction:   direction,
		Data:        data,
		TimeDiff:    meta.Timestamp,
		PID:         meta.Pid,
		ProcessName: string(comm),
		TCPTuple: &types.TCPTuple{
			SrcIP:   srcIP,
			SrcPort: srcPort,
			DstIP:   dstIP,
			DstPort: dstPort,
		},
	}

	return packetInfo
}

// 解析命令行参数
func parseCmdArgs() {
	var pidStr = flag.String("pid", "", "Target PID to monitor")
	var pidsStr = flag.String("pids", "", "Comma-separated list of PIDs to monitor")
	var pidFile = flag.String("pid-file", "", "File containing PIDs to monitor (one per line)")
	var soFile = flag.String("so-file", "/usr/lib/x86_64-linux-gnu/libssl.so.3", "Path to the SSL library file to monitor")
	var hex = flag.Bool("hex", false, "Print body in hex")

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
	printHex = *hex
}

// generateNormalizedConnID 生成规范化的连接ID
// 通过比较IP地址和端口，确保同一连接的双向流量使用相同的连接ID
func generateNormalizedConnID(saddr, daddr uint32, sport, dport uint16) string {
	// 将IP地址转换为字符串进行比较
	srcIP := uint32ToIP(saddr)
	dstIP := uint32ToIP(daddr)

	// 规范化：较小的IP:端口组合作为第一部分
	if srcIP < dstIP || (srcIP == dstIP && sport < dport) {
		return fmt.Sprintf("%s:%d-%s:%d", srcIP, sport, dstIP, dport)
	} else {
		return fmt.Sprintf("%s:%d-%s:%d", dstIP, dport, srcIP, sport)
	}
}
