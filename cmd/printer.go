package main

import (
	"fmt"
	"log"
	"time"

	"github.com/cilium/ebpf"
	"github.com/danl5/htrack/types"
)

func printHTTPData(req *types.HTTPRequest, resp *types.HTTPResponse) {
	if req != nil {
		fmt.Printf("%s > IN HTTP %s:%d -> %s:%d %s\n",
			req.ProcessName,
			req.TCPTuple.SrcIP, req.TCPTuple.SrcPort, req.TCPTuple.DstIP, req.TCPTuple.DstPort,
			req.Timestamp.Format("2006-01-02 15:04:05.0000"))
		fmt.Printf("Method: %s\nURL: %s\nVersion: %d.%d\n",
			req.Method, req.URL, req.ProtoMajor, req.ProtoMinor)

		if req.StreamID != nil {
			fmt.Printf("Stream ID: %d\n", *req.StreamID)
		}

		printHeaders(req.Headers)
		if len(req.Body) > 0 {
			printBody(req.Body, printHex)
		}
		fmt.Printf("\n")
	}

	if resp != nil {
		fmt.Printf("%s > OUT HTTP %s:%d -> %s:%d %s\n",
			resp.ProcessName,
			resp.TCPTuple.SrcIP, resp.TCPTuple.SrcPort, resp.TCPTuple.DstIP, resp.TCPTuple.DstPort,
			resp.Timestamp.Format("2006-01-02 15:04:05.0000"))
		fmt.Printf("Status: %s\nVersion: %d.%d\n",
			resp.Status, resp.ProtoMajor, resp.ProtoMinor)

		if resp.StreamID != nil {
			fmt.Printf("Stream ID: %d\n", *resp.StreamID)
		}

		printHeaders(resp.Headers)
		if len(resp.Body) > 0 {
			printBody(resp.Body, printHex)
		}
		fmt.Printf("\n")
	}
}

func printTLSData(req *types.HTTPRequest, resp *types.HTTPResponse) {
	if req != nil {
		fmt.Printf("%s > IN TLS %s:%d -> %s:%d %s\n",
			req.ProcessName,
			req.TCPTuple.SrcIP, req.TCPTuple.SrcPort, req.TCPTuple.DstIP, req.TCPTuple.DstPort,
			req.Timestamp.Format("2006-01-02 15:04:05.0000"))

		if len(req.Body) > 0 {
			printBody(req.Body, printHex)
		}
		fmt.Printf("\n")
	}

	if resp != nil {
		fmt.Printf("%s > OUT TLS %s:%d -> %s:%d %s\n",
			req.ProcessName,
			resp.TCPTuple.SrcIP, resp.TCPTuple.SrcPort, resp.TCPTuple.DstIP, resp.TCPTuple.DstPort,
			resp.Timestamp.Format("2006-01-02 15:04:05.0000"))

		if len(resp.Body) > 0 {
			printBody(resp.Body, printHex)
		}
		fmt.Printf("\n")
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

func printBody(body []byte, toHex bool) {
	if len(body) == 0 {
		return
	}

	if !toHex {
		fmt.Printf("Body: %s\n", string(body))
		return
	}

	printHexDump(body)
}

// 打印字节数组为格式化的十六进制输出
// 格式: 地址偏移 | 十六进制字节 | ASCII字符
func printHexDump(data []byte) {
	if len(data) == 0 {
		return
	}
	for i := 0; i < len(data); i += 16 {
		// 打印地址偏移
		fmt.Printf("%08x  ", i)

		// 打印十六进制字节
		for j := 0; j < 16; j++ {
			if i+j < len(data) {
				fmt.Printf("%02x ", data[i+j])
			} else {
				fmt.Print("   ")
			}
			// 在第8个字节后添加额外空格
			if j == 7 {
				fmt.Print(" ")
			}
		}

		// 打印ASCII字符
		fmt.Print(" |")
		for j := 0; j < 16 && i+j < len(data); j++ {
			b := data[i+j]
			if b >= 32 && b <= 126 {
				fmt.Printf("%c", b)
			} else {
				fmt.Print(".")
			}
		}
		fmt.Println("|")
	}
	fmt.Println()
}

// 将纳秒时间偏移转换为可读的时间间隔字符串
func formatNanosecondOffset(ns uint64) string {
	// 将纳秒转换为time.Duration
	duration := time.Duration(ns)

	// 根据时间长度选择合适的格式
	if duration < time.Microsecond {
		return fmt.Sprintf("%dns", ns)
	} else if duration < time.Millisecond {
		return fmt.Sprintf("%.3fμs", float64(ns)/1000.0)
	} else if duration < time.Second {
		return fmt.Sprintf("%.3fms", float64(ns)/1000000.0)
	} else if duration < time.Minute {
		return fmt.Sprintf("%.3fs", float64(ns)/1000000000.0)
	} else {
		// 对于更长的时间，使用标准的Duration.String()格式
		return duration.String()
	}
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
