package main

import (
	"fmt"
	"log"
	"time"

	"github.com/cilium/ebpf"
	"github.com/danl5/htrack/types"
)

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
