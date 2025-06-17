package config

import (
	"flag"
	"os"
	"strconv"
	"strings"

	"github.com/danl5/grpcapture/internal/logger"
)

// Config 应用配置
type Config struct {
	TargetPIDs []uint32
	SOFile     string
	HexOutput  bool
	Debug      bool
}

// ParseFlags 解析命令行参数
func ParseFlags() *Config {
	var pidStr = flag.String("pid", "", "Target PID to monitor")
	var pidsStr = flag.String("pids", "", "Comma-separated list of PIDs to monitor")
	var pidFile = flag.String("pid-file", "", "File containing PIDs to monitor (one per line)")
	var soFile = flag.String("so-file", "/usr/lib/x86_64-linux-gnu/libssl.so.3", "Path to the SSL library file to monitor")
	var hexOutput = flag.Bool("hex", false, "Output body data in hexadecimal format")
	var debug = flag.Bool("debug", false, "Enable debug logging")

	flag.Parse()

	config := &Config{
		SOFile:    *soFile,
		HexOutput: *hexOutput,
		Debug:     *debug,
	}

	// 解析PID参数
	config.TargetPIDs = parsePIDs(*pidStr, *pidsStr, *pidFile)

	return config
}

// parsePIDs 解析PID参数
func parsePIDs(pidStr, pidsStr, pidFile string) []uint32 {
	var targetPIDs []uint32

	// 解析单个PID参数
	if pidStr != "" {
		if pid, err := strconv.ParseUint(pidStr, 10, 32); err == nil {
			targetPIDs = append(targetPIDs, uint32(pid))
		} else {
			logger.Warn("Warning: invalid PID format: %s", pidStr)
		}
	}

	// 解析多个PID参数
	if pidsStr != "" {
		for _, pidStr := range strings.Split(pidsStr, ",") {
			pidStr = strings.TrimSpace(pidStr)
			if pidStr != "" {
				if pid, err := strconv.ParseUint(pidStr, 10, 32); err == nil {
					targetPIDs = append(targetPIDs, uint32(pid))
				} else {
					logger.Warn("Warning: invalid PID format: %s", pidStr)
				}
			}
		}
	}

	// 从文件读取PID列表
	if pidFile != "" {
		if data, err := os.ReadFile(pidFile); err == nil {
			for _, line := range strings.Split(string(data), "\n") {
				line = strings.TrimSpace(line)
				// 跳过空行和注释行
				if line != "" && !strings.HasPrefix(line, "#") {
					if pid, err := strconv.ParseUint(line, 10, 32); err == nil {
					targetPIDs = append(targetPIDs, uint32(pid))
				} else {
					logger.Warn("Warning: invalid PID format in file: %s", line)
				}
				}
			}
		} else {
			logger.Warn("Warning: failed to read PID file %s: %v", pidFile, err)
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

	return targetPIDs
}