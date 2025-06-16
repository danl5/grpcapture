package logger

import (
	"log"
	"os"
)

// Logger 全局日志实例
var (
	Verbose bool = false
	stdLogger = log.New(os.Stdout, "", log.LstdFlags)
	errLogger = log.New(os.Stderr, "", log.LstdFlags)
)

// SetVerbose 设置详细日志模式
func SetVerbose(verbose bool) {
	Verbose = verbose
}

// Info 输出信息日志
func Info(format string, args ...interface{}) {
	stdLogger.Printf("[INFO] "+format, args...)
}

// Warn 输出警告日志
func Warn(format string, args ...interface{}) {
	stdLogger.Printf("[WARN] "+format, args...)
}

// Error 输出错误日志
func Error(format string, args ...interface{}) {
	errLogger.Printf("[ERROR] "+format, args...)
}

// Fatal 输出致命错误日志并退出
func Fatal(format string, args ...interface{}) {
	errLogger.Printf("[FATAL] "+format, args...)
	os.Exit(1)
}

// Debug 输出调试日志（仅在 verbose 模式下）
func Debug(format string, args ...interface{}) {
	if Verbose {
		stdLogger.Printf("[DEBUG] "+format, args...)
	}
}

// Verbose 输出详细日志（仅在 verbose 模式下）
func VerboseLog(format string, args ...interface{}) {
	if Verbose {
		stdLogger.Printf("[VERBOSE] "+format, args...)
	}
}