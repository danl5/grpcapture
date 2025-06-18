package formatter

import (
	"fmt"
	"strings"

	"github.com/danl5/htrack/types"
)

// OutputFormat 定义输出格式
type OutputFormat int

const (
	FormatText OutputFormat = iota
	FormatHex
)

// Formatter 格式化器接口
type Formatter interface {
	FormatHTTPData(req *types.HTTPRequest, resp *types.HTTPResponse) string
	FormatTLSData(req *types.HTTPRequest, resp *types.HTTPResponse) string
}

// DefaultFormatter 默认格式化器
type DefaultFormatter struct {
	bodyFormat OutputFormat
}

// NewDefaultFormatter 创建默认格式化器
func NewDefaultFormatter(bodyFormat OutputFormat) *DefaultFormatter {
	return &DefaultFormatter{
		bodyFormat: bodyFormat,
	}
}

// FormatHTTPData 格式化HTTP数据
func (f *DefaultFormatter) FormatHTTPData(req *types.HTTPRequest, resp *types.HTTPResponse) string {
	var result strings.Builder

	if req != nil {
		result.WriteString("\n=== HTTP Request ===\n")
		result.WriteString(fmt.Sprintf("Method: %s\n", req.Method))
		result.WriteString(fmt.Sprintf("URL: %s\n", req.URL))
		result.WriteString(fmt.Sprintf("Proto: %s\n", req.Proto))
		result.WriteString("Headers:\n")
		for k, v := range req.Headers {
			result.WriteString(fmt.Sprintf("  %s: %s\n", k, v))
		}
		if len(req.Body) > 0 {
			result.WriteString("Body:\n")
			result.WriteString(f.formatBody(req.Body))
		}
	}

	if resp != nil {
		result.WriteString("\n=== HTTP Response ===\n")
		result.WriteString(fmt.Sprintf("Status: %s\n", resp.Status))
		result.WriteString(fmt.Sprintf("Proto: %s\n", resp.Proto))
		result.WriteString("Headers:\n")
		for k, v := range resp.Headers {
			result.WriteString(fmt.Sprintf("  %s: %s\n", k, v))
		}
		if len(resp.Body) > 0 {
			result.WriteString("Body:\n")
			result.WriteString(f.formatBody(resp.Body))
		}
	}

	return result.String()
}

// FormatTLSData 格式化TLS数据
func (f *DefaultFormatter) FormatTLSData(req *types.HTTPRequest, resp *types.HTTPResponse) string {
	var result strings.Builder

	if req != nil {
		result.WriteString("\n=== TLS Data (Request) ===\n")
		result.WriteString(fmt.Sprintf("Process: %s (PID: %d)\n", req.ProcessName, req.PID))
		if req.TCPTuple != nil {
			result.WriteString(fmt.Sprintf("Connection: %s:%d -> %s:%d\n", 
				req.TCPTuple.SrcIP, req.TCPTuple.SrcPort, 
				req.TCPTuple.DstIP, req.TCPTuple.DstPort))
		}
		result.WriteString(fmt.Sprintf("Data Length: %d bytes\n", len(req.Body)))
		if len(req.Body) > 0 {
			result.WriteString("Raw Data:\n")
			result.WriteString(f.formatBody(req.Body))
		}
	}

	if resp != nil {
		result.WriteString("\n=== TLS Data (Response) ===\n")
		result.WriteString(fmt.Sprintf("Process: %s (PID: %d)\n", resp.ProcessName, resp.PID))
		if resp.TCPTuple != nil {
			result.WriteString(fmt.Sprintf("Connection: %s:%d -> %s:%d\n", 
				resp.TCPTuple.SrcIP, resp.TCPTuple.SrcPort, 
				resp.TCPTuple.DstIP, resp.TCPTuple.DstPort))
		}
		result.WriteString(fmt.Sprintf("Data Length: %d bytes\n", len(resp.Body)))
		if len(resp.Body) > 0 {
			result.WriteString("Raw Data:\n")
			result.WriteString(f.formatBody(resp.Body))
		}
	}

	return result.String()
}

// formatBody 格式化body数据
func (f *DefaultFormatter) formatBody(body []byte) string {
	if len(body) == 0 {
		return ""
	}

	switch f.bodyFormat {
	case FormatHex:
		return f.formatHexDump(body)
	default:
		return string(body) + "\n"
	}
}

// formatHexDump 格式化十六进制输出
// 格式: 地址偏移 | 十六进制字节 | ASCII字符
func (f *DefaultFormatter) formatHexDump(data []byte) string {
	if len(data) == 0 {
		return ""
	}

	var result strings.Builder
	for i := 0; i < len(data); i += 16 {
		// 打印地址偏移
		result.WriteString(fmt.Sprintf("%08x  ", i))

		// 打印十六进制字节
		for j := 0; j < 16; j++ {
			if i+j < len(data) {
				result.WriteString(fmt.Sprintf("%02x ", data[i+j]))
			} else {
				result.WriteString("   ")
			}
			// 在第8个字节后添加额外空格
			if j == 7 {
				result.WriteString(" ")
			}
		}

		// 打印ASCII字符
		result.WriteString(" |")
		for j := 0; j < 16 && i+j < len(data); j++ {
			b := data[i+j]
			if b >= 32 && b <= 126 {
				result.WriteString(fmt.Sprintf("%c", b))
			} else {
				result.WriteString(".")
			}
		}
		result.WriteString("|\n")
	}
	result.WriteString("\n")
	return result.String()
}

// PrintHTTPData 打印HTTP数据（兼容性函数）
func PrintHTTPData(req *types.HTTPRequest, resp *types.HTTPResponse) {
	formatter := NewDefaultFormatter(FormatText)
	fmt.Print(formatter.FormatHTTPData(req, resp))
}

// PrintHTTPDataHex 打印HTTP数据（十六进制格式）
func PrintHTTPDataHex(req *types.HTTPRequest, resp *types.HTTPResponse) {
	formatter := NewDefaultFormatter(FormatHex)
	fmt.Print(formatter.FormatHTTPData(req, resp))
}

// PrintTLSData 打印TLS数据（兼容性函数）
func PrintTLSData(req *types.HTTPRequest, resp *types.HTTPResponse) {
	formatter := NewDefaultFormatter(FormatText)
	fmt.Print(formatter.FormatTLSData(req, resp))
}

// PrintTLSDataHex 打印TLS数据（十六进制格式）
func PrintTLSDataHex(req *types.HTTPRequest, resp *types.HTTPResponse) {
	formatter := NewDefaultFormatter(FormatHex)
	fmt.Print(formatter.FormatTLSData(req, resp))
}