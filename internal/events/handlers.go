package events

import (
	"bytes"
	"fmt"
	"net"
	"unsafe"

	"github.com/danl5/grpcapture/internal/logger"
	"github.com/danl5/grpcapture/internal/mapping"
	"github.com/danl5/htrack/types"
)

// TLSEventHandler 处理TLS事件
type TLSEventHandler struct {
	mappingManager *mapping.MappingManager
	packetCh       chan<- *types.PacketInfo
}

func NewTLSEventHandler(mappingManager *mapping.MappingManager, tlsParser interface{}, packetCh chan<- *types.PacketInfo) *TLSEventHandler {
	return &TLSEventHandler{
		mappingManager: mappingManager,
		packetCh:       packetCh,
	}
}

func (h *TLSEventHandler) GetEventType() string {
	return "TLS"
}

// generateNormalizedConnID 生成规范化的连接ID
// 通过比较IP地址和端口，确保同一连接的双向流量使用相同的连接ID
func (h *TLSEventHandler) generateNormalizedConnID(saddr, daddr uint32, sport, dport uint16) string {
	// 将IP地址转换为字符串进行比较
	srcIP := fmt.Sprintf("%d.%d.%d.%d",
		(saddr>>24)&0xFF, (saddr>>16)&0xFF, (saddr>>8)&0xFF, saddr&0xFF)
	dstIP := fmt.Sprintf("%d.%d.%d.%d",
		(daddr>>24)&0xFF, (daddr>>16)&0xFF, (daddr>>8)&0xFF, daddr&0xFF)

	// 规范化：较小的IP:端口组合作为第一部分
	if srcIP < dstIP || (srcIP == dstIP && sport < dport) {
		return fmt.Sprintf("%s:%d-%s:%d", srcIP, sport, dstIP, dport)
	} else {
		return fmt.Sprintf("%s:%d-%s:%d", dstIP, dport, srcIP, sport)
	}
}

func (h *TLSEventHandler) CanHandle(eventType EventType) bool {
	return eventType == EventTypeTLS
}

func (h *TLSEventHandler) Handle(event Event) error {
	tlsEvent, ok := event.(*TLSEvent)
	if !ok {
		return fmt.Errorf("expected TLSEvent, got %T", event)
	}

	// 提取元数据
	commBytes := *(*[16]byte)(unsafe.Pointer(&tlsEvent.Meta.Comm[0]))
	comm := string(bytes.TrimRight(commBytes[:], "\x00"))

	// 提取方向信息
	direction := types.DirectionServerToClient
	if tlsEvent.Meta.IsRead == 1 {
		direction = types.DirectionClientToServer
	}

	// 提取四元组信息
	var srcIP, dstIP string
	var srcPort, dstPort uint16
	if tlsEvent.Meta.TupleValid == 1 {
		tuple := tlsEvent.Meta.Tuple
		srcIP = fmt.Sprintf("%d.%d.%d.%d",
			(tuple.Saddr>>24)&0xFF,
			(tuple.Saddr>>16)&0xFF,
			(tuple.Saddr>>8)&0xFF,
			tuple.Saddr&0xFF)
		srcPort = tuple.Sport
		dstIP = fmt.Sprintf("%d.%d.%d.%d",
			(tuple.Daddr>>24)&0xFF,
			(tuple.Daddr>>16)&0xFF,
			(tuple.Daddr>>8)&0xFF,
			tuple.Daddr&0xFF)
		dstPort = tuple.Dport
	}

	// 构造PacketInfo
	packetInfo := &types.PacketInfo{
		Direction:   direction,
		Data:        tlsEvent.Data,
		TimeDiff:    tlsEvent.Meta.Timestamp,
		PID:         tlsEvent.Meta.Pid,
		ProcessName: comm,
		TCPTuple: &types.TCPTuple{
			SrcIP:   srcIP,
			SrcPort: srcPort,
			DstIP:   dstIP,
			DstPort: dstPort,
		},
	}

	// 发送到处理通道
	select {
	case h.packetCh <- packetInfo:
		return nil
	default:
		return fmt.Errorf("packet channel is full")
	}
}

// SSL设置FD事件处理器
type SSLSetFDEventHandler struct {
	mappingManager *mapping.MappingManager
}

func NewSSLSetFDEventHandler(mappingManager *mapping.MappingManager) *SSLSetFDEventHandler {
	return &SSLSetFDEventHandler{
		mappingManager: mappingManager,
	}
}

func (h *SSLSetFDEventHandler) CanHandle(eventType EventType) bool {
	return eventType == EventTypeSSLSetFD
}

func (h *SSLSetFDEventHandler) Handle(event Event) error {
	sslSetFDEvent, ok := event.(*SSLSetFDEvent)
	if !ok {
		return fmt.Errorf("invalid event type for SSL set FD handler")
	}

	// 设置SSL到FD的映射
	h.mappingManager.SetSSLToFD(
		sslSetFDEvent.PID,
		sslSetFDEvent.TID,
		sslSetFDEvent.SSLPtr,
		sslSetFDEvent.FD,
	)

	logger.Debug("SSL set FD mapping: PID=%d, TID=%d, SSL=%x, FD=%d",
		sslSetFDEvent.PID, sslSetFDEvent.TID, sslSetFDEvent.SSLPtr, sslSetFDEvent.FD)

	return nil
}

// 连接事件处理器
type ConnectEventHandler struct {
	mappingManager *mapping.MappingManager
}

func NewConnectEventHandler(mappingManager *mapping.MappingManager) *ConnectEventHandler {
	return &ConnectEventHandler{
		mappingManager: mappingManager,
	}
}

func (h *ConnectEventHandler) CanHandle(eventType EventType) bool {
	return eventType == EventTypeConnect || eventType == EventTypeSocketDestroy
}

func (h *ConnectEventHandler) Handle(event Event) error {
	connectEvent, ok := event.(*ConnectEvent)
	if !ok {
		return fmt.Errorf("invalid event type for connect handler")
	}

	if connectEvent.IsDestroy {
		// 处理Socket销毁事件
		h.mappingManager.HandleSocketDestroy(connectEvent.SockPtr)
		logger.Debug("Socket destroyed: sock=%x", connectEvent.SockPtr)
	} else {
		// 处理连接建立事件
		// 设置FD到Socket的映射
		h.mappingManager.SetFDToSock(
			connectEvent.PID,
			connectEvent.TID,
			connectEvent.FD,
			connectEvent.SockPtr,
		)

		// 设置Socket到TCP元组的映射
		tuple := mapping.TCPTuple{
			SrcIP:   connectEvent.SrcIP,
			DstIP:   connectEvent.DstIP,
			SrcPort: connectEvent.SrcPort,
			DstPort: connectEvent.DstPort,
		}
		h.mappingManager.SetSockToTuple(connectEvent.SockPtr, tuple)

		logger.Info("Connection established: PID=%d, TID=%d, FD=%d, sock=%x, %s:%d -> %s:%d",
			connectEvent.PID, connectEvent.TID, connectEvent.FD, connectEvent.SockPtr,
			net.IP(connectEvent.SrcIP[:]), connectEvent.SrcPort,
			net.IP(connectEvent.DstIP[:]), connectEvent.DstPort)
	}

	return nil
}

// 统计事件处理器（可选）
type StatsEventHandler struct {
	mappingManager *mapping.MappingManager
}

func NewStatsEventHandler(mappingManager *mapping.MappingManager) *StatsEventHandler {
	return &StatsEventHandler{
		mappingManager: mappingManager,
	}
}

func (h *StatsEventHandler) CanHandle(eventType EventType) bool {
	// 处理所有类型的事件以收集统计信息
	return true
}

func (h *StatsEventHandler) Handle(event Event) error {
	// 这里可以收集各种统计信息
	// 例如：事件计数、处理延迟等
	return nil
}
