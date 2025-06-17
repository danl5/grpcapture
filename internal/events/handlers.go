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

func NewTLSEventHandler(mappingManager *mapping.MappingManager, tlsParser any, packetCh chan<- *types.PacketInfo) *TLSEventHandler {
	return &TLSEventHandler{
		mappingManager: mappingManager,
		packetCh:       packetCh,
	}
}

func (h *TLSEventHandler) GetEventType() string {
	return "TLS"
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

	// 通过MappingManager获取四元组信息（优先使用FD，失败后使用SSL指针）
	var srcIP, dstIP string
	var srcPort, dstPort uint16
	if tuple, exists := h.mappingManager.GetTupleByFDOrSSL(
		tlsEvent.Meta.Pid,
		tlsEvent.Meta.Tid,
		int32(tlsEvent.Meta.Fd),
		uintptr(tlsEvent.Meta.SslPtr)); exists {
		srcIP = fmt.Sprintf("%d.%d.%d.%d",
			tuple.SrcIP[3], tuple.SrcIP[2], tuple.SrcIP[1], tuple.SrcIP[0])
		srcPort = tuple.SrcPort
		dstIP = fmt.Sprintf("%d.%d.%d.%d",
			tuple.DstIP[3], tuple.DstIP[2], tuple.DstIP[1], tuple.DstIP[0])
		dstPort = tuple.DstPort
	}

	// 构造PacketInfo
	packetInfo := &types.PacketInfo{
		Direction:   direction,
		Data:        tlsEvent.Data,
		TimeDiff:    tlsEvent.Meta.Timestamp,
		PID:         tlsEvent.Meta.Pid,
		TID:         tlsEvent.Meta.Tid,
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
