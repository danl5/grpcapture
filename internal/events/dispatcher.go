package events

import (
	"sync"
	"time"

	"github.com/danl5/grpcapture/internal/ebpf"
	"github.com/danl5/grpcapture/internal/logger"
)

// 事件类型枚举
type EventType int

const (
	EventTypeTLS EventType = iota
	EventTypeSSLSetFD
	EventTypeConnect
	EventTypeSocketDestroy
)

func (et EventType) String() string {
	switch et {
	case EventTypeTLS:
		return "TLS"
	case EventTypeSSLSetFD:
		return "SSLSetFD"
	case EventTypeConnect:
		return "Connect"
	case EventTypeSocketDestroy:
		return "SocketDestroy"
	default:
		return "Unknown"
	}
}

// 统一事件接口
type Event interface {
	Type() EventType
	Timestamp() time.Time
}

// TLS事件
type TLSEvent struct {
	Meta      ebpf.TlsMeta
	Data      []byte
	timestamp time.Time
}

func (e *TLSEvent) Type() EventType      { return EventTypeTLS }
func (e *TLSEvent) Timestamp() time.Time { return e.timestamp }

// SSL设置FD事件
type SSLSetFDEvent struct {
	PID       uint32
	TID       uint32
	SSLPtr    uintptr
	FD        int32
	timestamp time.Time
}

func (e *SSLSetFDEvent) Type() EventType      { return EventTypeSSLSetFD }
func (e *SSLSetFDEvent) Timestamp() time.Time { return e.timestamp }

// 连接事件
type ConnectEvent struct {
	PID       uint32
	TID       uint32
	FD        int32
	SockPtr   uintptr
	SrcIP     [4]byte
	DstIP     [4]byte
	SrcPort   uint16
	DstPort   uint16
	IsDestroy bool
	timestamp time.Time
}

func (e *ConnectEvent) Type() EventType {
	if e.IsDestroy {
		return EventTypeSocketDestroy
	}
	return EventTypeConnect
}
func (e *ConnectEvent) Timestamp() time.Time { return e.timestamp }

// 事件处理器接口
type EventHandler interface {
	Handle(event Event) error
	CanHandle(eventType EventType) bool
}

// 事件分发器
type EventDispatcher struct {
	handlers map[EventType][]EventHandler
	eventCh  chan Event
	stopCh   chan struct{}
	wg       sync.WaitGroup

	// 统计信息
	stats struct {
		sync.RWMutex
		processed map[EventType]uint64
		errors    map[EventType]uint64
	}
}

func NewEventDispatcher() *EventDispatcher {
	return &EventDispatcher{
		handlers: make(map[EventType][]EventHandler),
		eventCh:  make(chan Event, 1000), // 缓冲通道
		stopCh:   make(chan struct{}),
		stats: struct {
			sync.RWMutex
			processed map[EventType]uint64
			errors    map[EventType]uint64
		}{
			processed: make(map[EventType]uint64),
			errors:    make(map[EventType]uint64),
		},
	}
}

// 注册事件处理器
func (d *EventDispatcher) RegisterHandler(handler EventHandler) {
	for eventType := EventTypeTLS; eventType <= EventTypeSocketDestroy; eventType++ {
		if handler.CanHandle(eventType) {
			d.handlers[eventType] = append(d.handlers[eventType], handler)
		}
	}
}

// 发送事件
func (d *EventDispatcher) DispatchEvent(event Event) {
	select {
	case d.eventCh <- event:
	default:
		// 通道满了，记录错误或丢弃事件
		logger.Warn("Event channel full, dropping event of type %v", event.Type())
	}
}

// 启动事件处理循环
func (d *EventDispatcher) Start() {
	d.wg.Add(1)
	go d.eventLoop()
}

// 停止事件处理
func (d *EventDispatcher) Stop() {
	close(d.stopCh)
	d.wg.Wait()
}

// 事件处理主循环
func (d *EventDispatcher) eventLoop() {
	defer d.wg.Done()

	for {
		select {
		case event := <-d.eventCh:
			d.handleEvent(event)
		case <-d.stopCh:
			// 处理剩余事件
			for {
				select {
				case event := <-d.eventCh:
					d.handleEvent(event)
				default:
					return
				}
			}
		}
	}
}

// 处理单个事件
func (d *EventDispatcher) handleEvent(event Event) {
	eventType := event.Type()
	handlers, exists := d.handlers[eventType]
	if !exists {
		logger.Debug("No handlers registered for event type %v", eventType)
		return
	}

	// 并发处理多个处理器
	var wg sync.WaitGroup
	for _, handler := range handlers {
		wg.Add(1)
		go func(h EventHandler) {
			defer wg.Done()
			if err := h.Handle(event); err != nil {
				logger.Error("Handler error for event type %v: %v", eventType, err)
				d.incrementErrorCount(eventType)
			} else {
				d.incrementProcessedCount(eventType)
			}
		}(handler)
	}
	wg.Wait()
}

// 统计方法
func (d *EventDispatcher) incrementProcessedCount(eventType EventType) {
	d.stats.Lock()
	d.stats.processed[eventType]++
	d.stats.Unlock()
}

func (d *EventDispatcher) incrementErrorCount(eventType EventType) {
	d.stats.Lock()
	d.stats.errors[eventType]++
	d.stats.Unlock()
}

func (d *EventDispatcher) GetStats() map[EventType]struct{ Processed, Errors uint64 } {
	d.stats.RLock()
	defer d.stats.RUnlock()

	result := make(map[EventType]struct{ Processed, Errors uint64 })
	for eventType := EventTypeTLS; eventType <= EventTypeSocketDestroy; eventType++ {
		result[eventType] = struct{ Processed, Errors uint64 }{
			Processed: d.stats.processed[eventType],
			Errors:    d.stats.errors[eventType],
		}
	}
	return result
}
