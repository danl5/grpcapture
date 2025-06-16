package mapping

import (
	"sync"
	"time"
)

// 映射键结构
type SSLKey struct {
	PID    uint32
	TID    uint32
	SSLPtr uintptr
}

type FDKey struct {
	PID uint32
	TID uint32
	FD  int32
}

type SockInfo struct {
	SockPtr   uintptr
	Timestamp time.Time
}

type TCPTuple struct {
	SrcIP   [4]byte
	DstIP   [4]byte
	SrcPort uint16
	DstPort uint16
}

// 映射管理器
type MappingManager struct {
	// 使用读写锁保护映射表
	sslToFdMutex     sync.RWMutex
	fdToSockMutex    sync.RWMutex
	sockToTupleMutex sync.RWMutex

	// 映射表
	sslToFd     map[SSLKey]int32     // (pid, tid, ssl_ptr) -> fd
	fdToSock    map[FDKey]SockInfo   // (pid, tid, fd) -> sock_info
	sockToTuple map[uintptr]TCPTuple // sock_ptr -> tcp_tuple

	// 超时清理
	cleanupTicker *time.Ticker
	stopCleanup   chan struct{}
}

func NewMappingManager() *MappingManager {
	m := &MappingManager{
		sslToFd:     make(map[SSLKey]int32),
		fdToSock:    make(map[FDKey]SockInfo),
		sockToTuple: make(map[uintptr]TCPTuple),
		stopCleanup: make(chan struct{}),
	}
	m.startCleanupRoutine()
	return m
}

// SSL到FD的映射操作
func (m *MappingManager) SetSSLToFD(pid, tid uint32, sslPtr uintptr, fd int32) {
	key := SSLKey{PID: pid, TID: tid, SSLPtr: sslPtr}

	m.sslToFdMutex.Lock()
	defer m.sslToFdMutex.Unlock()

	m.sslToFd[key] = fd
}

func (m *MappingManager) GetFDBySSL(pid, tid uint32, sslPtr uintptr) (int32, bool) {
	key := SSLKey{PID: pid, TID: tid, SSLPtr: sslPtr}

	m.sslToFdMutex.RLock()
	defer m.sslToFdMutex.RUnlock()

	fd, exists := m.sslToFd[key]
	return fd, exists
}

// FD到Socket的映射操作
func (m *MappingManager) SetFDToSock(pid, tid uint32, fd int32, sockPtr uintptr) {
	key := FDKey{PID: pid, TID: tid, FD: fd}
	sockInfo := SockInfo{
		SockPtr:   sockPtr,
		Timestamp: time.Now(),
	}

	m.fdToSockMutex.Lock()
	defer m.fdToSockMutex.Unlock()

	m.fdToSock[key] = sockInfo
}

func (m *MappingManager) GetSockByFD(pid, tid uint32, fd int32) (uintptr, bool) {
	key := FDKey{PID: pid, TID: tid, FD: fd}

	m.fdToSockMutex.RLock()
	defer m.fdToSockMutex.RUnlock()

	sockInfo, exists := m.fdToSock[key]
	if !exists {
		return 0, false
	}
	return sockInfo.SockPtr, true
}

// Socket到TCP元组的映射操作
func (m *MappingManager) SetSockToTuple(sockPtr uintptr, tuple TCPTuple) {
	m.sockToTupleMutex.Lock()
	defer m.sockToTupleMutex.Unlock()

	m.sockToTuple[sockPtr] = tuple
}

func (m *MappingManager) GetTupleBySock(sockPtr uintptr) (TCPTuple, bool) {
	m.sockToTupleMutex.RLock()
	defer m.sockToTupleMutex.RUnlock()

	tuple, exists := m.sockToTuple[sockPtr]
	return tuple, exists
}

// 组合查询方法（链式查找）
func (m *MappingManager) GetTupleBySSL(pid, tid uint32, sslPtr uintptr) (TCPTuple, bool) {
	// 第一步：SSL -> FD
	fd, exists := m.GetFDBySSL(pid, tid, sslPtr)
	if !exists {
		return TCPTuple{}, false
	}

	// 第二步：FD -> Sock
	sockPtr, exists := m.GetSockByFD(pid, tid, fd)
	if !exists {
		return TCPTuple{}, false
	}

	// 第三步：Sock -> Tuple
	return m.GetTupleBySock(sockPtr)
}

// Socket销毁事件处理
func (m *MappingManager) HandleSocketDestroy(sockPtr uintptr) {
	// 从sock到tuple的映射中删除
	m.sockToTupleMutex.Lock()
	delete(m.sockToTuple, sockPtr)
	m.sockToTupleMutex.Unlock()

	// 从fd到sock的映射中删除相关条目
	m.fdToSockMutex.Lock()
	for key, sockInfo := range m.fdToSock {
		if sockInfo.SockPtr == sockPtr {
			delete(m.fdToSock, key)
		}
	}
	m.fdToSockMutex.Unlock()
}

// 清理机制
func (m *MappingManager) startCleanupRoutine() {
	m.cleanupTicker = time.NewTicker(30 * time.Second)

	go func() {
		for {
			select {
			case <-m.cleanupTicker.C:
				m.cleanupExpiredEntries()
			case <-m.stopCleanup:
				return
			}
		}
	}()
}

func (m *MappingManager) cleanupExpiredEntries() {
	now := time.Now()
	timeout := 5 * time.Minute

	// 清理过期的FD到Socket映射
	m.fdToSockMutex.Lock()
	for key, sockInfo := range m.fdToSock {
		if now.Sub(sockInfo.Timestamp) > timeout {
			delete(m.fdToSock, key)
		}
	}
	m.fdToSockMutex.Unlock()
}

// 停止清理例程
func (m *MappingManager) Stop() {
	if m.cleanupTicker != nil {
		m.cleanupTicker.Stop()
	}
	close(m.stopCleanup)
}

// 获取统计信息
func (m *MappingManager) GetStats() map[string]int {
	m.sslToFdMutex.RLock()
	m.fdToSockMutex.RLock()
	m.sockToTupleMutex.RLock()
	defer m.sslToFdMutex.RUnlock()
	defer m.fdToSockMutex.RUnlock()
	defer m.sockToTupleMutex.RUnlock()

	return map[string]int{
		"ssl_to_fd_mappings":     len(m.sslToFd),
		"fd_to_sock_mappings":    len(m.fdToSock),
		"sock_to_tuple_mappings": len(m.sockToTuple),
	}
}
