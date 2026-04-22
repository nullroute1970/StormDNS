// ==============================================================================
// StormDNS
// Author: nullroute1970
// Github: https://github.com/nullroute1970/StormDNS
// Year: 2026
// ==============================================================================

package inflight

import (
	"sync"
	"time"
)

type Entry[T any] struct {
	createdAt time.Time
	ready     chan struct{}
	value     T
	hasValue  bool
}

type Manager[T any] struct {
	timeout       time.Duration
	cleanupWindow time.Duration
	nextCleanupAt time.Time
	cloneValue    func(T) T
	mu            sync.Mutex
	items         map[string]*Entry[T]
}

func New[T any](timeout time.Duration, fallback time.Duration, cloneValue func(T) T) *Manager[T] {
	if timeout <= 0 {
		timeout = fallback
	}
	cleanupWindow := timeout / 4
	if cleanupWindow < time.Second {
		cleanupWindow = time.Second
	}
	return &Manager[T]{
		timeout:       timeout,
		cleanupWindow: cleanupWindow,
		cloneValue:    cloneValue,
		items:         make(map[string]*Entry[T]),
	}
}

func (m *Manager[T]) Acquire(key string, now time.Time) (*Entry[T], bool) {
	if m == nil || key == "" {
		return nil, false
	}

	m.mu.Lock()
	defer m.mu.Unlock()

	if m.nextCleanupAt.IsZero() || !now.Before(m.nextCleanupAt) {
		for existingKey, entry := range m.items {
			if entry == nil || now.Sub(entry.createdAt) >= m.timeout {
				delete(m.items, existingKey)
			}
		}
		m.nextCleanupAt = now.Add(m.cleanupWindow)
	}

	if entry, ok := m.items[key]; ok && entry != nil && now.Sub(entry.createdAt) < m.timeout {
		return entry, false
	}

	entry := &Entry[T]{
		createdAt: now,
		ready:     make(chan struct{}),
	}
	m.items[key] = entry
	return entry, true
}

func (m *Manager[T]) Begin(key string, now time.Time) bool {
	_, leader := m.Acquire(key, now)
	return leader
}

func (m *Manager[T]) Resolve(key string, value T, hasValue bool) {
	if m == nil || key == "" {
		return
	}

	m.mu.Lock()
	entry := m.items[key]
	delete(m.items, key)
	if entry != nil && hasValue {
		entry.value = m.clone(value)
		entry.hasValue = true
	}
	m.mu.Unlock()

	if entry != nil {
		close(entry.ready)
	}
}

func (m *Manager[T]) Wait(entry *Entry[T], timeout time.Duration) (T, bool) {
	var zero T
	if entry == nil {
		return zero, false
	}
	if timeout <= 0 {
		timeout = m.timeout
	}
	if timeout <= 0 {
		return zero, false
	}

	timer := time.NewTimer(timeout)
	defer timer.Stop()

	select {
	case <-entry.ready:
		if !entry.hasValue {
			return zero, true
		}
		return m.clone(entry.value), true
	case <-timer.C:
		return zero, false
	}
}

func (m *Manager[T]) clone(value T) T {
	if m == nil || m.cloneValue == nil {
		return value
	}
	return m.cloneValue(value)
}
