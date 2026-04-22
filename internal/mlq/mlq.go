// ==============================================================================
// StormDNS
// Author: nullroute1970
// Github: https://github.com/nullroute1970/StormDNS
// Year: 2026
// ==============================================================================

package mlq

import (
	"math/bits"
	"sync"
	"sync/atomic"
)

// PriorityQueue represents a single level of priority in the MLQ.
type PriorityQueue[T any] struct {
	Items []T
}

// MultiLevelQueue is a high-performance, thread-safe, multi-priority queue.
// It uses a bitmask for O(1) priority selection and hardware acceleration.
type MultiLevelQueue[T any] struct {
	mu sync.RWMutex

	queues  [6]PriorityQueue[T]
	bitmask uint16 // Bit i is 1 if queues[i] is not empty
	fastSize atomic.Int32

	// Global census for O(1) existence and duplicate prevention across all levels
	census map[uint64]T
}

const compactThreshold = 1024

// New creates a new MultiLevelQueue with an initial census capacity.
func New[T any](initialCapacity int) *MultiLevelQueue[T] {
	m := &MultiLevelQueue[T]{
		census: make(map[uint64]T, initialCapacity),
	}
	for i := 0; i < 6; i++ {
		m.queues[i].Items = make([]T, 0, 16)
	}
	return m
}

// Push adds an item to the queue at the specified priority if the key is unique.
func (m *MultiLevelQueue[T]) Push(priority int, key uint64, item T) bool {
	m.mu.Lock()
	defer m.mu.Unlock()

	// 1. Duplicate check (O(1))
	if _, exists := m.census[key]; exists {
		return false
	}

	if priority < 0 || priority >= 6 {
		priority = 3 // Default
	}

	// 2. Add to queue
	q := &m.queues[priority]
	q.Items = append(q.Items, item)

	// 3. Update census and bitmask
	m.census[key] = item
	m.bitmask |= (1 << uint(priority))
	m.fastSize.Add(1)

	return true
}

// Pop retrieves the highest priority item from the queue.
func (m *MultiLevelQueue[T]) Pop(keyExtractor func(T) uint64) (T, int, bool) {
	m.mu.Lock()
	defer m.mu.Unlock()

	return m.popLocked(keyExtractor)
}

// Peek returns the highest-priority queued item without removing it.
func (m *MultiLevelQueue[T]) Peek() (T, int, bool) {
	m.mu.RLock()
	defer m.mu.RUnlock()

	var zero T
	if m.bitmask == 0 {
		return zero, 0, false
	}

	tempMask := m.bitmask
	for tempMask != 0 {
		priority := bits.TrailingZeros16(tempMask)
		q := &m.queues[priority]
		if len(q.Items) > 0 {
			return q.Items[0], priority, true
		}
		tempMask &= ^(1 << uint(priority))
	}

	return zero, 0, false
}

func (m *MultiLevelQueue[T]) popLocked(keyExtractor func(T) uint64) (T, int, bool) {
	var zero T
	for m.bitmask != 0 {
		// Optimized: Use hardware instruction to find highest priority (trailing zeros)
		priority := bits.TrailingZeros16(m.bitmask)

		q := &m.queues[priority]
		if len(q.Items) == 0 {
			m.bitmask &= ^(1 << uint(priority))
			continue
		}

		item := q.Items[0]

		// Memory safety: Clear the pointer from the slice to avoid leaks if T is a pointer
		q.Items[0] = zero
		q.Items = q.Items[1:]
		maybeCompactQueue(q)

		// Update census and bitmask
		if keyExtractor != nil {
			delete(m.census, keyExtractor(item))
		}
		m.fastSize.Add(-1)

		if len(q.Items) == 0 {
			m.bitmask &= ^(1 << uint(priority))
		}

		return item, priority, true
	}

	return zero, 0, false
}

func maybeCompactQueue[T any](q *PriorityQueue[T]) {
	if q == nil {
		return
	}
	if cap(q.Items) <= compactThreshold || len(q.Items) >= cap(q.Items)/4 {
		return
	}
	compacted := make([]T, len(q.Items))
	copy(compacted, q.Items)
	q.Items = compacted
}

// Get checks if an item exists in the queue using its tracking key.
func (m *MultiLevelQueue[T]) Get(key uint64) (T, bool) {
	m.mu.RLock()
	defer m.mu.RUnlock()

	item, exists := m.census[key]
	return item, exists
}

// RemoveByKey removes a specific item if it is still queued.
// It returns the removed item and true on success.
func (m *MultiLevelQueue[T]) RemoveByKey(key uint64, keyExtractor func(T) uint64) (T, bool) {
	m.mu.Lock()
	defer m.mu.Unlock()

	var zero T
	if m.bitmask == 0 {
		return zero, false
	}

	if _, exists := m.census[key]; !exists {
		return zero, false
	}

	tempMask := m.bitmask
	for tempMask != 0 {
		priority := bits.TrailingZeros16(tempMask)
		q := &m.queues[priority]

		for i, item := range q.Items {
			if keyExtractor != nil && keyExtractor(item) != key {
				continue
			}

			q.Items[i] = zero
			copy(q.Items[i:], q.Items[i+1:])
			last := len(q.Items) - 1
			q.Items[last] = zero
			q.Items = q.Items[:last]
			maybeCompactQueue(q)

			delete(m.census, key)
			m.fastSize.Add(-1)
			if len(q.Items) == 0 {
				m.bitmask &= ^(1 << uint(priority))
			}
			return item, true
		}

		tempMask &= ^(1 << uint(priority))
	}

	return zero, false
}

// Count returns the number of items in a specific priority queue.
func (m *MultiLevelQueue[T]) Count(priority int) int {
	m.mu.RLock()
	defer m.mu.RUnlock()

	if priority < 0 || priority >= 6 {
		return 0
	}
	return len(m.queues[priority].Items)
}

// Size returns the total number of items in all queues.
func (m *MultiLevelQueue[T]) Size() int {
	m.mu.RLock()
	defer m.mu.RUnlock()

	return len(m.census)
}

// FastSize returns the exact queued item count using an atomic fast-path.
func (m *MultiLevelQueue[T]) FastSize() int {
	if m == nil {
		return 0
	}
	return int(m.fastSize.Load())
}

// Clear empties all queues and reset the bitmask.
// If a callback is provided, it is invoked for each item before clearing.
func (m *MultiLevelQueue[T]) Clear(callback func(T)) {
	m.mu.Lock()
	defer m.mu.Unlock()

	for i := range m.queues {
		if callback != nil {
			for _, item := range m.queues[i].Items {
				callback(item)
			}
		}
		clear(m.queues[i].Items)
		m.queues[i].Items = m.queues[i].Items[:0]
	}
	clear(m.census)
	m.bitmask = 0
	m.fastSize.Store(0)
}

// HighestPriority returns the highest priority level currently containing items, or -1 if empty.
// Lower digits correspond to higher priority levels.
func (m *MultiLevelQueue[T]) HighestPriority() int {
	m.mu.RLock()
	defer m.mu.RUnlock()
	if m.bitmask == 0 {
		return -1
	}
	return bits.TrailingZeros16(m.bitmask)
}

// PopIf retrieves the highest priority item IF and only IF it matches the given predicate condition.
func (m *MultiLevelQueue[T]) PopIf(priority int, predicate func(T) bool, keyExtractor func(T) uint64) (T, bool) {
	m.mu.Lock()
	defer m.mu.Unlock()

	var zero T
	if m.bitmask == 0 || priority < 0 || priority >= 6 {
		return zero, false
	}
	if (m.bitmask & (1 << uint(priority))) == 0 {
		return zero, false
	}

	q := &m.queues[priority]
	if len(q.Items) == 0 {
		m.bitmask &= ^(1 << uint(priority))
		return zero, false
	}

	item := q.Items[0]
	if predicate != nil && !predicate(item) {
		return zero, false
	}

	// Allowed to pop!
	q.Items[0] = zero // Memory safety
	q.Items = q.Items[1:]
	maybeCompactQueue(q)

	if keyExtractor != nil {
		delete(m.census, keyExtractor(item))
	}
	m.fastSize.Add(-1)
	if len(q.Items) == 0 {
		m.bitmask &= ^(1 << uint(priority))
	}
	return item, true
}

// PopAnyIf retrieves the highest priority item that matches the given predicate, regardless of its priority.
// To avoid scanning lower-priority elements (e.g. data packets when searching for control packets), use maxPriority.
func (m *MultiLevelQueue[T]) PopAnyIf(maxPriority int, predicate func(T) bool, keyExtractor func(T) uint64) (T, bool) {
	m.mu.Lock()
	defer m.mu.Unlock()

	var zero T
	if m.bitmask == 0 {
		return zero, false
	}

	// Iterate through all priorities from highest to lowest
	tempMask := m.bitmask
	for tempMask != 0 {
		priority := bits.TrailingZeros16(tempMask)
		if priority > maxPriority { // priority < 0 not possible
			break
		}
		q := &m.queues[priority]

		if len(q.Items) > 0 {
			// Search in this priority queue for an item matching the predicate
			for i, item := range q.Items {
				if predicate == nil || predicate(item) {
					// Found a match!
					q.Items[i] = zero // Memory safety

					// Remove from slice without append to avoid extra slice work.
					copy(q.Items[i:], q.Items[i+1:])
					last := len(q.Items) - 1
					q.Items[last] = zero
					q.Items = q.Items[:last]
					maybeCompactQueue(q)

					if keyExtractor != nil {
						delete(m.census, keyExtractor(item))
					}
					m.fastSize.Add(-1)
					if len(q.Items) == 0 {
						m.bitmask &= ^(1 << uint(priority))
					}
					return item, true
				}
			}
		}

		// Clear bit and check next priority
		tempMask &= ^(1 << uint(priority))
	}

	return zero, false
}
