// ==============================================================================
// StormDNS
// Author: nullroute1970
// Github: https://github.com/nullroute1970/StormDNS
// Year: 2026
// ==============================================================================

package fragmentstore

import (
	"sync"
	"sync/atomic"
	"time"
)

type Store[K comparable] struct {
	mu        sync.Mutex
	items     map[K]*entry
	completed map[K]time.Time
	lastPurge time.Time
	// conflicts counts incoming fragments that were dropped because their
	// totalFragments did not match an in-flight assembly for the same key.
	// Useful as an attack/buggy-peer signal; surfaced via ConflictCount().
	conflicts atomic.Uint64
}

type entry struct {
	createdAt      time.Time
	totalFragments uint8
	chunks         [256][]byte
	count          uint8
}

func New[K comparable](capacity int) *Store[K] {
	if capacity < 1 {
		capacity = 16
	}
	return &Store[K]{
		items:     make(map[K]*entry, capacity),
		completed: make(map[K]time.Time, capacity),
	}
}

func (s *Store[K]) Collect(key K, payload []byte, fragmentID uint8, totalFragments uint8, now time.Time, retention time.Duration) ([]byte, bool, bool) {
	if totalFragments <= 1 {
		if retention <= 0 {
			return append([]byte(nil), payload...), true, false
		}

		s.mu.Lock()
		defer s.mu.Unlock()

		if now.Sub(s.lastPurge) >= time.Second {
			s.purgeLocked(now, retention)
			s.lastPurge = now
		}
		if expiresAt, ok := s.completed[key]; ok && now.Before(expiresAt) {
			return nil, false, true
		}

		delete(s.items, key)
		s.completed[key] = now.Add(retention)
		return append([]byte(nil), payload...), true, false
	}

	if fragmentID >= totalFragments {
		return nil, false, false
	}

	s.mu.Lock()
	defer s.mu.Unlock()

	if now.Sub(s.lastPurge) >= time.Second {
		s.purgeLocked(now, retention)
		s.lastPurge = now
	}

	if expiresAt, ok := s.completed[key]; ok && now.Before(expiresAt) {
		return nil, false, true
	}

	current, ok := s.items[key]
	if !ok {
		current = &entry{
			createdAt:      now,
			totalFragments: totalFragments,
		}
		s.items[key] = current
	} else if current.totalFragments != totalFragments {
		// Conflicting totalFragments for the same key indicates either a
		// buggy peer or a flooding attack. Drop the in-flight assembly and
		// the new fragment rather than silently restarting reassembly,
		// which an attacker could exploit to keep memory occupied.
		delete(s.items, key)
		s.conflicts.Add(1)
		return nil, false, false
	}

	if current.chunks[fragmentID] == nil {
		current.count++
	}

	current.chunks[fragmentID] = append(current.chunks[fragmentID][:0], payload...)

	if current.count < totalFragments {
		return nil, false, false
	}

	totalSize := 0
	for idx := uint8(0); idx < totalFragments; idx++ {
		chunk := current.chunks[idx]
		if chunk == nil {
			return nil, false, false
		}
		totalSize += len(chunk)
	}

	assembled := make([]byte, 0, totalSize)
	for idx := uint8(0); idx < totalFragments; idx++ {
		assembled = append(assembled, current.chunks[idx]...)
	}

	delete(s.items, key)
	if retention > 0 {
		s.completed[key] = now.Add(retention)
	} else {
		delete(s.completed, key)
	}
	return assembled, true, false
}

func (s *Store[K]) Purge(now time.Time, retention time.Duration) {
	if s == nil {
		return
	}
	s.mu.Lock()
	s.purgeLocked(now, retention)
	s.mu.Unlock()
}

// ConflictCount returns the running count of fragments rejected due to a
// conflicting totalFragments value for an in-flight key. Safe to call from any
// goroutine.
func (s *Store[K]) ConflictCount() uint64 {
	if s == nil {
		return 0
	}
	return s.conflicts.Load()
}

func (s *Store[K]) Remove(key K) {
	if s == nil {
		return
	}
	s.mu.Lock()
	delete(s.items, key)
	delete(s.completed, key)
	s.mu.Unlock()
}

func (s *Store[K]) RemoveIf(match func(K) bool) {
	if s == nil || match == nil {
		return
	}

	s.mu.Lock()
	for key := range s.items {
		if match(key) {
			delete(s.items, key)
		}
	}
	for key := range s.completed {
		if match(key) {
			delete(s.completed, key)
		}
	}
	s.mu.Unlock()
}

func (s *Store[K]) purgeLocked(now time.Time, retention time.Duration) {
	if retention <= 0 {
		for key := range s.items {
			delete(s.items, key)
		}
		for key := range s.completed {
			delete(s.completed, key)
		}
		return
	}

	deadline := now.Add(-retention)
	for key, current := range s.items {
		if current == nil || !current.createdAt.After(deadline) {
			delete(s.items, key)
		}
	}
	for key, expiresAt := range s.completed {
		if !now.Before(expiresAt) {
			delete(s.completed, key)
		}
	}
}
