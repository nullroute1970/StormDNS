package fragmentstore

import (
	"testing"
	"time"
)

func TestCollectSingleFragmentMarksCompletedWithinRetention(t *testing.T) {
	store := New[string](4)
	now := time.Unix(1700000000, 0)

	assembled, ready, completed := store.Collect("req", []byte("hello"), 0, 1, now, 5*time.Minute)
	if !ready || completed {
		t.Fatalf("expected first single-fragment collect to complete once, ready=%v completed=%v", ready, completed)
	}
	if string(assembled) != "hello" {
		t.Fatalf("unexpected assembled payload: %q", string(assembled))
	}

	assembled, ready, completed = store.Collect("req", []byte("hello"), 0, 1, now.Add(time.Second), 5*time.Minute)
	if ready || !completed || assembled != nil {
		t.Fatalf("expected duplicate single-fragment collect to be completed-only, ready=%v completed=%v payload=%v", ready, completed, assembled)
	}
}

func TestRemoveIfClearsItemsAndCompletedEntries(t *testing.T) {
	store := New[int](4)
	now := time.Unix(1700000000, 0)

	if _, ready, _ := store.Collect(1, []byte("a"), 0, 2, now, 5*time.Minute); ready {
		t.Fatal("expected first fragment to stay incomplete")
	}
	if _, ready, completed := store.Collect(2, []byte("b"), 0, 1, now, 5*time.Minute); !ready || completed {
		t.Fatal("expected single fragment key to complete")
	}

	store.RemoveIf(func(key int) bool { return key == 1 || key == 2 })

	if _, ready, completed := store.Collect(1, []byte("c"), 1, 2, now.Add(time.Second), 5*time.Minute); ready || completed {
		t.Fatalf("expected removed incomplete key to behave as empty state, ready=%v completed=%v", ready, completed)
	}
	if payload, ready, completed := store.Collect(2, []byte("d"), 0, 1, now.Add(time.Second), 5*time.Minute); !ready || completed || string(payload) != "d" {
		t.Fatalf("expected removed completed key to accept new data, ready=%v completed=%v payload=%q", ready, completed, string(payload))
	}
}

func TestCollectRejectsConflictingTotalFragments(t *testing.T) {
	store := New[int](4)
	now := time.Unix(1700000000, 0)

	// Establish in-flight reassembly with totalFragments=4.
	if _, ready, completed := store.Collect(1, []byte("a"), 0, 4, now, 5*time.Minute); ready || completed {
		t.Fatalf("expected first fragment to stay incomplete, ready=%v completed=%v", ready, completed)
	}

	// A fragment for the same key with a different totalFragments is either
	// a buggy peer or a flooding attack. The store must drop the in-flight
	// assembly and return not-ready/not-completed instead of silently
	// restarting reassembly.
	if payload, ready, completed := store.Collect(1, []byte("b"), 0, 8, now.Add(time.Millisecond), 5*time.Minute); ready || completed || payload != nil {
		t.Fatalf("expected conflicting totalFragments to be dropped, payload=%v ready=%v completed=%v", payload, ready, completed)
	}

	// After the conflict, a fresh assembly for the same key should be able
	// to start and complete normally.
	if _, ready, _ := store.Collect(1, []byte("a"), 0, 2, now.Add(2*time.Millisecond), 5*time.Minute); ready {
		t.Fatal("expected fresh fragment to stay incomplete")
	}
	payload, ready, completed := store.Collect(1, []byte("b"), 1, 2, now.Add(3*time.Millisecond), 5*time.Minute)
	if !ready || completed || string(payload) != "ab" {
		t.Fatalf("expected fresh assembly to complete, payload=%q ready=%v completed=%v", payload, ready, completed)
	}
}
