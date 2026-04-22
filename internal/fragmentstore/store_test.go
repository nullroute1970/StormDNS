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
