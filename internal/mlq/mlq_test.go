package mlq

import "testing"

type testItem struct {
	key   uint64
	value string
}

func testKey(item *testItem) uint64 {
	if item == nil {
		return 0
	}
	return item.key
}

func TestMLQPushPopRespectsPriorityAndFIFO(t *testing.T) {
	q := New[*testItem](8)

	if !q.Push(3, 1, &testItem{key: 1, value: "p3-a"}) {
		t.Fatal("push p3-a failed")
	}
	if !q.Push(1, 2, &testItem{key: 2, value: "p1-a"}) {
		t.Fatal("push p1-a failed")
	}
	if !q.Push(1, 3, &testItem{key: 3, value: "p1-b"}) {
		t.Fatal("push p1-b failed")
	}
	if !q.Push(0, 4, &testItem{key: 4, value: "p0-a"}) {
		t.Fatal("push p0-a failed")
	}

	item, prio, ok := q.Pop(testKey)
	if !ok || prio != 0 || item.value != "p0-a" {
		t.Fatalf("unexpected first pop: ok=%v prio=%d value=%v", ok, prio, item)
	}

	item, prio, ok = q.Pop(testKey)
	if !ok || prio != 1 || item.value != "p1-a" {
		t.Fatalf("unexpected second pop: ok=%v prio=%d value=%v", ok, prio, item)
	}

	item, prio, ok = q.Pop(testKey)
	if !ok || prio != 1 || item.value != "p1-b" {
		t.Fatalf("unexpected third pop: ok=%v prio=%d value=%v", ok, prio, item)
	}

	item, prio, ok = q.Pop(testKey)
	if !ok || prio != 3 || item.value != "p3-a" {
		t.Fatalf("unexpected fourth pop: ok=%v prio=%d value=%v", ok, prio, item)
	}
}

func TestMLQRejectsDuplicateKeys(t *testing.T) {
	q := New[*testItem](4)

	if !q.Push(2, 10, &testItem{key: 10, value: "first"}) {
		t.Fatal("first push failed")
	}
	if q.Push(2, 10, &testItem{key: 10, value: "dup"}) {
		t.Fatal("duplicate push unexpectedly succeeded")
	}

	if q.Size() != 1 {
		t.Fatalf("unexpected size after duplicate push: %d", q.Size())
	}
}

func TestMLQPopIfOnlyConsumesMatchingHead(t *testing.T) {
	q := New[*testItem](4)

	q.Push(1, 1, &testItem{key: 1, value: "head"})
	q.Push(1, 2, &testItem{key: 2, value: "next"})

	if _, ok := q.PopIf(1, func(item *testItem) bool {
		return item.value == "nope"
	}, testKey); ok {
		t.Fatal("PopIf unexpectedly popped a non-matching head item")
	}

	item, ok := q.PopIf(1, func(item *testItem) bool {
		return item.value == "head"
	}, testKey)
	if !ok || item.value != "head" {
		t.Fatalf("unexpected PopIf result: ok=%v value=%v", ok, item)
	}

	item2, _, ok := q.Pop(testKey)
	if !ok || item2.value != "next" {
		t.Fatalf("unexpected remaining item after PopIf: ok=%v value=%v", ok, item2)
	}
}

func TestMLQPopAnyIfFindsHighestPriorityMatch(t *testing.T) {
	q := New[*testItem](8)

	q.Push(0, 1, &testItem{key: 1, value: "p0-nomatch"})
	q.Push(1, 2, &testItem{key: 2, value: "p1-match"})
	q.Push(2, 3, &testItem{key: 3, value: "p2-match"})

	item, ok := q.PopAnyIf(5, func(item *testItem) bool {
		return item.value == "p1-match" || item.value == "p2-match"
	}, testKey)
	if !ok || item.value != "p1-match" {
		t.Fatalf("unexpected PopAnyIf result: ok=%v value=%v", ok, item)
	}

	if q.Size() != 2 {
		t.Fatalf("unexpected size after PopAnyIf: %d", q.Size())
	}
}

func TestMLQClearInvokesCallbackAndResetsState(t *testing.T) {
	q := New[*testItem](4)

	q.Push(0, 1, &testItem{key: 1, value: "a"})
	q.Push(2, 2, &testItem{key: 2, value: "b"})

	var seen []string
	q.Clear(func(item *testItem) {
		seen = append(seen, item.value)
	})

	if len(seen) != 2 {
		t.Fatalf("unexpected callback count: %d", len(seen))
	}
	if q.Size() != 0 {
		t.Fatalf("queue not empty after clear: %d", q.Size())
	}
	if got := q.HighestPriority(); got != -1 {
		t.Fatalf("unexpected highest priority after clear: %d", got)
	}

	if _, _, ok := q.Pop(testKey); ok {
		t.Fatal("pop unexpectedly succeeded after clear")
	}
}

func TestMLQPeekReturnsHeadWithoutRemoving(t *testing.T) {
	q := New[*testItem](4)

	q.Push(2, 1, &testItem{key: 1, value: "later"})
	q.Push(1, 2, &testItem{key: 2, value: "first"})

	item, prio, ok := q.Peek()
	if !ok || prio != 1 || item.value != "first" {
		t.Fatalf("unexpected Peek result: ok=%v prio=%d value=%v", ok, prio, item)
	}

	if q.Size() != 2 {
		t.Fatalf("peek should not remove item, size=%d", q.Size())
	}

	item, prio, ok = q.Pop(testKey)
	if !ok || prio != 1 || item.value != "first" {
		t.Fatalf("unexpected pop after peek: ok=%v prio=%d value=%v", ok, prio, item)
	}
}

func TestMLQRemoveByKeyRemovesQueuedItem(t *testing.T) {
	q := New[*testItem](8)

	q.Push(4, 10, &testItem{key: 10, value: "data"})
	q.Push(2, 20, &testItem{key: 20, value: "other"})

	item, ok := q.RemoveByKey(10, testKey)
	if !ok || item == nil || item.value != "data" {
		t.Fatalf("unexpected RemoveByKey result: ok=%v item=%v", ok, item)
	}

	if q.Size() != 1 {
		t.Fatalf("unexpected size after RemoveByKey: %d", q.Size())
	}

	if _, exists := q.Get(10); exists {
		t.Fatal("removed key still present in census")
	}
}

func TestMLQCompactsAfterHeavyPopShrink(t *testing.T) {
	q := New[*testItem](2048)

	for i := 0; i < 2048; i++ {
		if !q.Push(1, uint64(i+1), &testItem{key: uint64(i + 1), value: "x"}) {
			t.Fatalf("push failed at %d", i)
		}
	}

	initialCap := cap(q.queues[1].Items)
	if initialCap <= compactThreshold {
		t.Fatalf("expected initial capacity above compact threshold, got %d", initialCap)
	}

	for i := 0; i < 1800; i++ {
		if _, _, ok := q.Pop(testKey); !ok {
			t.Fatalf("unexpected pop failure at %d", i)
		}
	}

	shrunkCap := cap(q.queues[1].Items)
	if shrunkCap >= initialCap {
		t.Fatalf("expected queue capacity to shrink, initial=%d current=%d", initialCap, shrunkCap)
	}

	if q.Size() != 248 {
		t.Fatalf("expected 248 items to remain, got %d", q.Size())
	}
}

func TestMLQFastSizeTracksAllMutations(t *testing.T) {
	q := New[*testItem](8)
	if got := q.FastSize(); got != 0 {
		t.Fatalf("expected initial FastSize=0, got %d", got)
	}

	if !q.Push(1, 1, &testItem{key: 1, value: "a"}) {
		t.Fatal("push a failed")
	}
	if !q.Push(2, 2, &testItem{key: 2, value: "b"}) {
		t.Fatal("push b failed")
	}
	if got := q.FastSize(); got != 2 {
		t.Fatalf("expected FastSize=2 after pushes, got %d", got)
	}

	if _, ok := q.RemoveByKey(2, testKey); !ok {
		t.Fatal("expected RemoveByKey to succeed")
	}
	if got := q.FastSize(); got != 1 {
		t.Fatalf("expected FastSize=1 after RemoveByKey, got %d", got)
	}

	if _, ok := q.PopIf(1, func(item *testItem) bool {
		return item != nil && item.key == 1
	}, testKey); !ok {
		t.Fatal("expected PopIf to succeed")
	}
	if got := q.FastSize(); got != 0 {
		t.Fatalf("expected FastSize=0 after PopIf, got %d", got)
	}

	if !q.Push(0, 3, &testItem{key: 3, value: "c"}) {
		t.Fatal("push c failed")
	}
	if !q.Push(1, 4, &testItem{key: 4, value: "d"}) {
		t.Fatal("push d failed")
	}
	if got := q.FastSize(); got != 2 {
		t.Fatalf("expected FastSize=2 before PopAnyIf, got %d", got)
	}

	if _, ok := q.PopAnyIf(5, func(item *testItem) bool {
		return item != nil && item.key == 4
	}, testKey); !ok {
		t.Fatal("expected PopAnyIf to succeed")
	}
	if got := q.FastSize(); got != 1 {
		t.Fatalf("expected FastSize=1 after PopAnyIf, got %d", got)
	}

	q.Clear(nil)
	if got := q.FastSize(); got != 0 {
		t.Fatalf("expected FastSize=0 after Clear, got %d", got)
	}
}
