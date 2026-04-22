package udpserver

import (
	"fmt"
	"testing"
	"time"
)

func TestThrottledLogStatePrunesExpiredKeys(t *testing.T) {
	state := &throttledLogState{}
	base := time.Unix(100, 0)
	interval := time.Second

	if !state.allow("a", base, interval) {
		t.Fatal("expected first log for a to be allowed")
	}
	if !state.allow("b", base, interval) {
		t.Fatal("expected first log for b to be allowed")
	}
	if got := len(state.last); got != 2 {
		t.Fatalf("expected 2 tracked keys, got %d", got)
	}

	later := base.Add(2 * interval)
	if !state.allow("fresh", later, interval) {
		t.Fatal("expected fresh key after interval to be allowed")
	}
	if got := len(state.last); got != 1 {
		t.Fatalf("expected expired keys to be pruned, got %d tracked keys", got)
	}
	if _, ok := state.last["fresh"]; !ok {
		t.Fatal("expected fresh key to remain tracked")
	}
}

func TestThrottledLogStateBoundsKeyGrowth(t *testing.T) {
	state := &throttledLogState{}
	base := time.Unix(200, 0)
	interval := time.Hour

	for i := 0; i < throttledLogHardCap+128; i++ {
		if !state.allow(fmt.Sprintf("key-%d", i), base.Add(time.Duration(i)*time.Millisecond), interval) {
			t.Fatalf("expected unique key %d to be allowed", i)
		}
	}

	if got := len(state.last); got > throttledLogHardCap {
		t.Fatalf("expected throttled log map to stay bounded, got %d > %d", got, throttledLogHardCap)
	}
}
