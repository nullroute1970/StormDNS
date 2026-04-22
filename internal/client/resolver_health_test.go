package client

import (
	"context"
	"net"
	"sync/atomic"
	"testing"
	"time"

	"stormdns-go/internal/config"
)

func waitForResolverHealthCondition(t *testing.T, timeout time.Duration, cond func() bool, message string) {
	t.Helper()

	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		if cond() {
			return
		}
		time.Sleep(10 * time.Millisecond)
	}

	if cond() {
		return
	}
	t.Fatal(message)
}

func TestResolverHealthAutoDisablesTimeoutOnlyConnection(t *testing.T) {
	c := buildTestClientWithResolvers(config.ClientConfig{
		AutoDisableTimeoutServers:       true,
		AutoDisableTimeoutWindowSeconds: 10.0,
		AutoDisableMinObservations:      3,
		AutoDisableCheckIntervalSeconds: 1.0,
	}, "a", "b", "c", "d")
	c.initResolverRecheckMeta()

	base := time.Date(2026, 3, 25, 12, 0, 0, 0, time.UTC)
	current := base
	c.nowFn = func() time.Time { return current }

	c.recordResolverHealthEvent("a", false, current)
	current = base.Add(5 * time.Second)
	c.recordResolverHealthEvent("a", false, current)
	current = base.Add(10 * time.Second)
	c.recordResolverHealthEvent("a", false, current)

	c.runResolverAutoDisable(current)

	conn, ok := c.GetConnectionByKey("a")
	if !ok {
		t.Fatal("expected disabled connection to still exist")
	}
	if conn.IsValid {
		t.Fatal("expected timeout-only resolver to be disabled")
	}
	if c.balancer.ValidCount() != 3 {
		t.Fatalf("unexpected valid count after disable: got=%d want=3", c.balancer.ValidCount())
	}
	if !c.isRuntimeDisabledResolver("a") {
		t.Fatal("expected disabled resolver to be tracked for runtime recheck")
	}
}

func TestResolverHealthRecheckReactivatesConnection(t *testing.T) {
	c := buildTestClientWithResolvers(config.ClientConfig{
		RecheckInactiveServersEnabled:  true,
		RecheckInactiveIntervalSeconds: 60.0,
		RecheckServerIntervalSeconds:   3.0,
		RecheckBatchSize:               2,
	}, "a", "b")
	c.successMTUChecks = true
	c.syncedUploadMTU = 120
	c.syncedDownloadMTU = 180

	if !c.balancer.SetConnectionValidity("a", false) {
		t.Fatal("expected test connection a to become invalid")
	}

	if idx, ok := c.connectionsByKey["a"]; ok {
		c.connections[idx].UploadMTUBytes = 0
		c.connections[idx].DownloadMTUBytes = 0
	}

	c.initResolverRecheckMeta()
	c.recheckConnectionFn = func(conn *Connection) bool {
		return conn != nil && conn.Key == "a"
	}

	now := time.Date(2026, 3, 25, 12, 30, 0, 0, time.UTC)
	c.nowFn = func() time.Time { return now }

	c.resolverHealthMu.Lock()
	c.resolverRecheck["a"] = resolverRecheckState{
		FailCount: 2,
		NextAt:    now.Add(-time.Second),
	}
	c.runtimeDisabled["a"] = resolverDisabledState{
		DisabledAt:  now.Add(-time.Minute),
		NextRetryAt: now.Add(-time.Second),
		RetryCount:  2,
		Cause:       "timeout window",
	}
	c.resolverHealthMu.Unlock()

	c.runResolverRecheckBatch(context.Background(), now)

	waitForResolverHealthCondition(t, 500*time.Millisecond, func() bool {
		conn, ok := c.GetConnectionByKey("a")
		if !ok || conn.IsValid {
			return false
		}
		c.resolverHealthMu.Lock()
		defer c.resolverHealthMu.Unlock()
		state, disabled := c.runtimeDisabled["a"]
		meta := c.resolverRecheck["a"]
		return disabled && state.SuccessCount == 1 && !meta.InFlight && meta.NextAt.After(now)
	}, "expected first successful recheck to keep runtime-disabled resolver invalid")

	now = now.Add(3 * time.Second)
	c.nowFn = func() time.Time { return now }
	c.runResolverRecheckBatch(context.Background(), now)

	waitForResolverHealthCondition(t, 500*time.Millisecond, func() bool {
		conn, ok := c.GetConnectionByKey("a")
		return ok && conn.IsValid
	}, "expected recheck to reactivate resolver")

	conn, ok := c.GetConnectionByKey("a")
	if !ok {
		t.Fatal("expected reactivated resolver to still exist")
	}
	if conn.UploadMTUBytes != 120 || conn.DownloadMTUBytes != 180 {
		t.Fatalf("expected synced MTUs to be restored, got up=%d down=%d", conn.UploadMTUBytes, conn.DownloadMTUBytes)
	}
	if c.balancer.ValidCount() != 2 {
		t.Fatalf("unexpected valid count after recheck: got=%d want=%d", c.balancer.ValidCount(), 2)
	}
	if c.isRuntimeDisabledResolver("a") {
		t.Fatal("expected runtime disabled marker to be cleared after reactivation")
	}
}

func TestResolverHealthRecheckUsesSnapshotUpdateInsteadOfMutatingSharedConnectionPointer(t *testing.T) {
	c := buildTestClientWithResolvers(config.ClientConfig{
		RecheckInactiveServersEnabled:  true,
		RecheckInactiveIntervalSeconds: 60.0,
		RecheckServerIntervalSeconds:   3.0,
		RecheckBatchSize:               1,
	}, "a", "b")
	c.successMTUChecks = true
	c.syncedUploadMTU = 120
	c.syncedDownloadMTU = 180

	if !c.balancer.SetConnectionValidity("a", false) {
		t.Fatal("expected test connection a to become invalid")
	}

	if idx, ok := c.connectionsByKey["a"]; ok {
		c.connections[idx].UploadMTUBytes = 0
		c.connections[idx].UploadMTUChars = 0
		c.connections[idx].DownloadMTUBytes = 0
	}
	c.balancer.RefreshValidConnections()

	c.initResolverRecheckMeta()
	now := time.Date(2026, 3, 31, 8, 0, 0, 0, time.UTC)
	c.nowFn = func() time.Time { return now }

	c.resolverHealthMu.Lock()
	c.resolverRecheck["a"] = resolverRecheckState{
		FailCount: 1,
		NextAt:    now.Add(-time.Second),
	}
	c.runtimeDisabled["a"] = resolverDisabledState{
		DisabledAt:  now.Add(-time.Minute),
		NextRetryAt: now.Add(-time.Second),
		RetryCount:  1,
		Cause:       "timeout window",
	}
	c.resolverHealthMu.Unlock()

	c.recheckConnectionFn = func(conn *Connection) bool {
		if conn == nil {
			return false
		}
		conn.UploadMTUBytes = 33
		conn.UploadMTUChars = 44
		conn.DownloadMTUBytes = 55
		if idx, ok := c.connectionsByKey["a"]; ok {
			source := c.connections[idx]
			if source.UploadMTUBytes != 0 || source.UploadMTUChars != 0 || source.DownloadMTUBytes != 0 {
				t.Fatalf("expected shared connection source to remain untouched during probe, got up=%d chars=%d down=%d", source.UploadMTUBytes, source.UploadMTUChars, source.DownloadMTUBytes)
			}
		}
		return conn.Key == "a"
	}

	c.runResolverRecheckBatch(context.Background(), now)

	waitForResolverHealthCondition(t, 500*time.Millisecond, func() bool {
		conn, ok := c.GetConnectionByKey("a")
		if !ok || conn.IsValid {
			return false
		}
		c.resolverHealthMu.Lock()
		defer c.resolverHealthMu.Unlock()
		state, disabled := c.runtimeDisabled["a"]
		meta := c.resolverRecheck["a"]
		return disabled && state.SuccessCount == 1 && !meta.InFlight && meta.NextAt.After(now)
	}, "expected first successful recheck to keep runtime-disabled resolver invalid")

	now = now.Add(3 * time.Second)
	c.nowFn = func() time.Time { return now }
	c.runResolverRecheckBatch(context.Background(), now)

	waitForResolverHealthCondition(t, 500*time.Millisecond, func() bool {
		conn, ok := c.GetConnectionByKey("a")
		return ok && conn.IsValid
	}, "expected recheck to reactivate resolver")

	conn, ok := c.GetConnectionByKey("a")
	if !ok {
		t.Fatal("expected resolver a to exist after reactivation")
	}
	if conn.UploadMTUBytes != 120 || conn.UploadMTUChars != c.encodedCharsForPayload(120) || conn.DownloadMTUBytes != 180 {
		t.Fatalf("expected synced MTUs after recheck, got up=%d chars=%d down=%d", conn.UploadMTUBytes, conn.UploadMTUChars, conn.DownloadMTUBytes)
	}
}

func TestResolverHealthRecheckFailureSchedulesNextRetry(t *testing.T) {
	c := buildTestClientWithResolvers(config.ClientConfig{
		RecheckInactiveServersEnabled:  true,
		RecheckInactiveIntervalSeconds: 60.0,
		RecheckServerIntervalSeconds:   3.0,
		RecheckBatchSize:               2,
	}, "a", "b")
	c.successMTUChecks = true
	c.syncedUploadMTU = 120
	c.syncedDownloadMTU = 180

	if !c.balancer.SetConnectionValidity("a", false) {
		t.Fatal("expected test connection a to become invalid")
	}

	c.initResolverRecheckMeta()
	c.recheckConnectionFn = func(conn *Connection) bool {
		return false
	}

	now := time.Date(2026, 3, 30, 9, 0, 0, 0, time.UTC)
	c.nowFn = func() time.Time { return now }

	c.resolverHealthMu.Lock()
	c.resolverRecheck["a"] = resolverRecheckState{
		FailCount: 1,
		NextAt:    now.Add(-time.Second),
	}
	c.runtimeDisabled["a"] = resolverDisabledState{
		DisabledAt:  now.Add(-time.Minute),
		NextRetryAt: now.Add(-time.Second),
		RetryCount:  1,
		Cause:       "timeout window",
	}
	c.resolverHealthMu.Unlock()

	c.runResolverRecheckBatch(context.Background(), now)

	waitForResolverHealthCondition(t, 500*time.Millisecond, func() bool {
		c.resolverHealthMu.Lock()
		defer c.resolverHealthMu.Unlock()
		meta := c.resolverRecheck["a"]
		return meta.FailCount >= 2 && meta.NextAt.After(now)
	}, "expected failed recheck to schedule a future retry")

	conn, ok := c.GetConnectionByKey("a")
	if !ok {
		t.Fatal("expected resolver a to still exist")
	}
	if conn.IsValid {
		t.Fatal("expected failed recheck to keep resolver invalid")
	}
}

func TestResolverHealthRecheckBatchReturnsWhileSlowProbeRunsInBackground(t *testing.T) {
	c := buildTestClientWithResolvers(config.ClientConfig{
		RecheckInactiveServersEnabled:  true,
		RecheckInactiveIntervalSeconds: 60.0,
		RecheckServerIntervalSeconds:   3.0,
		RecheckBatchSize:               1,
	}, "a")
	c.successMTUChecks = true
	c.syncedUploadMTU = 120
	c.syncedDownloadMTU = 180

	if !c.balancer.SetConnectionValidity("a", false) {
		t.Fatal("expected resolver a to become invalid")
	}

	c.initResolverRecheckMeta()
	now := time.Date(2026, 3, 30, 9, 15, 0, 0, time.UTC)
	c.nowFn = func() time.Time { return now }

	c.resolverHealthMu.Lock()
	c.resolverRecheck["a"] = resolverRecheckState{NextAt: now.Add(-time.Second)}
	c.resolverHealthMu.Unlock()

	started := make(chan struct{}, 1)
	release := make(chan struct{})
	var calls atomic.Int32
	c.recheckConnectionFn = func(conn *Connection) bool {
		calls.Add(1)
		select {
		case started <- struct{}{}:
		default:
		}
		<-release
		return true
	}

	done := make(chan struct{})
	go func() {
		c.runResolverRecheckBatch(context.Background(), now)
		close(done)
	}()

	select {
	case <-started:
	case <-time.After(200 * time.Millisecond):
		t.Fatal("expected slow recheck probe to start")
	}

	select {
	case <-done:
	case <-time.After(200 * time.Millisecond):
		t.Fatal("expected merged implementation to return without waiting for slow probe completion")
	}

	if calls.Load() != 1 {
		t.Fatalf("expected exactly one in-flight probe call, got %d", calls.Load())
	}

	close(release)
}

func TestResolverHealthRecheckBatchStartsSecondDueResolverWithoutWaitingForFirst(t *testing.T) {
	c := buildTestClientWithResolvers(config.ClientConfig{
		RecheckInactiveServersEnabled:  true,
		RecheckInactiveIntervalSeconds: 60.0,
		RecheckServerIntervalSeconds:   3.0,
		RecheckBatchSize:               2,
	}, "a", "b")
	c.successMTUChecks = true
	c.syncedUploadMTU = 120
	c.syncedDownloadMTU = 180

	for _, key := range []string{"a", "b"} {
		if !c.balancer.SetConnectionValidity(key, false) {
			t.Fatalf("expected resolver %s to become invalid", key)
		}
	}

	c.initResolverRecheckMeta()
	now := time.Date(2026, 3, 30, 9, 20, 0, 0, time.UTC)
	c.nowFn = func() time.Time { return now }

	c.resolverHealthMu.Lock()
	c.resolverRecheck["a"] = resolverRecheckState{NextAt: now.Add(-time.Second)}
	c.resolverRecheck["b"] = resolverRecheckState{NextAt: now.Add(-time.Second)}
	c.resolverHealthMu.Unlock()

	firstStarted := make(chan struct{}, 1)
	releaseFirst := make(chan struct{})
	secondStarted := make(chan struct{}, 1)
	var startedA atomic.Int32
	var startedB atomic.Int32

	c.recheckConnectionFn = func(conn *Connection) bool {
		if conn == nil {
			return false
		}
		switch conn.Key {
		case "a":
			startedA.Add(1)
			select {
			case firstStarted <- struct{}{}:
			default:
			}
			<-releaseFirst
			return true
		case "b":
			startedB.Add(1)
			select {
			case secondStarted <- struct{}{}:
			default:
			}
			return true
		default:
			return false
		}
	}

	done := make(chan struct{})
	go func() {
		c.runResolverRecheckBatch(context.Background(), now)
		close(done)
	}()

	select {
	case <-firstStarted:
	case <-time.After(200 * time.Millisecond):
		t.Fatal("expected first due resolver to start recheck")
	}

	select {
	case <-secondStarted:
	case <-time.After(200 * time.Millisecond):
		t.Fatal("expected second due resolver to start without waiting for first probe to finish")
	}

	if startedA.Load() != 1 {
		t.Fatalf("expected first resolver to start once, got %d", startedA.Load())
	}
	if startedB.Load() != 1 {
		t.Fatalf("expected second resolver to start once, got %d", startedB.Load())
	}

	select {
	case <-done:
	case <-time.After(200 * time.Millisecond):
		t.Fatal("expected batch to return after launching background rechecks")
	}

	close(releaseFirst)
}

func TestResolverHealthRecheckBatchDoesNotLaunchSameResolverTwiceWhileInFlight(t *testing.T) {
	c := buildTestClientWithResolvers(config.ClientConfig{
		RecheckInactiveServersEnabled:  true,
		RecheckInactiveIntervalSeconds: 60.0,
		RecheckServerIntervalSeconds:   3.0,
		RecheckBatchSize:               1,
	}, "a")
	c.successMTUChecks = true
	c.syncedUploadMTU = 120
	c.syncedDownloadMTU = 180

	if !c.balancer.SetConnectionValidity("a", false) {
		t.Fatal("expected resolver a to become invalid")
	}

	c.initResolverRecheckMeta()
	now := time.Date(2026, 3, 30, 9, 25, 0, 0, time.UTC)
	c.nowFn = func() time.Time { return now }

	c.resolverHealthMu.Lock()
	c.resolverRecheck["a"] = resolverRecheckState{NextAt: now.Add(-time.Second)}
	c.runtimeDisabled["a"] = resolverDisabledState{
		DisabledAt:  now.Add(-time.Minute),
		NextRetryAt: now.Add(-time.Second),
		RetryCount:  1,
		Cause:       "timeout window",
	}
	c.resolverHealthMu.Unlock()

	started := make(chan struct{}, 1)
	release := make(chan struct{})
	var calls atomic.Int32
	c.recheckConnectionFn = func(conn *Connection) bool {
		calls.Add(1)
		select {
		case started <- struct{}{}:
		default:
		}
		<-release
		return false
	}

	c.runResolverRecheckBatch(context.Background(), now)

	select {
	case <-started:
	case <-time.After(200 * time.Millisecond):
		t.Fatal("expected first in-flight recheck to start")
	}

	c.runResolverRecheckBatch(context.Background(), now.Add(10*time.Millisecond))

	select {
	case <-started:
		t.Fatal("expected in-flight resolver to be skipped by subsequent batches")
	case <-time.After(100 * time.Millisecond):
	}

	if calls.Load() != 1 {
		t.Fatalf("expected only one in-flight probe call, got %d", calls.Load())
	}

	close(release)

	waitForResolverHealthCondition(t, 500*time.Millisecond, func() bool {
		c.resolverHealthMu.Lock()
		defer c.resolverHealthMu.Unlock()
		meta := c.resolverRecheck["a"]
		return !meta.InFlight && meta.FailCount >= 1 && meta.NextAt.After(now)
	}, "expected failed in-flight recheck to clear in-flight state and schedule retry")
}

func TestResolverHealthRecheckBatchHonorsGlobalInFlightLimitAcrossBatches(t *testing.T) {
	c := buildTestClientWithResolvers(config.ClientConfig{
		RecheckInactiveServersEnabled:  true,
		RecheckInactiveIntervalSeconds: 60.0,
		RecheckServerIntervalSeconds:   3.0,
		RecheckBatchSize:               1,
	}, "a", "b")
	c.successMTUChecks = true
	c.syncedUploadMTU = 120
	c.syncedDownloadMTU = 180

	for _, key := range []string{"a", "b"} {
		if !c.balancer.SetConnectionValidity(key, false) {
			t.Fatalf("expected resolver %s to become invalid", key)
		}
	}

	c.initResolverRecheckMeta()
	now := time.Date(2026, 3, 30, 9, 26, 0, 0, time.UTC)
	c.nowFn = func() time.Time { return now }

	c.resolverHealthMu.Lock()
	c.resolverRecheck["a"] = resolverRecheckState{NextAt: now.Add(-time.Second)}
	c.resolverRecheck["b"] = resolverRecheckState{NextAt: now.Add(-time.Second)}
	c.runtimeDisabled["a"] = resolverDisabledState{
		DisabledAt:  now.Add(-time.Minute),
		NextRetryAt: now.Add(-time.Second),
		RetryCount:  1,
		Cause:       "timeout window",
	}
	c.runtimeDisabled["b"] = resolverDisabledState{
		DisabledAt:  now.Add(-time.Minute),
		NextRetryAt: now.Add(-time.Second),
		RetryCount:  1,
		Cause:       "timeout window",
	}
	c.resolverHealthMu.Unlock()

	startedA := make(chan struct{}, 1)
	releaseA := make(chan struct{})
	var callsA atomic.Int32
	var callsB atomic.Int32
	c.recheckConnectionFn = func(conn *Connection) bool {
		if conn == nil {
			return false
		}
		switch conn.Key {
		case "a":
			callsA.Add(1)
			select {
			case startedA <- struct{}{}:
			default:
			}
			<-releaseA
			return false
		case "b":
			callsB.Add(1)
			return false
		default:
			return false
		}
	}

	c.runResolverRecheckBatch(context.Background(), now)

	select {
	case <-startedA:
	case <-time.After(200 * time.Millisecond):
		t.Fatal("expected first resolver recheck to start")
	}

	c.runResolverRecheckBatch(context.Background(), now.Add(10*time.Millisecond))
	time.Sleep(100 * time.Millisecond)

	if callsA.Load() != 1 {
		t.Fatalf("expected resolver a to start once, got %d", callsA.Load())
	}
	if callsB.Load() != 0 {
		t.Fatalf("expected resolver b to wait for a free global recheck slot, got %d launches", callsB.Load())
	}

	close(releaseA)

	waitForResolverHealthCondition(t, 500*time.Millisecond, func() bool {
		c.resolverHealthMu.Lock()
		defer c.resolverHealthMu.Unlock()
		return !c.resolverRecheck["a"].InFlight
	}, "expected first recheck to finish and clear in-flight state")
}

func TestResolverHealthSuccessfulRecheckClearsInFlightWhenResolverBecomesValidElsewhere(t *testing.T) {
	c := buildTestClientWithResolvers(config.ClientConfig{
		RecheckInactiveServersEnabled:  true,
		RecheckInactiveIntervalSeconds: 60.0,
		RecheckServerIntervalSeconds:   3.0,
		RecheckBatchSize:               1,
	}, "a")
	c.successMTUChecks = true
	c.syncedUploadMTU = 120
	c.syncedDownloadMTU = 180

	if !c.balancer.SetConnectionValidity("a", false) {
		t.Fatal("expected resolver a to become invalid")
	}

	c.initResolverRecheckMeta()
	now := time.Date(2026, 3, 30, 9, 27, 0, 0, time.UTC)
	c.nowFn = func() time.Time { return now }

	c.resolverHealthMu.Lock()
	c.resolverRecheck["a"] = resolverRecheckState{
		FailCount: 1,
		NextAt:    now.Add(-time.Second),
	}
	c.runtimeDisabled["a"] = resolverDisabledState{
		DisabledAt:  now.Add(-time.Minute),
		NextRetryAt: now.Add(-time.Second),
		RetryCount:  1,
		Cause:       "timeout window",
	}
	c.resolverHealthMu.Unlock()

	started := make(chan struct{}, 1)
	release := make(chan struct{})
	c.recheckConnectionFn = func(conn *Connection) bool {
		select {
		case started <- struct{}{}:
		default:
		}
		<-release
		return true
	}

	c.runResolverRecheckBatch(context.Background(), now)

	select {
	case <-started:
	case <-time.After(200 * time.Millisecond):
		t.Fatal("expected in-flight successful recheck to start")
	}

	if !c.balancer.SetConnectionValidity("a", true) {
		t.Fatal("expected resolver a to become valid through an external path")
	}

	close(release)

	waitForResolverHealthCondition(t, 500*time.Millisecond, func() bool {
		c.resolverHealthMu.Lock()
		defer c.resolverHealthMu.Unlock()
		meta := c.resolverRecheck["a"]
		return !meta.InFlight
	}, "expected successful recheck fallback path to clear in-flight marker")
}

func TestResolverHealthRecheckBatchHonorsLimit(t *testing.T) {
	c := buildTestClientWithResolvers(config.ClientConfig{
		RecheckInactiveServersEnabled:  true,
		RecheckInactiveIntervalSeconds: 60.0,
		RecheckServerIntervalSeconds:   3.0,
		RecheckBatchSize:               1,
	}, "a", "b", "c")
	c.successMTUChecks = true
	c.syncedUploadMTU = 120
	c.syncedDownloadMTU = 180

	for _, key := range []string{"a", "b", "c"} {
		if !c.balancer.SetConnectionValidity(key, false) {
			t.Fatalf("expected resolver %s to become invalid", key)
		}
	}

	c.initResolverRecheckMeta()
	c.recheckConnectionFn = func(conn *Connection) bool {
		return conn != nil
	}

	now := time.Date(2026, 3, 30, 9, 5, 0, 0, time.UTC)
	c.nowFn = func() time.Time { return now }

	c.resolverHealthMu.Lock()
	for _, key := range []string{"a", "b", "c"} {
		c.resolverRecheck[key] = resolverRecheckState{
			FailCount: 0,
			NextAt:    now.Add(-time.Second),
		}
	}
	c.resolverHealthMu.Unlock()

	c.runResolverRecheckBatch(context.Background(), now)

	waitForResolverHealthCondition(t, 500*time.Millisecond, func() bool {
		validCount := 0
		for _, key := range []string{"a", "b", "c"} {
			conn, ok := c.GetConnectionByKey(key)
			if ok && conn.IsValid {
				validCount++
			}
		}
		return validCount == 1
	}, "expected only one resolver to be rechecked due to batch limit")

	validCount := 0
	for _, key := range []string{"a", "b", "c"} {
		conn, ok := c.GetConnectionByKey(key)
		if ok && conn.IsValid {
			validCount++
		}
	}
	if validCount != 1 {
		t.Fatalf("expected exactly one resolver to reactivate, got %d", validCount)
	}
}

func TestResolverHealthRecheckBatchSkipsNotYetDueResolvers(t *testing.T) {
	c := buildTestClientWithResolvers(config.ClientConfig{
		RecheckInactiveServersEnabled:  true,
		RecheckInactiveIntervalSeconds: 60.0,
		RecheckServerIntervalSeconds:   3.0,
		RecheckBatchSize:               2,
	}, "a", "b")
	c.successMTUChecks = true
	c.syncedUploadMTU = 120
	c.syncedDownloadMTU = 180

	if !c.balancer.SetConnectionValidity("a", false) {
		t.Fatal("expected resolver a to become invalid")
	}
	if !c.balancer.SetConnectionValidity("b", false) {
		t.Fatal("expected resolver b to become invalid")
	}

	c.initResolverRecheckMeta()

	seen := make(map[string]int)
	c.recheckConnectionFn = func(conn *Connection) bool {
		if conn != nil {
			seen[conn.Key]++
		}
		return conn != nil && conn.Key == "a"
	}

	now := time.Date(2026, 3, 30, 9, 10, 0, 0, time.UTC)
	c.nowFn = func() time.Time { return now }

	c.resolverHealthMu.Lock()
	c.resolverRecheck["a"] = resolverRecheckState{NextAt: now.Add(-time.Second)}
	c.resolverRecheck["b"] = resolverRecheckState{NextAt: now.Add(time.Minute)}
	c.resolverHealthMu.Unlock()

	c.runResolverRecheckBatch(context.Background(), now)

	waitForResolverHealthCondition(t, 500*time.Millisecond, func() bool {
		conn, ok := c.GetConnectionByKey("a")
		return ok && conn.IsValid
	}, "expected due resolver a to reactivate")

	if seen["a"] != 1 {
		t.Fatalf("expected resolver a to be rechecked once, got %d", seen["a"])
	}
	if seen["b"] != 0 {
		t.Fatalf("expected resolver b to be skipped while not due, got %d checks", seen["b"])
	}
}

func TestDisableResolverClearsPreferredStreamResolverReferences(t *testing.T) {
	c := buildTestClientWithResolvers(config.ClientConfig{
		AutoDisableTimeoutServers:       true,
		AutoDisableTimeoutWindowSeconds: 10.0,
		AutoDisableMinObservations:      3,
	}, "a", "b", "c", "d")
	c.initResolverRecheckMeta()

	streamA := testStream(21)
	streamA.PreferredServerKey = "a"
	streamA.ResolverResendStreak = 3
	c.active_streams[streamA.StreamID] = streamA

	streamB := testStream(22)
	streamB.PreferredServerKey = "b"
	streamB.ResolverResendStreak = 2
	c.active_streams[streamB.StreamID] = streamB

	if !c.disableResolverConnection("a", "test disable") {
		t.Fatal("expected resolver a to be disabled")
	}

	if streamA.PreferredServerKey != "" {
		t.Fatalf("expected preferred resolver for streamA to be cleared, got=%q", streamA.PreferredServerKey)
	}
	if streamA.ResolverResendStreak != 0 {
		t.Fatalf("expected resend streak for streamA to be reset, got=%d", streamA.ResolverResendStreak)
	}
	if streamB.PreferredServerKey != "b" {
		t.Fatalf("expected unrelated stream preferred resolver to stay intact, got=%q", streamB.PreferredServerKey)
	}
}

func TestResetRuntimeBindingsPreservesResolverHealthState(t *testing.T) {
	c := buildTestClientWithResolvers(config.ClientConfig{
		RecheckInactiveServersEnabled:  true,
		AutoDisableTimeoutServers:      true,
		RecheckInactiveIntervalSeconds: 60.0,
		RecheckServerIntervalSeconds:   3.0,
	}, "a", "b", "c", "d")
	c.successMTUChecks = true
	c.syncedUploadMTU = 120
	c.syncedDownloadMTU = 180
	c.initResolverRecheckMeta()

	now := time.Date(2026, 3, 25, 13, 0, 0, 0, time.UTC)
	c.nowFn = func() time.Time { return now }

	stream := testStream(31)
	stream.PreferredServerKey = "a"
	c.active_streams[stream.StreamID] = stream

	if !c.disableResolverConnection("a", "test disable") {
		t.Fatal("expected resolver a to be disabled")
	}

	if !c.isRuntimeDisabledResolver("a") {
		t.Fatal("expected runtime disabled state before reset")
	}

	c.resetRuntimeBindings(true)

	if !c.isRuntimeDisabledResolver("a") {
		t.Fatal("expected runtime disabled resolver state to survive runtime reset")
	}

	conn, ok := c.GetConnectionByKey("a")
	if !ok {
		t.Fatal("expected resolver a to still exist after reset")
	}
	if conn.IsValid {
		t.Fatal("expected resolver a to remain invalid after reset")
	}

	if len(c.active_streams) != 0 {
		t.Fatalf("expected streams to be cleared by runtime reset, got=%d", len(c.active_streams))
	}
}

func TestLateResolverSuccessRetractsPriorTimeoutEvent(t *testing.T) {
	c := buildTestClientWithResolvers(config.ClientConfig{
		AutoDisableTimeoutServers:       true,
		AutoDisableTimeoutWindowSeconds: 3.0,
		AutoDisableCheckIntervalSeconds: 3.0,
		TunnelPacketTimeoutSec:          10.0,
	}, "a", "b", "c", "d")
	c.initResolverRecheckMeta()

	sentAt := time.Date(2026, 3, 26, 1, 44, 50, 0, time.UTC)
	timeoutAt := sentAt.Add(3 * time.Second)
	receivedAt := timeoutAt.Add(400 * time.Millisecond)

	key := resolverSampleKey{
		resolverAddr: "127.0.0.1:5350",
		dnsID:        77,
	}
	c.resolverPending[key] = resolverSample{
		serverKey: "a",
		sentAt:    sentAt,
	}

	c.collectExpiredResolverTimeouts(timeoutAt)
	c.trackResolverSuccess([]byte{0x00, 0x4d}, &net.UDPAddr{IP: net.ParseIP("127.0.0.1"), Port: 5350}, "", receivedAt)

	c.resolverHealthMu.Lock()
	state := c.resolverHealth["a"]
	c.resolverHealthMu.Unlock()

	if state == nil {
		t.Fatal("expected resolver health state to exist")
	}
	if len(state.Events) != 0 {
		t.Fatalf("expected timeout streak to be cleared after late success, got %d events", len(state.Events))
	}
	if !state.TimeoutOnlySince.IsZero() {
		t.Fatal("expected timeout-only streak to be cleared after late success")
	}
	if state.LastSuccessAt.IsZero() {
		t.Fatal("expected late success timestamp to be recorded")
	}
}

func TestCollectExpiredResolverTimeoutsCanTriggerAutoDisable(t *testing.T) {
	c := buildTestClientWithResolvers(config.ClientConfig{
		AutoDisableTimeoutServers:       true,
		AutoDisableTimeoutWindowSeconds: 3.0,
		AutoDisableMinObservations:      3,
		AutoDisableCheckIntervalSeconds: 1.0,
		TunnelPacketTimeoutSec:          10.0,
	}, "a", "b", "c", "d")
	c.initResolverRecheckMeta()

	base := time.Date(2026, 3, 25, 14, 0, 0, 0, time.UTC)
	steps := []time.Time{
		base.Add(2 * time.Second),
		base.Add(4 * time.Second),
		base.Add(5 * time.Second),
	}
	for i, now := range steps {
		key := resolverSampleKey{
			resolverAddr: "127.0.0.1:5300",
			dnsID:        uint16(i + 1),
		}
		c.resolverPending[key] = resolverSample{
			serverKey: "a",
			sentAt:    now.Add(-1 * time.Second),
		}
		c.nowFn = func(current time.Time) func() time.Time {
			return func() time.Time { return current }
		}(now)
		c.collectExpiredResolverTimeouts(now)
		c.runResolverAutoDisable(now)
	}

	conn, ok := c.GetConnectionByKey("a")
	if !ok {
		t.Fatal("expected disabled connection to still exist")
	}
	if conn.IsValid {
		t.Fatal("expected timeout-derived health events to disable resolver")
	}
}

func TestResolverRequestTimeoutHonorsShortAutoDisableWindow(t *testing.T) {
	c := buildTestClientWithResolvers(config.ClientConfig{
		AutoDisableTimeoutServers:       true,
		AutoDisableTimeoutWindowSeconds: 3.0,
		AutoDisableCheckIntervalSeconds: 3.0,
		TunnelPacketTimeoutSec:          10.0,
	}, "a")

	if got := c.resolverRequestTimeout(); got != 3*time.Second {
		t.Fatalf("unexpected resolver request timeout: got=%s want=%s", got, 3*time.Second)
	}
}

func TestSingleSweepTimeoutsPreserveLogicalTimeoutSpanForAutoDisable(t *testing.T) {
	c := buildTestClientWithResolvers(config.ClientConfig{
		AutoDisableTimeoutServers:       true,
		AutoDisableTimeoutWindowSeconds: 3.0,
		AutoDisableMinObservations:      3,
		AutoDisableCheckIntervalSeconds: 3.0,
		TunnelPacketTimeoutSec:          10.0,
	}, "a", "b", "c", "d")
	c.initResolverRecheckMeta()

	now := time.Date(2026, 3, 25, 15, 0, 10, 0, time.UTC)
	c.nowFn = func() time.Time { return now }

	// These three requests all expire during the same sweep, but their logical
	// timeout times are spaced across the whole 3s window.
	samples := []resolverSample{
		{serverKey: "a", sentAt: now.Add(-6 * time.Second)},
		{serverKey: "a", sentAt: now.Add(-4*time.Second - 500*time.Millisecond)},
		{serverKey: "a", sentAt: now.Add(-3 * time.Second)},
	}
	for i, sample := range samples {
		c.resolverPending[resolverSampleKey{
			resolverAddr: "127.0.0.1:5300",
			dnsID:        uint16(100 + i),
		}] = sample
	}

	c.collectExpiredResolverTimeouts(now)
	c.runResolverAutoDisable(now)

	conn, ok := c.GetConnectionByKey("a")
	if !ok {
		t.Fatal("expected disabled connection to still exist")
	}
	if conn.IsValid {
		t.Fatal("expected single-sweep timeout observations to disable resolver")
	}
}

func TestResolverAutoDisableUsesTimeoutOnlyStreakAcrossWindow(t *testing.T) {
	c := buildTestClientWithResolvers(config.ClientConfig{
		AutoDisableTimeoutServers:       true,
		AutoDisableTimeoutWindowSeconds: 1.0,
		AutoDisableMinObservations:      1,
		AutoDisableCheckIntervalSeconds: 1.0,
	}, "a", "b", "c", "d")
	c.initResolverRecheckMeta()

	base := time.Date(2026, 3, 25, 16, 0, 0, 0, time.UTC)
	c.recordResolverHealthEvent("a", false, base)
	c.recordResolverHealthEvent("a", false, base.Add(400*time.Millisecond))
	c.recordResolverHealthEvent("a", false, base.Add(800*time.Millisecond))

	now := base.Add(1100 * time.Millisecond)
	c.nowFn = func() time.Time { return now }
	c.runResolverAutoDisable(now)

	conn, ok := c.GetConnectionByKey("a")
	if !ok {
		t.Fatal("expected disabled connection to still exist")
	}
	if conn.IsValid {
		t.Fatal("expected timeout-only streak across the full window to disable resolver")
	}
}

func TestResolverAutoDisableStopsAtThreeValidResolvers(t *testing.T) {
	c := buildTestClientWithResolvers(config.ClientConfig{
		AutoDisableTimeoutServers:       true,
		AutoDisableTimeoutWindowSeconds: 1.0,
		AutoDisableMinObservations:      1,
		AutoDisableCheckIntervalSeconds: 1.0,
	}, "a", "b", "c")
	c.initResolverRecheckMeta()

	base := time.Date(2026, 3, 25, 16, 30, 0, 0, time.UTC)
	now := base.Add(1100 * time.Millisecond)

	for _, key := range []string{"a", "b", "c"} {
		c.recordResolverHealthEvent(key, false, base)
	}

	c.runResolverAutoDisable(now)

	valid := c.balancer.ValidCount()
	if valid != 3 {
		t.Fatalf("expected no resolver to be disabled at the floor, got valid=%d", valid)
	}
}

func TestResolverHealthSuccessClearsTimeoutHistory(t *testing.T) {
	c := buildTestClientWithResolvers(config.ClientConfig{
		AutoDisableTimeoutServers:       true,
		AutoDisableTimeoutWindowSeconds: 3.0,
	}, "a", "b", "c", "d")
	c.initResolverRecheckMeta()

	base := time.Date(2026, 3, 26, 2, 0, 0, 0, time.UTC)
	c.recordResolverHealthEvent("a", true, base.Add(2*time.Second))
	c.recordResolverHealthEvent("a", false, base)
	c.recordResolverHealthEvent("a", true, base.Add(3*time.Second))

	c.resolverHealthMu.Lock()
	state := c.resolverHealth["a"]
	c.resolverHealthMu.Unlock()

	if state == nil {
		t.Fatal("expected resolver health state to exist")
	}
	if len(state.Events) != 0 {
		t.Fatalf("expected success to clear timeout history, got %d events", len(state.Events))
	}
	if state.LastSuccessAt != base.Add(3*time.Second) {
		t.Fatalf("unexpected last success timestamp: got=%s want=%s", state.LastSuccessAt, base.Add(3*time.Second))
	}
}
