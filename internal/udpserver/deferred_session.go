// ==============================================================================
// StormDNS
// Author: nullroute1970
// Github: https://github.com/nullroute1970/StormDNS
// Year: 2026
// ==============================================================================

package udpserver

import (
	"context"
	"fmt"
	"sync"
	"sync/atomic"
	"time"

	"stormdns-go/internal/logger"
)

type deferredSessionLane struct {
	sessionID uint8
	streamID  uint16
}

type deferredSessionTask struct {
	lane deferredSessionLane
	run  func(context.Context)
}

type deferredSessionWorker struct {
	jobs    chan deferredSessionTask
	pending atomic.Int32
}

type deferredSessionProcessor struct {
	log                *logger.Logger
	workers            []deferredSessionWorker
	mu                 sync.Mutex
	laneWorker         map[deferredSessionLane]int
	cancelled          map[deferredSessionLane]struct{}
	running            map[deferredSessionLane]context.CancelFunc
	sessionPending     map[uint8]int32
	sessionPendingCap  int32
	sessionPressureLog throttledLogState
	backlogHighLog     throttledLogState
	nextWorker         int
}

func deriveDeferredSessionPendingCap(workerCount int, queueLimit int) int32 {
	if workerCount <= 0 {
		workerCount = 1
	}

	if queueLimit < 1 {
		queueLimit = 256
	}

	// Keep the per-session cap comfortably below the total queue budget, but
	// large enough that one busy session does not trip overflow logs long before
	// the processor itself is under real pressure.
	capGuess := min(max(queueLimit/2, 32), 1024)

	totalCapacity := workerCount * queueLimit
	if capGuess > totalCapacity {
		capGuess = totalCapacity
	}

	if capGuess < 8 {
		capGuess = 8
	}

	// Never exceed what the worker queues can actually hold.
	if capGuess > totalCapacity {
		capGuess = totalCapacity
	}

	return int32(capGuess)
}

func newDeferredSessionProcessor(workerCount int, queueLimit int, log *logger.Logger) *deferredSessionProcessor {
	if workerCount <= 0 {
		return nil
	}
	if workerCount > 64 {
		workerCount = 64
	}
	if queueLimit < 1 {
		queueLimit = 256
	}
	if queueLimit > 8192 {
		queueLimit = 8192
	}

	workers := make([]deferredSessionWorker, workerCount)
	for i := range workers {
		workers[i].jobs = make(chan deferredSessionTask, queueLimit)
	}

	return &deferredSessionProcessor{
		log:               log,
		workers:           workers,
		laneWorker:        make(map[deferredSessionLane]int, 128),
		cancelled:         make(map[deferredSessionLane]struct{}, 128),
		running:           make(map[deferredSessionLane]context.CancelFunc, 128),
		sessionPending:    make(map[uint8]int32, 64),
		sessionPendingCap: deriveDeferredSessionPendingCap(workerCount, queueLimit),
	}
}

func (p *deferredSessionProcessor) Start(ctx context.Context) {
	if p == nil {
		return
	}

	for idx := range p.workers {
		go p.runDeferredWorker(ctx, idx)
	}
}

func (p *deferredSessionProcessor) Enqueue(lane deferredSessionLane, run func(context.Context)) bool {
	if p == nil || run == nil || len(p.workers) == 0 {
		return false
	}

	task := deferredSessionTask{
		lane: lane,
		run:  run,
	}

	p.mu.Lock()
	delete(p.cancelled, lane)
	if !p.canAcceptSessionLocked(lane.sessionID) {
		p.mu.Unlock()
		return false
	}
	if workerIdx, ok := p.laneWorker[lane]; ok {
		ok = p.enqueueToExistingWorkerLocked(workerIdx, task)

		p.mu.Unlock()
		return ok
	}

	start := p.nextWorker
	workerIdx := p.selectLeastLoadedWorkerLocked(start)
	if workerIdx < 0 {
		p.mu.Unlock()
		return false
	}
	p.nextWorker = (workerIdx + 1) % len(p.workers)
	p.laneWorker[lane] = workerIdx
	ok := p.tryEnqueueLocked(workerIdx, task)
	if !ok {
		delete(p.laneWorker, lane)
	}
	p.mu.Unlock()
	return ok
}

func (p *deferredSessionProcessor) RemoveSession(sessionID uint8) {
	if p == nil {
		return
	}
	p.mu.Lock()
	for lane, cancel := range p.running {
		if lane.sessionID == sessionID {
			cancel()
			delete(p.running, lane)
		}
	}
	for lane := range p.laneWorker {
		if lane.sessionID == sessionID {
			p.cancelled[lane] = struct{}{}
			delete(p.laneWorker, lane)
		}
	}
	p.compactQueuesLocked(func(lane deferredSessionLane) bool {
		return lane.sessionID == sessionID
	})
	p.mu.Unlock()
}

func (p *deferredSessionProcessor) RemoveLane(lane deferredSessionLane) {
	if p == nil || lane.sessionID == 0 {
		return
	}
	p.mu.Lock()
	if cancel, ok := p.running[lane]; ok {
		cancel()
		delete(p.running, lane)
	}

	delete(p.laneWorker, lane)

	if _, ok := p.cancelled[lane]; !ok {
		p.cancelled[lane] = struct{}{}
	}

	p.compactQueuesLocked(func(candidate deferredSessionLane) bool {
		return candidate == lane
	})

	p.mu.Unlock()
}

func (p *deferredSessionProcessor) FinalizeLane(lane deferredSessionLane) {
	if p == nil || lane.sessionID == 0 {
		return
	}
	p.mu.Lock()

	delete(p.laneWorker, lane)
	if _, ok := p.cancelled[lane]; !ok {
		p.cancelled[lane] = struct{}{}
	}

	p.compactQueuesLocked(func(candidate deferredSessionLane) bool {
		return candidate == lane
	})

	p.mu.Unlock()
}

func (p *deferredSessionProcessor) runDeferredWorker(ctx context.Context, workerIdx int) {
	worker := &p.workers[workerIdx]
	for {
		select {
		case <-ctx.Done():
			return
		case task, ok := <-worker.jobs:
			if !ok {
				return
			}
			func() {
				taskCtx, cancel := p.beginTaskContext(ctx, task.lane)
				defer func() {
					cancel()
					worker.pending.Add(-1)
					p.finishLane(task.lane, workerIdx)
					if recovered := recover(); recovered != nil && p.log != nil {
						p.log.Debugf(
							"Deferred Session Worker Panic, Worker: %d, Session: %d, Stream: %d, Error: %v",
							workerIdx+1,
							task.lane.sessionID,
							task.lane.streamID,
							recovered,
						)
					}
				}()
				task.run(taskCtx)
			}()
		}
	}
}

func (p *deferredSessionProcessor) beginTaskContext(parent context.Context, lane deferredSessionLane) (context.Context, context.CancelFunc) {
	taskCtx, cancel := context.WithCancel(parent)
	if p == nil {
		return taskCtx, cancel
	}

	p.mu.Lock()
	if _, cancelled := p.cancelled[lane]; cancelled {
		cancel()
		p.mu.Unlock()
		return taskCtx, func() {}
	}
	p.running[lane] = cancel
	p.mu.Unlock()
	return taskCtx, cancel
}

func (p *deferredSessionProcessor) enqueueToExistingWorkerLocked(workerIdx int, task deferredSessionTask) bool {
	worker := &p.workers[workerIdx]
	worker.pending.Add(1)
	p.sessionPending[task.lane.sessionID]++
	select {
	case worker.jobs <- task:
		p.maybeLogPressureLocked(workerIdx, task.lane)
		return true
	default:
		worker.pending.Add(-1)
		p.decrementSessionPendingLocked(task.lane.sessionID)
		return false
	}
}

func (p *deferredSessionProcessor) tryEnqueueLocked(workerIdx int, task deferredSessionTask) bool {
	worker := &p.workers[workerIdx]
	worker.pending.Add(1)
	p.sessionPending[task.lane.sessionID]++
	select {
	case worker.jobs <- task:
		p.maybeLogPressureLocked(workerIdx, task.lane)
		return true
	default:
		worker.pending.Add(-1)
		p.decrementSessionPendingLocked(task.lane.sessionID)
		return false
	}
}

func (p *deferredSessionProcessor) finishLane(lane deferredSessionLane, workerIdx int) {
	if p == nil {
		return
	}
	p.mu.Lock()
	if mappedWorker, ok := p.laneWorker[lane]; ok && mappedWorker == workerIdx {
		delete(p.laneWorker, lane)
	}
	if cancel, ok := p.running[lane]; ok {
		cancel()
		delete(p.running, lane)
	}
	delete(p.cancelled, lane)
	p.decrementSessionPendingLocked(lane.sessionID)
	p.mu.Unlock()
}

func (p *deferredSessionProcessor) compactQueuesLocked(drop func(deferredSessionLane) bool) int {
	totalDropped := 0
	for idx := range p.workers {
		totalDropped += p.compactWorkerLocked(idx, drop)
	}
	return totalDropped
}

func (p *deferredSessionProcessor) compactWorkerLocked(workerIdx int, drop func(deferredSessionLane) bool) int {
	worker := &p.workers[workerIdx]
	if len(worker.jobs) == 0 {
		return 0
	}

	dropped := 0
	queued := make([]deferredSessionTask, 0, len(worker.jobs))
	for {
		select {
		case task := <-worker.jobs:
			if p.shouldDropTaskLocked(task.lane, drop) {
				worker.pending.Add(-1)
				delete(p.laneWorker, task.lane)
				p.decrementSessionPendingLocked(task.lane.sessionID)
				dropped++
				continue
			}
			queued = append(queued, task)
		default:
			for _, task := range queued {
				worker.jobs <- task
			}
			return dropped
		}
	}
}

func (p *deferredSessionProcessor) canAcceptSessionLocked(sessionID uint8) bool {
	if p == nil || sessionID == 0 {
		return true
	}
	return p.sessionPending[sessionID] < p.sessionPendingCap
}

func (p *deferredSessionProcessor) decrementSessionPendingLocked(sessionID uint8) {
	if p == nil || sessionID == 0 {
		return
	}
	if pending := p.sessionPending[sessionID]; pending > 1 {
		p.sessionPending[sessionID] = pending - 1
		return
	}
	delete(p.sessionPending, sessionID)
}

func (p *deferredSessionProcessor) maybeLogPressureLocked(workerIdx int, lane deferredSessionLane) {
	if p == nil || p.log == nil {
		return
	}
	workerPending := p.workers[workerIdx].pending.Load()
	sessionPending := p.sessionPending[lane.sessionID]
	if workerPending < 16 && sessionPending < p.sessionPendingCap {
		return
	}

	if !p.backlogHighLog.allow(fmt.Sprintf("worker:%d:session:%d", workerIdx, lane.sessionID), time.Now(), time.Second) {
		return
	}
}

func (p *deferredSessionProcessor) workerCount() int {
	if p == nil {
		return 0
	}
	return len(p.workers)
}

func (p *deferredSessionProcessor) queueLimit() int {
	if p == nil || len(p.workers) == 0 {
		return 0
	}
	return cap(p.workers[0].jobs)
}

func (p *deferredSessionProcessor) sessionCap() int32 {
	if p == nil {
		return 0
	}
	return p.sessionPendingCap
}

func (p *deferredSessionProcessor) shouldDropTaskLocked(lane deferredSessionLane, drop func(deferredSessionLane) bool) bool {
	if drop != nil && drop(lane) {
		return true
	}
	_, cancelled := p.cancelled[lane]
	return cancelled
}

func (p *deferredSessionProcessor) selectLeastLoadedWorkerLocked(start int) int {
	if len(p.workers) == 0 {
		return -1
	}

	bestIdx := -1
	bestPending := int32(0)
	for offset := range p.workers {
		idx := (start + offset) % len(p.workers)
		pending := p.workers[idx].pending.Load()
		if bestIdx < 0 || pending < bestPending {
			bestIdx = idx
			bestPending = pending
			if pending == 0 {
				break
			}
		}
	}
	return bestIdx
}
