package agent

import "context"

// workerPool caps concurrent check executions to max via a buffered
// semaphore. Used by the scheduler so a Lighthouse with 100 checks all
// firing on the same minute boundary doesn't spawn 100 goroutines at
// once on a tiny customer host.
type workerPool struct {
	slots chan struct{}
}

func newWorkerPool(size int) *workerPool {
	if size < 1 {
		size = 1
	}
	return &workerPool{slots: make(chan struct{}, size)}
}

// Submit blocks until a slot is available, then runs fn. Honors ctx
// cancellation while waiting for a slot — partially-cancelled jobs are
// dropped (returns ctx.Err()).
func (p *workerPool) Submit(ctx context.Context, fn func()) error {
	select {
	case <-ctx.Done():
		return ctx.Err()
	case p.slots <- struct{}{}:
	}
	defer func() { <-p.slots }()
	fn()
	return nil
}
