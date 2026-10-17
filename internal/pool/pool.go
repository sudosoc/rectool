// Package pool implements a bounded worker pool shared by all modules, so the
// total number of in-flight tasks stays fixed no matter how many modules or
// targets are queued.
package pool

import (
	"context"
	"sync"
)

// Pool runs submitted functions on a fixed number of goroutines.
type Pool struct {
	tasks chan func()
	wg    sync.WaitGroup
	once  sync.Once
}

// New starts workers goroutines consuming a queue of the given capacity.
func New(workers, queue int) *Pool {
	if workers < 1 {
		workers = 1
	}
	if queue < 0 {
		queue = 0
	}
	p := &Pool{tasks: make(chan func(), queue)}
	p.wg.Add(workers)
	for i := 0; i < workers; i++ {
		go p.worker()
	}
	return p
}

func (p *Pool) worker() {
	defer p.wg.Done()
	for fn := range p.tasks {
		func() {
			// A misbehaving task must not take the whole process down.
			defer func() { _ = recover() }()
			fn()
		}()
	}
}

// Submit enqueues fn, blocking while the queue is full (back-pressure).
// It returns ctx.Err() if the context ends first; fn is then NOT run.
// Submit must not be called after Close.
func (p *Pool) Submit(ctx context.Context, fn func()) error {
	select {
	case <-ctx.Done():
		return ctx.Err()
	default:
	}
	select {
	case p.tasks <- fn:
		return nil
	case <-ctx.Done():
		return ctx.Err()
	}
}

// Close stops accepting work and waits for queued tasks to finish.
func (p *Pool) Close() {
	p.once.Do(func() { close(p.tasks) })
	p.wg.Wait()
}
