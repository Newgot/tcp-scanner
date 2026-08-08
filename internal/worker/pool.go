package worker

import (
	"context"
	"sync"
)

// Task представляет функцию, которую должен выполнить воркер.
type Task func(ctx context.Context) error

// Pool управляет пулом воркеров для параллельного выполнения задач.
type Pool struct {
	workersCount int
	taskQueue    chan Task
	wg           sync.WaitGroup
	ctx          context.Context
	cancel       context.CancelFunc
	once         sync.Once
	mu           sync.RWMutex
	stopped      bool
}

// NewPool создает новый пул с указанным количеством воркеров.
func NewPool(ctx context.Context, workers int) *Pool {
	ctx, cancel := context.WithCancel(ctx)
	return &Pool{
		workersCount: workers,
		taskQueue:    make(chan Task, workers*2),
		ctx:          ctx,
		cancel:       cancel,
		stopped:      false,
	}
}

// Start запускает воркеров. Вызывается один раз.
func (p *Pool) Start() {
	p.once.Do(func() {
		for i := 0; i < p.workersCount; i++ {
			p.wg.Add(1)
			go p.worker()
		}
	})
}

// worker — горутина, которая выполняет задачи из очереди.
func (p *Pool) worker() {
	defer p.wg.Done()
	for {
		select {
		case <-p.ctx.Done():
			return
		case task, ok := <-p.taskQueue:
			if !ok {
				return
			}
			_ = task(p.ctx)
		}
	}
}

// Submit отправляет задачу в пул.
func (p *Pool) Submit(task Task) error {
	p.mu.RLock()
	if p.stopped {
		p.mu.RUnlock()
		return context.Canceled
	}
	p.mu.RUnlock()

	select {
	case <-p.ctx.Done():
		return p.ctx.Err()
	case p.taskQueue <- task:
		return nil
	}
}

// Stop останавливает пул.
func (p *Pool) Stop() {
	p.mu.Lock()
	if p.stopped {
		p.mu.Unlock()
		return
	}
	p.stopped = true
	p.mu.Unlock()

	p.cancel()
	close(p.taskQueue)
	p.wg.Wait()
}
