package worker

import (
	"context"
	"sync"
)

// Task представляет функцию, которую должен выполнить воркер.
// Возвращает ошибку, если выполнение завершилось неудачей.
type Task func(ctx context.Context) error

// Pool управляет пулом воркеров для параллельного выполнения задач.
type Pool struct {
	workersCount int
	taskQueue    chan Task
	wg           sync.WaitGroup
	ctx          context.Context
	cancel       context.CancelFunc
	once         sync.Once
}

// NewPool создает новый пул с указанным количеством воркеров.
func NewPool(ctx context.Context, workers int) *Pool {
	ctx, cancel := context.WithCancel(ctx)
	return &Pool{
		workersCount: workers,
		taskQueue:    make(chan Task, workers*2), // буферизированный канал
		ctx:          ctx,
		cancel:       cancel,
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
			return // завершаем работу при отмене контекста
		case task, ok := <-p.taskQueue:
			if !ok {
				return // канал задач закрыт
			}
			// Выполняем задачу с контекстом пула
			_ = task(p.ctx) // ошибка может логироваться или обрабатываться отдельно
		}
	}
}

// Submit отправляет задачу в пул. Блокируется, если очередь заполнена.
func (p *Pool) Submit(task Task) error {
	select {
	case <-p.ctx.Done():
		return p.ctx.Err()
	case p.taskQueue <- task:
		return nil
	}
}

// Stop останавливает пул: закрывает канал задач и ожидает завершения воркеров.
func (p *Pool) Stop() {
	p.cancel()         // сигнал всем воркерам остановиться
	close(p.taskQueue) // закрываем канал задач
	p.wg.Wait()        // ожидаем завершения всех воркеров
}
