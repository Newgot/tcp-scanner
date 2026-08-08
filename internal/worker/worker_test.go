// internal/worker/worker_test.go - увеличиваем время ожидания
package worker

import (
	"context"
	"sync/atomic"
	"testing"
	"time"
)

func TestPool_Submit(t *testing.T) {
	ctx := context.Background()
	pool := NewPool(ctx, 2)
	pool.Start()

	var counter int32
	task := func(ctx context.Context) error {
		atomic.AddInt32(&counter, 1)
		// Добавляем небольшую задержку
		time.Sleep(1 * time.Millisecond)
		return nil
	}

	for i := 0; i < 100; i++ {
		if err := pool.Submit(task); err != nil {
			t.Errorf("Submit() error = %v", err)
		}
	}

	// Увеличиваем время ожидания
	time.Sleep(300 * time.Millisecond)
	pool.Stop()

	if counter != 100 {
		t.Errorf("Expected counter=100, got %d", counter)
	}
}

func TestPool_MultipleWorkers(t *testing.T) {
	ctx := context.Background()
	workers := 5
	pool := NewPool(ctx, workers)
	pool.Start()

	var counter int32
	var maxConcurrent int32
	var currentConcurrent int32

	task := func(ctx context.Context) error {
		cur := atomic.AddInt32(&currentConcurrent, 1)
		for {
			maxCount := atomic.LoadInt32(&maxConcurrent)
			if cur <= maxCount || atomic.CompareAndSwapInt32(&maxConcurrent, maxCount, cur) {
				break
			}
		}

		time.Sleep(20 * time.Millisecond)

		atomic.AddInt32(&counter, 1)
		atomic.AddInt32(&currentConcurrent, -1)
		return nil
	}

	for i := 0; i < 20; i++ {
		if err := pool.Submit(task); err != nil {
			t.Errorf("Submit() error = %v", err)
		}
	}

	// Увеличиваем время ожидания
	time.Sleep(500 * time.Millisecond)
	pool.Stop()

	if maxConcurrent > int32(workers) {
		t.Errorf("Max concurrent workers %d exceeds pool size %d", maxConcurrent, workers)
	}

	if counter != 20 {
		t.Errorf("Expected counter=20, got %d", counter)
	}

	t.Logf("Max concurrent: %d, Workers: %d", maxConcurrent, workers)
}

func TestPool_StopMultipleTimes(t *testing.T) {
	ctx := context.Background()
	pool := NewPool(ctx, 2)
	pool.Start()

	var counter int32
	task := func(ctx context.Context) error {
		atomic.AddInt32(&counter, 1)
		time.Sleep(5 * time.Millisecond)
		return nil
	}

	for i := 0; i < 5; i++ {
		if err := pool.Submit(task); err != nil {
			t.Errorf("Submit() error = %v", err)
		}
	}

	// Даем время на выполнение
	time.Sleep(100 * time.Millisecond)

	pool.Stop()
	pool.Stop()
	pool.Stop()

	if counter != 5 {
		t.Errorf("Expected counter=5, got %d", counter)
	}
}

func TestPool_GoroutineLeak(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping goroutine leak test in short mode")
	}

	ctx := context.Background()
	pool := NewPool(ctx, 5)
	pool.Start()

	var counter int32
	task := func(ctx context.Context) error {
		atomic.AddInt32(&counter, 1)
		time.Sleep(5 * time.Millisecond)
		return nil
	}

	for i := 0; i < 50; i++ {
		if err := pool.Submit(task); err != nil {
			t.Errorf("Submit() error = %v", err)
		}
	}

	// Увеличиваем время ожидания
	time.Sleep(500 * time.Millisecond)
	pool.Stop()

	if counter != 50 {
		t.Errorf("Expected counter=50, got %d", counter)
	}
}

func TestPool_HighLoad(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping high load test in short mode")
	}

	ctx := context.Background()
	pool := NewPool(ctx, 20)
	pool.Start()

	var counter int32
	task := func(ctx context.Context) error {
		atomic.AddInt32(&counter, 1)
		time.Sleep(1 * time.Millisecond)
		return nil
	}

	taskCount := 1000
	for i := 0; i < taskCount; i++ {
		if err := pool.Submit(task); err != nil {
			t.Errorf("Submit() error = %v", err)
		}
	}

	// Увеличиваем время ожидания
	time.Sleep(500 * time.Millisecond)
	pool.Stop()

	if counter != int32(taskCount) {
		t.Errorf("Expected counter=%d, got %d", taskCount, counter)
	}
}
