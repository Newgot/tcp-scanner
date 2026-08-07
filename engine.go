// engine.go
package portscan

import (
	"context"
	"errors"
	"fmt"
	"net"
	"strconv"
	"strings"
	"sync"

	"github.com/Newgot/tcp-scanner/internal/dialer"
)

type Scanner struct {
	config *Config
	dialer *dialer.TCPDialer
	mu     sync.RWMutex
	closed bool
}

func New(opts ...Option) (*Scanner, error) {
	cfg := DefaultConfig()
	for _, opt := range opts {
		if err := opt(cfg); err != nil {
			return nil, fmt.Errorf("invalid option: %w", err)
		}
	}

	if err := cfg.Validate(); err != nil {
		return nil, err
	}

	return &Scanner{
		config: cfg,
		dialer: dialer.NewTCPDialer(dialer.Config{
			Timeout:   cfg.ConnectTimeout,
			LocalAddr: cfg.LocalAddr,
			KeepAlive: -1,
		}),
	}, nil
}

func MustNew(opts ...Option) *Scanner {
	s, err := New(opts...)
	if err != nil {
		panic(err)
	}
	return s
}

// Scan выполняет сканирование для указанных хостов и портов
func (s *Scanner) Scan(ctx context.Context, hosts []string, ports []int) (<-chan Result, error) {
	s.mu.RLock()
	if s.closed {
		s.mu.RUnlock()
		return nil, ErrClosed
	}
	s.mu.RUnlock()

	if len(hosts) == 0 {
		return nil, ErrNoHosts
	}
	if len(ports) == 0 {
		return nil, ErrNoPorts
	}

	for _, p := range ports {
		if p < 1 || p > 65535 {
			return nil, fmt.Errorf("%w: %d", ErrInvalidPort, p)
		}
	}

	results := make(chan Result, s.config.Concurrency*2)
	tasks := make(chan task, s.config.Concurrency*2)

	var wg sync.WaitGroup

	// Создаем контекст с отменой
	ctx, cancel := context.WithCancel(ctx)

	// Запускаем воркеров
	for i := 0; i < s.config.Concurrency; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for task := range tasks {
				select {
				case <-ctx.Done():
					return
				default:
					result := s.scanPort(ctx, task.host, task.port)
					select {
					case results <- result:
					case <-ctx.Done():
						return
					}
				}
			}
		}()
	}

	// Отправляем задачи
	go func() {
		defer close(tasks)
		for _, host := range hosts {
			for _, port := range ports {
				select {
				case <-ctx.Done():
					return
				case tasks <- task{host: host, port: port}:
				}
			}
		}
	}()

	// Закрываем результаты ПОСЛЕ завершения всех воркеров
	go func() {
		wg.Wait()
		cancel()
		close(results)
	}()

	return results, nil
}

// ScanAll выполняет сканирование и собирает все результаты в слайс
func (s *Scanner) ScanAll(ctx context.Context, hosts []string, ports []int) ([]Result, error) {
	resultsChan, err := s.Scan(ctx, hosts, ports)
	if err != nil {
		return nil, err
	}

	var results []Result
	for result := range resultsChan {
		results = append(results, result)
	}

	return results, nil
}

// scanPort сканирует один порт
func (s *Scanner) scanPort(ctx context.Context, host string, port int) Result {
	addr := net.JoinHostPort(host, strconv.Itoa(port))
	conn, err := s.dialer.DialContext(ctx, "tcp", addr)

	if err != nil {
		return s.handleScanError(host, port, err)
	}
	defer conn.Close()

	return Result{
		Host:  host,
		Port:  port,
		State: StateOpen,
	}
}

// handleScanError обрабатывает ошибки сканирования
func (s *Scanner) handleScanError(host string, port int, err error) Result {
	var netErr net.Error
	if errors.As(err, &netErr) {
		if netErr.Timeout() {
			return Result{
				Host:  host,
				Port:  port,
				State: StateFiltered,
				Error: err,
			}
		}
	}

	errStr := err.Error()
	if strings.Contains(errStr, "connection refused") ||
		strings.Contains(errStr, "no route to host") ||
		strings.Contains(errStr, "connection reset") {
		return Result{
			Host:  host,
			Port:  port,
			State: StateClosed,
			Error: err,
		}
	}

	return Result{
		Host:  host,
		Port:  port,
		State: StateError,
		Error: err,
	}
}

// Close закрывает сканер и освобождает ресурсы
func (s *Scanner) Close() error {
	s.mu.Lock()
	defer s.mu.Unlock()

	if s.closed {
		return ErrClosed
	}
	s.closed = true
	return nil
}

// IsClosed проверяет, закрыт ли сканер
func (s *Scanner) IsClosed() bool {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.closed
}
