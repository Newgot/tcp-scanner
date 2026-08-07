package portscan

import (
	"context"
	"errors"
	"fmt"
	"net"
	"os"
	"strconv"
	"sync"
	"syscall"

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

	// Валидация портов
	if err := ValidatePorts(ports); err != nil {
		return nil, err
	}

	// Разрешаем хосты
	hostsInfo, err := ValidateHosts(hosts)
	if err != nil {
		return nil, err
	}

	// Получаем уникальные IP-адреса для сканирования
	addresses := GetUniqueAddresses(hostsInfo)
	if len(addresses) == 0 {
		return nil, fmt.Errorf("no valid IP addresses to scan")
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
		for _, addr := range addresses {
			for _, port := range ports {
				select {
				case <-ctx.Done():
					return
				case tasks <- task{host: addr, port: port}:
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
	// Проверяем, не отменен ли контекст
	select {
	case <-ctx.Done():
		return Result{
			Host:  host,
			Port:  port,
			State: StateCanceled,
			Error: ctx.Err(),
		}
	default:
	}

	addr := net.JoinHostPort(host, strconv.Itoa(port))
	conn, err := s.dialer.DialContext(ctx, "tcp", addr)

	if err != nil {
		return s.classifyError(host, port, err)
	}
	defer func(conn net.Conn) {
		err := conn.Close()
		if err != nil {
			panic(err)
		}
	}(conn)

	return Result{
		Host:  host,
		Port:  port,
		State: StateOpen,
	}
}

// classifyError классифицирует ошибку без сравнения текста
func (s *Scanner) classifyError(host string, port int, err error) Result {
	// Проверяем отмену контекста
	if errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded) {
		return Result{
			Host:  host,
			Port:  port,
			State: StateCanceled,
			Error: err,
		}
	}

	// Проверяем сетевые ошибки
	var netErr net.Error
	if errors.As(err, &netErr) {
		// Таймаут
		if netErr.Timeout() {
			return Result{
				Host:  host,
				Port:  port,
				State: StateTimeout,
				Error: err,
			}
		}
	}

	// Проверяем ошибки syscall
	var opErr *net.OpError
	if errors.As(err, &opErr) {
		// Проверяем ошибки соединения
		if opErr.Op == "dial" {
			// Проверяем системные ошибки
			if sysErr, ok := opErr.Err.(*os.SyscallError); ok {
				switch sysErr.Err {
				case syscall.ECONNREFUSED:
					return Result{
						Host:  host,
						Port:  port,
						State: StateClosed,
						Error: err,
					}
				case syscall.ENETUNREACH:
					return Result{
						Host:  host,
						Port:  port,
						State: StateUnreachable,
						Error: err,
					}
				case syscall.EHOSTUNREACH:
					return Result{
						Host:  host,
						Port:  port,
						State: StateUnreachable,
						Error: err,
					}
				case syscall.ECONNRESET:
					return Result{
						Host:  host,
						Port:  port,
						State: StateClosed,
						Error: err,
					}
				case syscall.ETIMEDOUT:
					return Result{
						Host:  host,
						Port:  port,
						State: StateTimeout,
						Error: err,
					}
				}
			}
		}

		// Проверяем ошибки DNS
		if dnsErr, ok := opErr.Err.(*net.DNSError); ok {
			if dnsErr.IsNotFound {
				return Result{
					Host:  host,
					Port:  port,
					State: StateUnreachable,
					Error: err,
				}
			}
			if dnsErr.IsTimeout {
				return Result{
					Host:  host,
					Port:  port,
					State: StateTimeout,
					Error: err,
				}
			}
		}
	}

	// Если ошибка не классифицирована, возвращаем как error
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
