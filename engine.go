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
	"time"

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

	// Создаем карту для отслеживания исходных хостов по IP
	hostMap := make(map[string]string)
	for _, info := range hostsInfo {
		for _, addr := range info.Addresses {
			hostMap[addr] = info.Original
		}
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
					// Получаем исходное имя хоста
					hostName := hostMap[task.host]
					if hostName == "" {
						hostName = task.host
					}
					result := s.scanPort(ctx, hostName, task.host, task.port)
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
func (s *Scanner) scanPort(ctx context.Context, hostName, ipAddr string, port int) Result {
	start := time.Now()

	select {
	case <-ctx.Done():
		return Result{
			Host:     hostName,
			IP:       net.ParseIP(ipAddr),
			Port:     uint16(port),
			State:    StateCanceled,
			Duration: time.Since(start),
			Error:    ctx.Err(),
		}
	default:
	}

	addr := net.JoinHostPort(ipAddr, strconv.Itoa(port))
	conn, err := s.dialer.DialContext(ctx, "tcp", addr)

	duration := time.Since(start)

	if err != nil {
		return s.classifyError(hostName, ipAddr, port, duration, err)
	}

	// Исправление: обрабатываем ошибку закрытия без panic
	if err := conn.Close(); err != nil {
		// Логируем ошибку, но не паникуем
		// В реальном коде можно использовать логгер
	}

	return Result{
		Host:     hostName,
		IP:       net.ParseIP(ipAddr),
		Port:     uint16(port),
		State:    StateOpen,
		Duration: duration,
	}
}

// classifyError классифицирует ошибку без сравнения текста
func (s *Scanner) classifyError(hostName, ipAddr string, port int, duration time.Duration, err error) Result {
	// Проверяем отмену контекста
	if errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded) {
		return Result{
			Host:     hostName,
			IP:       net.ParseIP(ipAddr),
			Port:     uint16(port),
			State:    StateCanceled,
			Duration: duration,
			Error:    err,
		}
	}

	// Проверяем сетевые ошибки
	var netErr net.Error
	if errors.As(err, &netErr) {
		if netErr.Timeout() {
			return Result{
				Host:     hostName,
				IP:       net.ParseIP(ipAddr),
				Port:     uint16(port),
				State:    StateTimeout,
				Duration: duration,
				Error:    err,
			}
		}
	}

	// Проверяем ошибки syscall
	var opErr *net.OpError
	if errors.As(err, &opErr) {
		if opErr.Op == "dial" {
			if sysErr, ok := opErr.Err.(*os.SyscallError); ok {
				switch sysErr.Err {
				case syscall.ECONNREFUSED, syscall.ECONNRESET:
					return Result{
						Host:     hostName,
						IP:       net.ParseIP(ipAddr),
						Port:     uint16(port),
						State:    StateClosed,
						Duration: duration,
						Error:    err,
					}
				case syscall.ENETUNREACH, syscall.EHOSTUNREACH:
					return Result{
						Host:     hostName,
						IP:       net.ParseIP(ipAddr),
						Port:     uint16(port),
						State:    StateUnreachable,
						Duration: duration,
						Error:    err,
					}
				case syscall.ETIMEDOUT:
					return Result{
						Host:     hostName,
						IP:       net.ParseIP(ipAddr),
						Port:     uint16(port),
						State:    StateTimeout,
						Duration: duration,
						Error:    err,
					}
				}
			}
		}

		// Проверяем ошибки DNS
		var dnsErr *net.DNSError
		if errors.As(opErr.Err, &dnsErr) {
			if dnsErr.IsNotFound {
				return Result{
					Host:     hostName,
					IP:       nil,
					Port:     uint16(port),
					State:    StateUnreachable,
					Duration: duration,
					Error:    err,
				}
			}
			if dnsErr.IsTimeout {
				return Result{
					Host:     hostName,
					IP:       nil,
					Port:     uint16(port),
					State:    StateTimeout,
					Duration: duration,
					Error:    err,
				}
			}
		}
	}

	// Если ошибка не классифицирована, возвращаем как error
	return Result{
		Host:     hostName,
		IP:       net.ParseIP(ipAddr),
		Port:     uint16(port),
		State:    StateError,
		Duration: duration,
		Error:    err,
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
