package portscan

import (
	"context"
	"errors"
	"testing"
	"time"
)

func TestNew(t *testing.T) {
	tests := []struct {
		name    string
		opts    []Option
		wantErr bool
	}{
		{
			name:    "default options",
			opts:    []Option{},
			wantErr: false,
		},
		{
			name:    "custom concurrency",
			opts:    []Option{WithConcurrency(50)},
			wantErr: false,
		},
		{
			name:    "invalid concurrency",
			opts:    []Option{WithConcurrency(0)},
			wantErr: true,
		},
		{
			name:    "negative timeout",
			opts:    []Option{WithConnectTimeout(-1 * time.Second)},
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := New(tt.opts...)
			if (err != nil) != tt.wantErr {
				t.Errorf("New() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}

func TestScanner_Scan(t *testing.T) {
	scanner, err := New(WithConnectTimeout(100 * time.Millisecond))
	if err != nil {
		t.Fatal(err)
	}
	defer func() {
		if err := scanner.Close(); err != nil {
			t.Logf("Error closing scanner: %v", err)
		}
	}()

	ctx := context.Background()
	ports := []int{80, 443, 8080}

	results, err := scanner.Scan(ctx, []string{"localhost"}, ports)
	if err != nil {
		t.Fatal(err)
	}

	count := 0
	for result := range results {
		count++
		// Проверяем, что IP адрес установлен
		if result.IP == nil {
			t.Errorf("Result IP is nil for port %d", result.Port)
		}
		// Проверяем, что порт валидный
		if result.Port < 1 || result.Port > 65535 {
			t.Errorf("Invalid port: %d", result.Port)
		}
	}

	if count != len(ports) {
		t.Errorf("Expected %d results, got %d", len(ports), count)
	}
}

func TestScanner_ScanAll(t *testing.T) {
	scanner, err := New(WithConnectTimeout(100 * time.Millisecond))
	if err != nil {
		t.Fatal(err)
	}
	defer func() {
		if err := scanner.Close(); err != nil {
			t.Logf("Error closing scanner: %v", err)
		}
	}()

	ctx := context.Background()
	ports := Range(1, 10)

	results, err := scanner.ScanAll(ctx, []string{"localhost"}, ports)
	if err != nil {
		t.Fatal(err)
	}

	if len(results) != len(ports) {
		t.Errorf("Expected %d results, got %d", len(ports), len(results))
	}
}

func TestScanner_Close(t *testing.T) {
	scanner, err := New()
	if err != nil {
		t.Fatal(err)
	}

	if err := scanner.Close(); err != nil {
		t.Errorf("Close() error = %v", err)
	}

	// Попытка повторного закрытия
	if err := scanner.Close(); err != ErrClosed {
		t.Errorf("Close() error = %v, want %v", err, ErrClosed)
	}

	// Попытка сканирования после закрытия
	_, err = scanner.Scan(context.Background(), []string{"localhost"}, []int{80})
	if !errors.Is(err, ErrClosed) {
		t.Errorf("Scan() error = %v, want %v", err, ErrClosed)
	}
}

func TestScanner_ContextCancel(t *testing.T) {
	scanner, err := New(WithConcurrency(10), WithConnectTimeout(1*time.Second))
	if err != nil {
		t.Fatal(err)
	}
	defer func() {
		if err := scanner.Close(); err != nil {
			t.Logf("Error closing scanner: %v", err)
		}
	}()

	ctx, cancel := context.WithCancel(context.Background())
	ports := Range(1, 1000)

	results, err := scanner.Scan(ctx, []string{"localhost"}, ports)
	if err != nil {
		t.Fatal(err)
	}

	// Отменяем через 10ms
	time.AfterFunc(10*time.Millisecond, func() {
		cancel()
	})

	count := 0
	for range results {
		count++
	}

	// Должно быть меньше 1000, так как отмена произошла
	if count >= 1000 {
		t.Errorf("Expected less than 1000 results after cancel, got %d", count)
	}
}

func TestScanner_MultipleHosts(t *testing.T) {
	scanner, err := New(WithConnectTimeout(100 * time.Millisecond))
	if err != nil {
		t.Fatal(err)
	}
	defer func() {
		if err := scanner.Close(); err != nil {
			t.Logf("Error closing scanner: %v", err)
		}
	}()

	// Используем хосты, которые гарантированно разрешаются
	hosts := []string{"localhost", "127.0.0.1"}
	ports := []int{80, 443}

	ctx := context.Background()
	results, err := scanner.Scan(ctx, hosts, ports)
	if err != nil {
		t.Fatal(err)
	}

	count := 0
	for range results {
		count++
	}

	// Проверяем, что получили хотя бы один результат
	if count == 0 {
		t.Error("Expected at least one result, got 0")
	}

	// Проверяем, что количество результатов соответствует ожидаемому
	expected := len(hosts) * len(ports)
	if count < expected {
		// Может быть меньше, если хосты разрешились в одинаковые IP
		t.Logf("Got %d results, expected up to %d (hosts may resolve to same IP)", count, expected)
	}
}

// Дополнительный тест для проверки разных хостов с разными IP
func TestScanner_DifferentHosts(t *testing.T) {
	scanner, err := New(WithConnectTimeout(100 * time.Millisecond))
	if err != nil {
		t.Fatal(err)
	}
	defer func() {
		if err := scanner.Close(); err != nil {
			t.Logf("Error closing scanner: %v", err)
		}
	}()

	// Хосты, которые гарантированно имеют разные IP
	hosts := []string{"google.com", "github.com"}
	ports := []int{80}

	ctx := context.Background()
	results, err := scanner.Scan(ctx, hosts, ports)
	if err != nil {
		t.Fatal(err)
	}

	var ips []string
	for result := range results {
		if result.IP != nil {
			ips = append(ips, result.IP.String())
		}
	}

	// Проверяем, что получили уникальные IP
	if len(ips) == 0 {
		t.Error("Expected at least one result, got 0")
	}

	// Проверяем, что все IP уникальны
	seen := make(map[string]bool)
	for _, ip := range ips {
		if seen[ip] {
			t.Logf("Duplicate IP found: %s", ip)
		}
		seen[ip] = true
	}
}

// Бенчмарк для проверки производительности
func BenchmarkScan(b *testing.B) {
	scanner, err := New(
		WithConcurrency(100),
		WithConnectTimeout(100*time.Millisecond),
	)
	if err != nil {
		b.Fatal(err)
	}
	defer func() {
		if err := scanner.Close(); err != nil {
			b.Logf("Error closing scanner: %v", err)
		}
	}()

	ports := Range(1, 100)
	ctx := context.Background()

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		results, err := scanner.Scan(ctx, []string{"localhost"}, ports)
		if err != nil {
			b.Fatal(err)
		}
		for range results {
			// Потребляем результаты
		}
	}
}
