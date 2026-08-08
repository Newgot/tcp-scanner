package main

import (
	"context"
	"fmt"
	"testing"
	"time"

	portscan "github.com/Newgot/tcp-scanner"
)

func TestBasicScan(t *testing.T) {
	scanner, err := portscan.New()
	if err != nil {
		t.Fatal(err)
	}
	defer func() {
		if err := scanner.Close(); err != nil {
			t.Logf("Error closing scanner: %v", err)
		}
	}()

	ports := []int{22, 80, 443, 3306, 5432, 6379, 8080, 8443}
	hosts := []string{"localhost"}

	ctx := context.Background()
	results, err := scanner.Scan(ctx, hosts, ports)
	if err != nil {
		t.Fatal(err)
	}

	var allResults []portscan.Result
	for result := range results {
		allResults = append(allResults, result)
	}

	// Проверяем, что получили результаты для всех портов
	if len(allResults) != len(ports) {
		t.Errorf("Expected %d results, got %d", len(ports), len(allResults))
	}

	// Проверяем, что у каждого результата есть IP
	for _, r := range allResults {
		if r.IP == nil {
			t.Errorf("Result for %s:%d has no IP", r.Host, r.Port)
		}
	}

	// Проверяем, что все порты валидны
	for _, r := range allResults {
		if r.Port < 1 || r.Port > 65535 {
			t.Errorf("Invalid port: %d", r.Port)
		}
	}

	// Проверяем, что все результаты имеют корректное состояние
	validStates := map[portscan.State]bool{
		portscan.StateOpen:        true,
		portscan.StateClosed:      true,
		portscan.StateTimeout:     true,
		portscan.StateUnreachable: true,
		portscan.StateFiltered:    true,
		portscan.StateCanceled:    true,
		portscan.StateError:       true,
	}
	for _, r := range allResults {
		if !validStates[r.State] {
			t.Errorf("Invalid state for %s:%d: %s", r.Host, r.Port, r.State)
		}
	}

	t.Logf("✅ Всего получено результатов: %d", len(allResults))
}

func TestBasicScanWithInvalidHost(t *testing.T) {
	scanner, err := portscan.New()
	if err != nil {
		t.Fatal(err)
	}
	defer func() {
		if err := scanner.Close(); err != nil {
			t.Logf("Error closing scanner: %v", err)
		}
	}()

	ports := []int{80, 443}
	hosts := []string{"invalid.host.xyz"}

	ctx := context.Background()
	results, err := scanner.Scan(ctx, hosts, ports)
	if err != nil {
		// Ожидаемая ошибка - хост не разрешается
		t.Logf("Expected error: %v", err)
		return
	}

	// Если ошибки нет, проверяем что результаты пустые
	count := 0
	for range results {
		count++
	}
	if count > 0 {
		t.Errorf("Expected 0 results for invalid host, got %d", count)
	}
}

func TestBasicScanWithEmptyHosts(t *testing.T) {
	scanner, err := portscan.New()
	if err != nil {
		t.Fatal(err)
	}
	defer func() {
		if err := scanner.Close(); err != nil {
			t.Logf("Error closing scanner: %v", err)
		}
	}()

	ports := []int{80, 443}
	hosts := []string{}

	ctx := context.Background()
	_, err = scanner.Scan(ctx, hosts, ports)
	if err == nil {
		t.Error("Expected error for empty hosts, got nil")
	}
	if err != portscan.ErrNoHosts {
		t.Errorf("Expected ErrNoHosts, got %v", err)
	}
}

func TestBasicScanWithEmptyPorts(t *testing.T) {
	scanner, err := portscan.New()
	if err != nil {
		t.Fatal(err)
	}
	defer func() {
		if err := scanner.Close(); err != nil {
			t.Logf("Error closing scanner: %v", err)
		}
	}()

	ports := []int{}
	hosts := []string{"localhost"}

	ctx := context.Background()
	_, err = scanner.Scan(ctx, hosts, ports)
	if err == nil {
		t.Error("Expected error for empty ports, got nil")
	}
	if err != portscan.ErrNoPorts {
		t.Errorf("Expected ErrNoPorts, got %v", err)
	}
}

func TestBasicScanWithInvalidPort(t *testing.T) {
	scanner, err := portscan.New()
	if err != nil {
		t.Fatal(err)
	}
	defer func() {
		if err := scanner.Close(); err != nil {
			t.Logf("Error closing scanner: %v", err)
		}
	}()

	ports := []int{80, 99999, 443}
	hosts := []string{"localhost"}

	ctx := context.Background()
	_, err = scanner.Scan(ctx, hosts, ports)
	if err == nil {
		t.Error("Expected error for invalid port, got nil")
	}
}

func TestBasicScanWithContextTimeout(t *testing.T) {
	scanner, err := portscan.New(
		portscan.WithConcurrency(10),
		portscan.WithConnectTimeout(50*time.Millisecond),
	)
	if err != nil {
		t.Fatal(err)
	}
	defer func() {
		if err := scanner.Close(); err != nil {
			t.Logf("Error closing scanner: %v", err)
		}
	}()

	ports := portscan.Range(1, 100)
	hosts := []string{"localhost"}

	ctx, cancel := context.WithTimeout(context.Background(), 100*time.Millisecond)
	defer cancel()

	startTime := time.Now()
	results, err := scanner.Scan(ctx, hosts, ports)
	if err != nil {
		t.Fatal(err)
	}

	count := 0
	for range results {
		count++
	}

	duration := time.Since(startTime)
	t.Logf("Сканировано %d портов за %v", count, duration)

	// Проверяем, что сканирование завершилось за разумное время
	if duration > 200*time.Millisecond {
		t.Logf("Scan took %v, may have been slower than expected", duration)
	}
}

func TestBasicScanWithCancel(t *testing.T) {
	scanner, err := portscan.New(
		portscan.WithConcurrency(10),
		portscan.WithConnectTimeout(1*time.Second),
	)
	if err != nil {
		t.Fatal(err)
	}
	defer func() {
		if err := scanner.Close(); err != nil {
			t.Logf("Error closing scanner: %v", err)
		}
	}()

	ports := portscan.Range(1, 1000)
	hosts := []string{"localhost"}

	ctx, cancel := context.WithCancel(context.Background())

	// Отменяем через 10ms
	time.AfterFunc(10*time.Millisecond, func() {
		t.Log("⏰ Отмена сканирования...")
		cancel()
	})

	startTime := time.Now()
	results, err := scanner.Scan(ctx, hosts, ports)
	if err != nil {
		t.Fatal(err)
	}

	count := 0
	for range results {
		count++
	}

	duration := time.Since(startTime)
	t.Logf("Сканирование завершено за %v, получено %d результатов", duration, count)

	// Должно быть меньше 1000, так как отмена произошла
	if count >= 1000 {
		t.Errorf("Expected less than 1000 results after cancel, got %d", count)
	}
}

func TestBasicScanMultipleHosts(t *testing.T) {
	scanner, err := portscan.New(
		portscan.WithConnectTimeout(100 * time.Millisecond),
	)
	if err != nil {
		t.Fatal(err)
	}
	defer func() {
		if err := scanner.Close(); err != nil {
			t.Logf("Error closing scanner: %v", err)
		}
	}()

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

	t.Logf("Получено %d результатов для хостов %v", count, hosts)

	if count == 0 {
		t.Error("Expected at least one result, got 0")
	}
}

func TestBasicScanWithDuplicates(t *testing.T) {
	scanner, err := portscan.New(
		portscan.WithConnectTimeout(100 * time.Millisecond),
	)
	if err != nil {
		t.Fatal(err)
	}
	defer func() {
		if err := scanner.Close(); err != nil {
			t.Logf("Error closing scanner: %v", err)
		}
	}()

	// Дублирующиеся хосты и порты
	hosts := []string{"localhost", "localhost", "127.0.0.1"}
	ports := []int{80, 80, 443}

	ctx := context.Background()
	results, err := scanner.Scan(ctx, hosts, ports)
	if err != nil {
		t.Fatal(err)
	}

	count := 0
	for range results {
		count++
	}

	// Должны быть уникальные комбинации
	t.Logf("Получено %d результатов с дублирующимися входами", count)

	if count == 0 {
		t.Error("Expected at least one result, got 0")
	}
}

// Тест на производительность
func TestBasicScanPerformance(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping performance test in short mode")
	}

	scanner, err := portscan.New(
		portscan.WithConcurrency(100),
		portscan.WithConnectTimeout(50*time.Millisecond),
	)
	if err != nil {
		t.Fatal(err)
	}
	defer func() {
		if err := scanner.Close(); err != nil {
			t.Logf("Error closing scanner: %v", err)
		}
	}()

	ports := portscan.Range(1, 100)
	hosts := []string{"localhost"}

	ctx := context.Background()
	startTime := time.Now()

	results, err := scanner.Scan(ctx, hosts, ports)
	if err != nil {
		t.Fatal(err)
	}

	count := 0
	for range results {
		count++
	}

	duration := time.Since(startTime)
	t.Logf("Сканировано %d портов за %v", count, duration)

	// Проверяем производительность (должно быть не слишком медленно)
	if duration > 5*time.Second && count > 0 {
		t.Logf("Scan took %v, which might be slow for %d ports", duration, count)
	}
}

// Бенчмарк для базового сканирования
func BenchmarkBasicScan(b *testing.B) {
	scanner, err := portscan.New(
		portscan.WithConcurrency(100),
		portscan.WithConnectTimeout(100*time.Millisecond),
	)
	if err != nil {
		b.Fatal(err)
	}
	defer func() {
		if err := scanner.Close(); err != nil {
			b.Logf("Error closing scanner: %v", err)
		}
	}()

	ports := []int{22, 80, 443, 3306, 5432, 6379, 8080, 8443}
	hosts := []string{"localhost"}
	ctx := context.Background()

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		results, err := scanner.Scan(ctx, hosts, ports)
		if err != nil {
			b.Fatal(err)
		}
		for range results {
			// Потребляем результаты
		}
	}
}

// Бенчмарк с разными уровнями конкурентности
func BenchmarkBasicScanConcurrency(b *testing.B) {
	concurrencies := []int{10, 50, 100, 200}

	for _, c := range concurrencies {
		b.Run(fmt.Sprintf("concurrency_%d", c), func(b *testing.B) {
			scanner, err := portscan.New(
				portscan.WithConcurrency(c),
				portscan.WithConnectTimeout(100*time.Millisecond),
			)
			if err != nil {
				b.Fatal(err)
			}
			defer func() {
				if err := scanner.Close(); err != nil {
					b.Logf("Error closing scanner: %v", err)
				}
			}()

			ports := []int{22, 80, 443, 3306, 5432, 6379, 8080, 8443}
			hosts := []string{"localhost"}
			ctx := context.Background()

			b.ResetTimer()
			for i := 0; i < b.N; i++ {
				results, err := scanner.Scan(ctx, hosts, ports)
				if err != nil {
					b.Fatal(err)
				}
				for range results {
					// Потребляем результаты
				}
			}
		})
	}
}
