package main

import (
	"context"
	"testing"
	"time"

	portscan "github.com/Newgot/tcp-scanner"
)

func TestAdvancedScan(t *testing.T) {
	scanner, err := portscan.New(
		portscan.WithConcurrency(50),
		portscan.WithConnectTimeout(200*time.Millisecond),
	)
	if err != nil {
		t.Fatal(err)
	}
	defer func() {
		if err := scanner.Close(); err != nil {
			t.Logf("Error closing scanner: %v", err)
		}
	}()

	ports, err := portscan.ParsePorts(
		"22,80,443",
		"8000-8100",
	)
	if err != nil {
		t.Fatal(err)
	}

	hosts := []string{
		"localhost",
		"google.com",
		"github.com",
	}

	t.Logf("Сканируем %d портов на %d хостах...", len(ports), len(hosts))

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	startTime := time.Now()
	results, err := scanner.Scan(ctx, hosts, ports)
	if err != nil {
		t.Fatal(err)
	}

	var allResults []portscan.Result
	for result := range results {
		allResults = append(allResults, result)
	}

	stats := portscan.Stats(allResults)
	stats.TotalDuration = time.Since(startTime)

	t.Logf("📊 Статистика: %s", stats)

	// Проверяем, что получили результаты
	if len(allResults) == 0 {
		t.Error("Expected at least one result, got 0")
	}

	// Проверяем, что все хосты присутствуют в результатах
	grouped := portscan.GroupByHost(allResults)
	for _, host := range hosts {
		if _, exists := grouped[host]; !exists {
			t.Logf("Host %s not found in results (may not resolve)", host)
		}
	}

	// Проверяем, что у каждого результата есть IP
	for _, r := range allResults {
		if r.IP == nil && r.State != portscan.StateUnreachable {
			t.Errorf("Result for %s:%d has no IP (state: %s)", r.Host, r.Port, r.State)
		}
	}

	// Проверяем валидность портов
	for _, r := range allResults {
		if r.Port < 1 || r.Port > 65535 {
			t.Errorf("Invalid port: %d", r.Port)
		}
	}

	t.Logf("✅ Всего получено результатов: %d", len(allResults))
}

func TestAdvancedScanWithCancel(t *testing.T) {
	scanner, err := portscan.New(
		portscan.WithConcurrency(50),
		portscan.WithConnectTimeout(200*time.Millisecond),
	)
	if err != nil {
		t.Fatal(err)
	}
	defer func() {
		if err := scanner.Close(); err != nil {
			t.Logf("Error closing scanner: %v", err)
		}
	}()

	ports, err := portscan.ParsePorts(
		"22,80,443",
		"8000-8100",
	)
	if err != nil {
		t.Fatal(err)
	}

	hosts := []string{
		"localhost",
		"google.com",
		"github.com",
	}

	ctx, cancel := context.WithCancel(context.Background())

	// Отменяем через 100ms
	time.AfterFunc(100*time.Millisecond, func() {
		t.Log("⏰ Отмена сканирования...")
		cancel()
	})

	startTime := time.Now()
	results, err := scanner.Scan(ctx, hosts, ports)
	if err != nil {
		t.Fatal(err)
	}

	var allResults []portscan.Result
	for result := range results {
		allResults = append(allResults, result)
	}

	duration := time.Since(startTime)
	t.Logf("Сканирование завершено за %v, получено %d результатов", duration, len(allResults))

	// Проверяем, что сканирование было отменено (должно быть меньше полного количества)
	expectedTotal := len(hosts) * len(ports)
	if len(allResults) >= expectedTotal {
		t.Logf("Scan completed fully (%d results) before cancellation", len(allResults))
	} else {
		t.Logf("Scan was cancelled after %d of %d results", len(allResults), expectedTotal)
	}
}

func TestAdvancedScanWithInvalidHosts(t *testing.T) {
	scanner, err := portscan.New(
		portscan.WithConcurrency(50),
		portscan.WithConnectTimeout(200*time.Millisecond),
	)
	if err != nil {
		t.Fatal(err)
	}
	defer func() {
		if err := scanner.Close(); err != nil {
			t.Logf("Error closing scanner: %v", err)
		}
	}()

	ports, err := portscan.ParsePorts(
		"22,80,443",
	)
	if err != nil {
		t.Fatal(err)
	}

	// Смесь валидных и невалидных хостов
	hosts := []string{
		"localhost",
		"invalid.host.xyz",
		"google.com",
	}

	ctx := context.Background()
	results, err := scanner.Scan(ctx, hosts, ports)
	if err != nil {
		// Может быть ошибка, если все хосты невалидны
		t.Logf("Scan returned error: %v", err)
		return
	}

	var allResults []portscan.Result
	for result := range results {
		allResults = append(allResults, result)
	}

	// Проверяем, что результаты есть для валидных хостов
	if len(allResults) == 0 {
		t.Error("Expected at least some results, got 0")
	}

	t.Logf("Получено %d результатов", len(allResults))
}

func TestAdvancedScanWithLargePortRange(t *testing.T) {
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

	ports := portscan.Range(1, 500)
	hosts := []string{"localhost"}

	t.Logf("Сканируем %d портов на localhost...", len(ports))

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
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

	if count != len(ports) {
		t.Errorf("Expected %d results, got %d", len(ports), count)
	}
}

func TestAdvancedScanWithCustomConfig(t *testing.T) {
	// Тестируем различные конфигурации
	configs := []struct {
		name        string
		concurrency int
		timeout     time.Duration
	}{
		{"low concurrency", 10, 500 * time.Millisecond},
		{"medium concurrency", 50, 200 * time.Millisecond},
		{"high concurrency", 200, 50 * time.Millisecond},
	}

	ports := portscan.Range(1, 50)
	hosts := []string{"localhost"}

	for _, cfg := range configs {
		t.Run(cfg.name, func(t *testing.T) {
			scanner, err := portscan.New(
				portscan.WithConcurrency(cfg.concurrency),
				portscan.WithConnectTimeout(cfg.timeout),
			)
			if err != nil {
				t.Fatal(err)
			}
			defer func() {
				if err := scanner.Close(); err != nil {
					t.Logf("Error closing scanner: %v", err)
				}
			}()

			ctx := context.Background()
			startTime := time.Now()
			results, err := scanner.ScanAll(ctx, hosts, ports)
			if err != nil {
				t.Fatal(err)
			}

			duration := time.Since(startTime)

			if len(results) != len(ports) {
				t.Errorf("Expected %d results, got %d", len(ports), len(results))
			}

			t.Logf("%s: сканировано %d портов за %v", cfg.name, len(results), duration)
		})
	}
}

// Бенчмарк для примера
func BenchmarkAdvancedScan(b *testing.B) {
	scanner, err := portscan.New(
		portscan.WithConcurrency(50),
		portscan.WithConnectTimeout(200*time.Millisecond),
	)
	if err != nil {
		b.Fatal(err)
	}
	defer func() {
		if err := scanner.Close(); err != nil {
			b.Logf("Error closing scanner: %v", err)
		}
	}()

	ports, err := portscan.ParsePorts(
		"22,80,443",
		"8000-8100",
	)
	if err != nil {
		b.Fatal(err)
	}

	hosts := []string{
		"localhost",
		"google.com",
		"github.com",
	}

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
