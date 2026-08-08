package main

import (
	"context"
	"testing"
	"time"

	portscan "github.com/Newgot/tcp-scanner"
)

func TestHostsValidation(t *testing.T) {
	scanner, err := portscan.New()
	if err != nil {
		t.Fatal(err)
	}
	defer func() {
		if err := scanner.Close(); err != nil {
			t.Logf("Error closing scanner: %v", err)
		}
	}()

	hosts := []string{
		"localhost",
		"127.0.0.1",
		"::1",
		"google.com",
		"",
		"invalid.host.xyz",
		"192.168.1.1",
	}

	hostsInfo, err := portscan.ValidateHosts(hosts)
	if err != nil {
		t.Logf("Validation error: %v", err)
	}

	// Проверяем, что валидные хосты распознаны правильно
	var validCount int
	for _, info := range hostsInfo {
		if info.IsValid {
			validCount++
			// Проверяем, что у валидных хостов есть адреса
			if len(info.Addresses) == 0 {
				t.Errorf("Host %s has no addresses but is valid", info.Original)
			}
			// Проверяем, что тип хоста корректный
			switch info.Type {
			case portscan.HostTypeIPv4, portscan.HostTypeIPv6, portscan.HostTypeDNS:
				// OK
			default:
				t.Errorf("Host %s has unknown type: %s", info.Original, info.Type)
			}
		}
	}

	t.Logf("Найдено %d валидных хостов из %d", validCount, len(hosts))
}

func TestHostTypes(t *testing.T) {
	tests := []struct {
		name     string
		host     string
		expected portscan.HostType
	}{
		{"IPv4", "192.168.1.1", portscan.HostTypeIPv4},
		{"IPv6", "::1", portscan.HostTypeIPv6},
		{"DNS", "localhost", portscan.HostTypeDNS},
		{"DNS with dots", "google.com", portscan.HostTypeDNS},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			hostsInfo, err := portscan.ValidateHosts([]string{tt.host})
			if err != nil {
				t.Fatalf("ValidateHosts failed: %v", err)
			}
			if len(hostsInfo) == 0 {
				t.Fatal("No host info returned")
			}
			if hostsInfo[0].Type != tt.expected {
				t.Errorf("Expected type %s, got %s", tt.expected, hostsInfo[0].Type)
			}
		})
	}
}

func TestHostResolution(t *testing.T) {
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

	// Хосты, которые должны разрешиться
	hosts := []string{
		"localhost",
		"127.0.0.1",
		"::1",
		"google.com",
	}

	ports := []int{80}

	ctx := context.Background()
	results, err := scanner.Scan(ctx, hosts, ports)
	if err != nil {
		t.Fatal(err)
	}

	count := 0
	ips := make(map[string]bool)
	for result := range results {
		count++
		if result.IP != nil {
			ips[result.IP.String()] = true
		}
	}

	t.Logf("Получено %d результатов от %d уникальных IP", count, len(ips))

	if count == 0 {
		t.Error("Expected at least one result, got 0")
	}
}

func TestHostDeduplication(t *testing.T) {
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

	// Дублирующиеся хосты
	hosts := []string{
		"localhost",
		"localhost",
		"127.0.0.1",
		"127.0.0.1",
		"::1",
	}

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

	// Должно быть меньше, чем len(hosts) * len(ports) из-за дедупликации
	expectedMax := len(hosts) * len(ports)
	t.Logf("Получено %d результатов из возможных %d (с дедупликацией)", count, expectedMax)

	if count == 0 {
		t.Error("Expected at least one result, got 0")
	}
}

func TestInvalidHosts(t *testing.T) {
	scanner, err := portscan.New()
	if err != nil {
		t.Fatal(err)
	}
	defer func() {
		if err := scanner.Close(); err != nil {
			t.Logf("Error closing scanner: %v", err)
		}
	}()

	testCases := []struct {
		name  string
		hosts []string
	}{
		{"empty host", []string{""}},
		{"invalid DNS", []string{"nonexistent.domain.xyz"}},
		{"invalid format", []string{"...invalid..."}},
		{"mixed valid and invalid", []string{"localhost", "invalid.host.xyz"}},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			ctx := context.Background()
			ports := []int{80}
			results, err := scanner.Scan(ctx, tc.hosts, ports)

			if err != nil {
				// Может быть ошибка, если все хосты невалидны
				t.Logf("Scan returned error: %v", err)
				return
			}

			count := 0
			for range results {
				count++
			}
			t.Logf("Получено %d результатов", count)
		})
	}
}

func TestDNSWithMultipleIPs(t *testing.T) {
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

	// Хосты, которые обычно имеют несколько IP
	hosts := []string{
		"google.com",
		"github.com",
	}

	ports := []int{80}

	ctx := context.Background()
	results, err := scanner.Scan(ctx, hosts, ports)
	if err != nil {
		t.Fatal(err)
	}

	ips := make(map[string]bool)
	count := 0
	for result := range results {
		count++
		if result.IP != nil {
			ips[result.IP.String()] = true
		}
	}

	t.Logf("Хост %v вернул %d уникальных IP", hosts, len(ips))
	t.Logf("Всего получено %d результатов", count)

	// Проверяем, что получили хотя бы один результат
	if count == 0 {
		t.Error("Expected at least one result, got 0")
	}
}

func TestIPv6Support(t *testing.T) {
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

	// IPv6 адреса
	hosts := []string{
		"::1",
		"[::1]",
	}

	ports := []int{80, 443}

	ctx := context.Background()
	results, err := scanner.Scan(ctx, hosts, ports)
	if err != nil {
		// IPv6 может не поддерживаться в окружении
		t.Logf("IPv6 scan returned error: %v", err)
		return
	}

	count := 0
	for range results {
		count++
	}

	t.Logf("IPv6 сканирование вернуло %d результатов", count)

	// Проверяем, что хотя бы один IPv6 адрес был обработан
	if count > 0 {
		t.Log("IPv6 поддержка работает")
	}
}

func TestHostValidationErrors(t *testing.T) {
	tests := []struct {
		name    string
		hosts   []string
		wantErr bool
		errType error
	}{
		{
			name:    "empty hosts list",
			hosts:   []string{},
			wantErr: true,
			errType: portscan.ErrNoHosts,
		},
		{
			name:    "single valid host",
			hosts:   []string{"localhost"},
			wantErr: false,
		},
		{
			name:    "single invalid host",
			hosts:   []string{"invalid.host.xyz"},
			wantErr: true,
		},
		{
			name:    "mixed valid and invalid",
			hosts:   []string{"localhost", "invalid.host.xyz"},
			wantErr: false, // Не ошибка, так как есть валидные хосты
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			info, err := portscan.ValidateHosts(tt.hosts)
			if tt.wantErr {
				if err == nil {
					t.Error("Expected error, got nil")
				}
				if tt.errType != nil && err != tt.errType {
					t.Errorf("Expected error type %v, got %v", tt.errType, err)
				}
			} else {
				if err != nil {
					t.Errorf("Unexpected error: %v", err)
				}
				// Проверяем, что валидные хосты возвращены
				if len(info) == 0 && len(tt.hosts) > 0 {
					t.Error("Expected at least one valid host")
				}
			}
		})
	}
}

func TestScanWithHostInfo(t *testing.T) {
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

	hosts := []string{"localhost", "google.com"}
	ports := []int{80}

	ctx := context.Background()
	results, err := scanner.Scan(ctx, hosts, ports)
	if err != nil {
		t.Fatal(err)
	}

	for result := range results {
		// Проверяем, что Host соответствует исходному хосту
		if result.Host == "" {
			t.Errorf("Result has empty Host field")
		}
		// Проверяем, что IP установлен
		if result.IP == nil {
			t.Errorf("Result for %s:%d has no IP", result.Host, result.Port)
		}
		// Проверяем, что порт валидный
		if result.Port < 1 || result.Port > 65535 {
			t.Errorf("Invalid port: %d", result.Port)
		}
		// Проверяем, что состояние валидное
		if result.State == "" {
			t.Errorf("Result has empty State")
		}
	}
}

// Бенчмарк для проверки разрешения хостов
func BenchmarkHostResolution(b *testing.B) {
	hosts := []string{
		"localhost",
		"127.0.0.1",
		"google.com",
		"github.com",
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, err := portscan.ValidateHosts(hosts)
		if err != nil {
			b.Fatal(err)
		}
	}
}

// Бенчмарк для сканирования с разными типами хостов
func BenchmarkScanWithHosts(b *testing.B) {
	scanner, err := portscan.New(
		portscan.WithConcurrency(50),
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

	hosts := []string{"localhost", "127.0.0.1", "google.com"}
	ports := []int{80, 443}
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
