package main

import (
	"context"
	"testing"
	"time"

	portscan "github.com/Newgot/tcp-scanner"
)

func TestPortRange(t *testing.T) {
	tests := []struct {
		name  string
		start int
		end   int
		want  []int
	}{
		{
			name:  "normal range",
			start: 1,
			end:   10,
			want:  []int{1, 2, 3, 4, 5, 6, 7, 8, 9, 10},
		},
		{
			name:  "reverse range",
			start: 10,
			end:   1,
			want:  []int{1, 2, 3, 4, 5, 6, 7, 8, 9, 10},
		},
		{
			name:  "single port",
			start: 80,
			end:   80,
			want:  []int{80},
		},
		{
			name:  "out of bounds low",
			start: 0,
			end:   10,
			want:  []int{1, 2, 3, 4, 5, 6, 7, 8, 9, 10},
		},
		{
			name:  "out of bounds high",
			start: 65530,
			end:   65540,
			want:  []int{65530, 65531, 65532, 65533, 65534, 65535},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ports := portscan.Range(tt.start, tt.end)
			if len(ports) != len(tt.want) {
				t.Errorf("Range() got %d ports, want %d", len(ports), len(tt.want))
			}
			for i, p := range ports {
				if i < len(tt.want) && p != tt.want[i] {
					t.Errorf("Range() port[%d] = %d, want %d", i, p, tt.want[i])
				}
			}
		})
	}
}

func TestPortsFunction(t *testing.T) {
	tests := []struct {
		name  string
		ports []int
		want  []int
	}{
		{
			name:  "valid ports",
			ports: []int{80, 443, 8080},
			want:  []int{80, 443, 8080},
		},
		{
			name:  "with invalid ports",
			ports: []int{80, 0, 443, 99999, 8080},
			want:  []int{80, 443, 8080},
		},
		{
			name:  "duplicates",
			ports: []int{80, 80, 443, 80, 443},
			want:  []int{80, 443},
		},
		{
			name:  "empty",
			ports: []int{},
			want:  []int{},
		},
		{
			name:  "all invalid",
			ports: []int{0, 99999, -1},
			want:  []int{},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ports := portscan.Ports(tt.ports...)
			if len(ports) != len(tt.want) {
				t.Errorf("Ports() got %d ports, want %d", len(ports), len(tt.want))
			}
			for i, p := range ports {
				if i < len(tt.want) && p != tt.want[i] {
					t.Errorf("Ports() port[%d] = %d, want %d", i, p, tt.want[i])
				}
			}
		})
	}
}

func TestParsePorts(t *testing.T) {
	tests := []struct {
		name    string
		specs   []string
		want    []int
		wantErr bool
	}{
		{
			name:    "single port",
			specs:   []string{"80"},
			want:    []int{80},
			wantErr: false,
		},
		{
			name:    "port range",
			specs:   []string{"1-5"},
			want:    []int{1, 2, 3, 4, 5},
			wantErr: false,
		},
		{
			name:    "reverse range",
			specs:   []string{"10-1"},
			want:    []int{1, 2, 3, 4, 5, 6, 7, 8, 9, 10},
			wantErr: false,
		},
		{
			name:    "multiple specs",
			specs:   []string{"80,443", "1-10"},
			want:    []int{80, 443, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10},
			wantErr: false,
		},
		{
			name:    "duplicates in specs",
			specs:   []string{"80,80", "443,80"},
			want:    []int{80, 443},
			wantErr: false,
		},
		{
			name:    "port 0",
			specs:   []string{"0"},
			want:    nil,
			wantErr: true,
		},
		{
			name:    "port > 65535",
			specs:   []string{"99999"},
			want:    nil,
			wantErr: true,
		},
		{
			name:    "invalid format",
			specs:   []string{"abc"},
			want:    nil,
			wantErr: true,
		},
		{
			name:    "empty spec",
			specs:   []string{""},
			want:    nil,
			wantErr: true,
		},
		{
			name:    "mixed valid and invalid",
			specs:   []string{"80,abc,443"},
			want:    nil,
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ports, err := portscan.ParsePorts(tt.specs...)
			if (err != nil) != tt.wantErr {
				t.Errorf("ParsePorts() error = %v, wantErr %v", err, tt.wantErr)
			}
			if !tt.wantErr {
				if len(ports) != len(tt.want) {
					t.Errorf("ParsePorts() got %d ports, want %d", len(ports), len(tt.want))
				}
				for i, p := range ports {
					if i < len(tt.want) && p != tt.want[i] {
						t.Errorf("ParsePorts() port[%d] = %d, want %d", i, p, tt.want[i])
					}
				}
			}
		})
	}
}

func TestMergePorts(t *testing.T) {
	tests := []struct {
		name  string
		lists [][]int
		want  []int
	}{
		{
			name: "two lists",
			lists: [][]int{
				{1, 2, 3, 4, 5},
				{3, 4, 5, 6, 7},
			},
			want: []int{1, 2, 3, 4, 5, 6, 7},
		},
		{
			name: "three lists",
			lists: [][]int{
				{1, 2, 3},
				{3, 4, 5},
				{5, 6, 7},
			},
			want: []int{1, 2, 3, 4, 5, 6, 7},
		},
		{
			name: "with invalid ports",
			lists: [][]int{
				{1, 2, 0, 3},
				{3, 99999, 4, 5},
			},
			want: []int{1, 2, 3, 4, 5},
		},
		{
			name:  "empty",
			lists: [][]int{},
			want:  []int{},
		},
		{
			name: "list with duplicates",
			lists: [][]int{
				{80, 80, 443, 443},
				{443, 8080, 8080},
			},
			want: []int{80, 443, 8080},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ports := portscan.MergePorts(tt.lists...)
			if len(ports) != len(tt.want) {
				t.Errorf("MergePorts() got %d ports, want %d", len(ports), len(tt.want))
			}
			for i, p := range ports {
				if i < len(tt.want) && p != tt.want[i] {
					t.Errorf("MergePorts() port[%d] = %d, want %d", i, p, tt.want[i])
				}
			}
		})
	}
}

func TestValidatePorts(t *testing.T) {
	tests := []struct {
		name    string
		ports   []int
		wantErr bool
	}{
		{
			name:    "valid ports",
			ports:   []int{80, 443, 8080},
			wantErr: false,
		},
		{
			name:    "port 0",
			ports:   []int{0, 80, 443},
			wantErr: true,
		},
		{
			name:    "port > 65535",
			ports:   []int{80, 99999, 443},
			wantErr: true,
		},
		{
			name:    "empty list",
			ports:   []int{},
			wantErr: true,
		},
		{
			name:    "negative port",
			ports:   []int{-1, 80},
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := portscan.ValidatePorts(tt.ports)
			if (err != nil) != tt.wantErr {
				t.Errorf("ValidatePorts() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}

func TestScanWithVariousPorts(t *testing.T) {
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

	testCases := []struct {
		name  string
		ports []int
	}{
		{"single port", []int{80}},
		{"multiple ports", []int{80, 443, 8080}},
		{"range", portscan.Range(1, 10)},
		{"mixed", portscan.Ports(22, 80, 443, 8080)},
		{"large range", portscan.Range(1, 100)},
	}

	hosts := []string{"localhost"}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			ctx := context.Background()
			results, err := scanner.Scan(ctx, hosts, tc.ports)
			if err != nil {
				t.Fatal(err)
			}

			count := 0
			for range results {
				count++
			}

			if count != len(tc.ports) {
				t.Errorf("Expected %d results, got %d", len(tc.ports), count)
			}
			t.Logf("Сканировано %d портов", count)
		})
	}
}

func TestScanWithCombinedPorts(t *testing.T) {
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

	// Используем тот же набор портов, что и в примере
	allPorts, err := portscan.ParsePorts("22,80,443", "8000-8005")
	if err != nil {
		t.Fatal(err)
	}

	t.Logf("Комбинированные порты: %d портов", len(allPorts))

	ctx := context.Background()
	results, err := scanner.Scan(ctx, []string{"localhost"}, allPorts)
	if err != nil {
		t.Fatal(err)
	}

	count := 0
	for range results {
		count++
	}

	if count != len(allPorts) {
		t.Errorf("Expected %d results, got %d", len(allPorts), count)
	}
	t.Logf("✅ Сканировано %d портов", count)
}

func TestPortSpecValidation(t *testing.T) {
	// Тестируем комбинации портов
	tests := []struct {
		name    string
		ports   []int
		wantErr bool
	}{
		{
			name:    "all ports range",
			ports:   portscan.Range(1, 65535),
			wantErr: false,
		},
		{
			name:    "ports with duplicates",
			ports:   portscan.Ports(80, 80, 443, 443, 8080),
			wantErr: false,
		},
		{
			name:    "ports with invalid",
			ports:   portscan.Ports(80, 0, 443, 99999, 8080),
			wantErr: false, // Ports() фильтрует невалидные порты
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := portscan.ValidatePorts(tt.ports)
			if (err != nil) != tt.wantErr {
				t.Errorf("ValidatePorts() error = %v, wantErr %v", err, tt.wantErr)
			}
			if !tt.wantErr && len(tt.ports) > 0 {
				t.Logf("Валидация прошла для %d портов", len(tt.ports))
			}
		})
	}
}

// Бенчмарк для разных способов создания портов
func BenchmarkRange(b *testing.B) {
	for i := 0; i < b.N; i++ {
		_ = portscan.Range(1, 1000)
	}
}

func BenchmarkPorts(b *testing.B) {
	ports := []int{22, 80, 443, 8080, 8443, 3306, 5432, 6379}
	for i := 0; i < b.N; i++ {
		_ = portscan.Ports(ports...)
	}
}

func BenchmarkParsePorts(b *testing.B) {
	specs := []string{"22,80,443", "8000-8100", "9000-9020"}
	for i := 0; i < b.N; i++ {
		_, _ = portscan.ParsePorts(specs...)
	}
}

func BenchmarkMergePorts(b *testing.B) {
	list1 := portscan.Range(1, 500)
	list2 := portscan.Range(501, 1000)
	for i := 0; i < b.N; i++ {
		_ = portscan.MergePorts(list1, list2)
	}
}

// Бенчмарк сканирования с разными наборами портов
func BenchmarkScanWithPorts(b *testing.B) {
	scanner, err := portscan.New(
		portscan.WithConcurrency(50),
		portscan.WithConnectTimeout(50*time.Millisecond),
	)
	if err != nil {
		b.Fatal(err)
	}
	defer func() {
		if err := scanner.Close(); err != nil {
			b.Logf("Error closing scanner: %v", err)
		}
	}()

	ports := portscan.Range(1, 100)
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
