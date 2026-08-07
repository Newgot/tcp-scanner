package benchmarks

import (
	"context"
	"testing"
	"time"

	portscan "github.com/Newgot/tcp-scanner"
)

func TestScanBasic(t *testing.T) {
	scanner, err := portscan.New(
		portscan.WithConcurrency(10),
		portscan.WithConnectTimeout(100*time.Millisecond),
	)
	if err != nil {
		t.Fatal(err)
	}
	defer func(scanner *portscan.Scanner) {
		err := scanner.Close()
		if err != nil {
			panic(err)
		}
	}(scanner)

	ctx := context.Background()
	results, err := scanner.Scan(
		ctx,
		[]string{"localhost"},
		portscan.Range(1, 20),
	)
	if err != nil {
		t.Fatal(err)
	}

	count := 0
	for result := range results {
		count++
		t.Logf("Result: %s", result)
	}

	t.Logf("Total results: %d", count)
}

func BenchmarkScanSmall(b *testing.B) {
	scanner, err := portscan.New(
		portscan.WithConcurrency(50),
		portscan.WithConnectTimeout(100*time.Millisecond),
	)
	if err != nil {
		b.Fatal(err)
	}
	defer func(scanner *portscan.Scanner) {
		err := scanner.Close()
		if err != nil {
			panic(err)
		}
	}(scanner)

	ports := portscan.Range(1, 100)

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		ctx := context.Background()
		results, err := scanner.Scan(ctx, []string{"localhost"}, ports)
		if err != nil {
			b.Fatal(err)
		}
		// Потребляем все результаты
		for range results {
		}
	}
}

func BenchmarkScanLarge(b *testing.B) {
	scanner, err := portscan.New(
		portscan.WithConcurrency(500),
		portscan.WithConnectTimeout(50*time.Millisecond),
	)
	if err != nil {
		b.Fatal(err)
	}
	defer func(scanner *portscan.Scanner) {
		err := scanner.Close()
		if err != nil {
			panic(err)
		}
	}(scanner)

	ports := portscan.Range(1, 1000)

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		ctx := context.Background()
		results, err := scanner.Scan(ctx, []string{"localhost"}, ports)
		if err != nil {
			b.Fatal(err)
		}
		// Потребляем все результаты
		for range results {
		}
	}
}

func BenchmarkScanAll(b *testing.B) {
	scanner, err := portscan.New(
		portscan.WithConcurrency(200),
		portscan.WithConnectTimeout(100*time.Millisecond),
	)
	if err != nil {
		b.Fatal(err)
	}
	defer func(scanner *portscan.Scanner) {
		err := scanner.Close()
		if err != nil {
			panic(err)
		}
	}(scanner)

	hosts := []string{"localhost", "127.0.0.1", "::1"}
	ports := portscan.Range(1, 500)

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		ctx := context.Background()
		_, err := scanner.ScanAll(ctx, hosts, ports)
		if err != nil {
			b.Fatal(err)
		}
	}
}
