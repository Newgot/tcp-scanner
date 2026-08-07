package benchmarks

import (
	"context"
	"testing"
	"time"

	"github.com/Newgot/tcp-scanner"
)

func BenchmarkScanConcurrency10(b *testing.B) {
	scanner, err := portscan.New(
		portscan.WithConcurrency(10),
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
	ctx := context.Background()

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		results, err := scanner.Scan(ctx, []string{"localhost"}, ports)
		if err != nil {
			b.Fatal(err)
		}
		for range results {
		}
	}
}

func BenchmarkScanConcurrency100(b *testing.B) {
	scanner, err := portscan.New(
		portscan.WithConcurrency(100),
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
	ctx := context.Background()

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		results, err := scanner.Scan(ctx, []string{"localhost"}, ports)
		if err != nil {
			b.Fatal(err)
		}
		for range results {
		}
	}
}

func BenchmarkScanConcurrency500(b *testing.B) {
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

	ports := portscan.Range(1, 100)
	ctx := context.Background()

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		results, err := scanner.Scan(ctx, []string{"localhost"}, ports)
		if err != nil {
			b.Fatal(err)
		}
		for range results {
		}
	}
}

func BenchmarkScanLargePorts(b *testing.B) {
	scanner, err := portscan.New(
		portscan.WithConcurrency(200),
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
	ctx := context.Background()

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		results, err := scanner.Scan(ctx, []string{"localhost"}, ports)
		if err != nil {
			b.Fatal(err)
		}
		for range results {
		}
	}
}

func BenchmarkScanMultipleHosts(b *testing.B) {
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
	ports := portscan.Range(1, 100)
	ctx := context.Background()

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		results, err := scanner.Scan(ctx, hosts, ports)
		if err != nil {
			b.Fatal(err)
		}
		for range results {
		}
	}
}
