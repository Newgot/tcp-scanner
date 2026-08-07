// benchmarks/debug_test.go
package benchmarks

import (
	"context"
	"fmt"
	"testing"
	"time"

	"github.com/Newgot/tcp-scanner"
)

func TestDebugScan(t *testing.T) {
	fmt.Println("=== Starting debug scan ===")

	scanner, err := portscan.New(
		portscan.WithConcurrency(5),
		portscan.WithConnectTimeout(200*time.Millisecond),
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

	// Увеличиваем таймаут для отладки
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	ports := portscan.Range(1, 50)
	fmt.Printf("Scanning %d ports...\n", len(ports))

	results, err := scanner.Scan(ctx, []string{"localhost"}, ports)
	if err != nil {
		t.Fatal(err)
	}

	count := 0
	for result := range results {
		count++
		if count%5 == 0 {
			fmt.Printf("Received %d results, last: %s\n", count, result.String())
		}
	}

	fmt.Printf("Total results: %d\n", count)
	fmt.Println("=== Debug scan completed ===")
}
