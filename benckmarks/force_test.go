// benchmarks/force_test.go
package benchmarks

import (
	"context"
	"fmt"
	"testing"
	"time"

	"github.com/Newgot/tcp-scanner"
)

func TestForceScan(t *testing.T) {
	fmt.Println("=== Starting force scan ===")

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

	ctx, cancel := context.WithCancel(context.Background())

	// Отменяем через 2 секунды
	go func() {
		time.Sleep(2 * time.Second)
		fmt.Println("=== Canceling context ===")
		cancel()
	}()

	ports := portscan.Range(1, 100)
	results, err := scanner.Scan(ctx, []string{"localhost"}, ports)
	if err != nil {
		t.Fatal(err)
	}

	count := 0
	for result := range results {
		count++
		if count%10 == 0 {
			fmt.Printf("Received %d results\n", count)
		}
		_ = result // Используем переменную
	}

	fmt.Printf("Total results: %d\n", count)
	fmt.Println("=== Force scan completed ===")
}
