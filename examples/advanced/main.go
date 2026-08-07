package main

import (
	"context"
	"fmt"
	"log"
	"time"

	portscan "github.com/Newgot/tcp-scanner"
)

func main() {
	fmt.Println("=== Расширенное сканирование с детальной информацией ===")

	scanner, err := portscan.New(
		portscan.WithConcurrency(50),
		portscan.WithConnectTimeout(200*time.Millisecond),
	)
	if err != nil {
		log.Fatal(err)
	}
	defer func() {
		if err := scanner.Close(); err != nil {
			log.Printf("Error closing scanner: %v", err)
		}
	}()

	ports, err := portscan.ParsePorts(
		"22,80,443",
		"8000-8100",
	)
	if err != nil {
		log.Fatal(err)
	}

	hosts := []string{
		"localhost",
		"google.com",
		"github.com",
	}

	fmt.Printf("Сканируем %d портов на %d хостах...\n\n", len(ports), len(hosts))

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	startTime := time.Now()
	results, err := scanner.Scan(ctx, hosts, ports)
	if err != nil {
		log.Fatal(err)
	}

	var allResults []portscan.Result
	for result := range results {
		allResults = append(allResults, result)
	}

	stats := portscan.Stats(allResults)
	stats.TotalDuration = time.Since(startTime)

	fmt.Printf("📊 Статистика:\n%s\n\n", stats)

	fmt.Println("📋 Детальные результаты:")

	grouped := portscan.GroupByHost(allResults)
	for host, results := range grouped {
		fmt.Printf("\n🌐 %s:\n", host)

		var openPorts []portscan.Result
		var closedPorts []portscan.Result

		for _, r := range results {
			if r.IsOpen() {
				openPorts = append(openPorts, r)
			} else {
				closedPorts = append(closedPorts, r)
			}
		}

		if len(openPorts) > 0 {
			fmt.Printf("   ✅ Открытые порты:\n")
			for _, r := range openPorts {
				fmt.Printf("      %d (IP: %s, %v) [%v]\n",
					r.Port, r.IP, r.State, r.Duration)
			}
		}

		if len(closedPorts) > 0 {
			fmt.Printf("   ❌ Закрытые/ошибочные порты:\n")
			for _, r := range closedPorts {
				if r.Error != nil {
					fmt.Printf("      %d: %s (IP: %s, %v) [%v]\n",
						r.Port, r.State, r.IP, r.Duration, r.Error)
				} else {
					fmt.Printf("      %d: %s (IP: %s, %v)\n",
						r.Port, r.State, r.IP, r.Duration)
				}
			}
		}
	}
}
