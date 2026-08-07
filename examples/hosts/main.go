package main

import (
	"context"
	"fmt"
	"log"

	portscan "github.com/Newgot/tcp-scanner"
)

func main() {
	fmt.Println("=== Поддержка различных типов хостов ===")
	fmt.Println()

	scanner, err := portscan.New()
	if err != nil {
		log.Fatal(err)
	}
	defer func() {
		if err := scanner.Close(); err != nil {
			log.Printf("Error closing scanner: %v", err)
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

	fmt.Println("📋 Список хостов:")
	for i, h := range hosts {
		fmt.Printf("  %d. %s\n", i+1, h)
	}
	fmt.Println()

	hostsInfo, err := portscan.ValidateHosts(hosts)
	if err != nil {
		fmt.Printf("❌ Ошибка: %v\n", err)
	} else {
		fmt.Println("✅ Валидные хосты:")
		for _, info := range hostsInfo {
			fmt.Printf("  %s (%s): %v\n",
				info.Original,
				info.Type,
				info.Addresses)
		}
		fmt.Println()
	}

	ports := []int{80, 443}

	fmt.Printf("🔍 Сканирование портов %v на валидных хостах...\n", ports)
	fmt.Println()

	ctx := context.Background()
	results, err := scanner.Scan(ctx, hosts, ports)
	if err != nil {
		log.Fatal(err)
	}

	fmt.Println("📊 Результаты:")
	count := 0
	for result := range results {
		count++
		if result.IsOpen() {
			fmt.Printf("  ✅ %s:%d - ОТКРЫТ (IP: %s, %v)\n",
				result.Host, result.Port, result.IP, result.Duration)
		} else {
			fmt.Printf("  ❌ %s:%d - %s (IP: %s, %v)\n",
				result.Host, result.Port, result.State, result.IP, result.Duration)
		}
	}
	fmt.Println()

	if count == 0 {
		fmt.Println("  Нет результатов")
	} else {
		fmt.Printf("✅ Всего получено результатов: %d\n", count)
	}
}
