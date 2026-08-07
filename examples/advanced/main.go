package main

import (
	"context"
	"fmt"
	"log"
	"time"

	portscan "github.com/Newgot/tcp-scanner"
)

func main() {
	fmt.Println("=== Расширенное сканирование портов ===")

	// Создаем сканер с пользовательскими настройками
	scanner, err := portscan.New(
		portscan.WithConcurrency(50),                      // 50 одновременных проверок
		portscan.WithConnectTimeout(200*time.Millisecond), // 200мс таймаут
	)
	if err != nil {
		log.Fatal(err)
	}
	defer func(scanner *portscan.Scanner) {
		err := scanner.Close()
		if err != nil {
			panic(err)
		}
	}(scanner)

	// Парсим сложную спецификацию портов
	ports, err := portscan.ParsePorts(
		"22,80,443", // отдельные порты
		"8000-8100", // диапазон
		"9000-9100", // другой диапазон
	)
	if err != nil {
		log.Fatal(err)
	}

	// Сканируем несколько хостов
	hosts := []string{
		"localhost",
		"127.0.0.1",
		"::1",
	}

	fmt.Printf("\nСканируем %d портов на %d хостах...\n", len(ports), len(hosts))

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	results, err := scanner.Scan(ctx, hosts, ports)
	if err != nil {
		log.Fatal(err)
	}

	// Собираем результаты
	var allResults []portscan.Result
	for result := range results {
		allResults = append(allResults, result)
	}

	// Статистика
	stats := portscan.Stats(allResults)
	fmt.Printf("\n📊 Статистика:\n%s\n", stats)

	// Только открытые порты
	openPorts := portscan.OpenPorts(allResults)
	if len(openPorts) > 0 {
		fmt.Println("\n✅ Открытые порты:")
		for _, r := range openPorts {
			fmt.Printf("  %s\n", r)
		}
	} else {
		fmt.Println("\n❌ Открытых портов не найдено")
	}

	// Группировка по хостам
	grouped := portscan.GroupByHost(allResults)
	fmt.Println("\n📋 Результаты по хостам:")
	for host, results := range grouped {
		fmt.Printf("\n  %s: %d портов\n", host, len(results))
	}
}
