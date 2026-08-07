package main

import (
	"context"
	"fmt"
	"log"

	portscan "github.com/Newgot/tcp-scanner"
)

func main() {
	fmt.Println("=== Поддержка различных типов хостов ===\n")

	scanner, err := portscan.New()
	if err != nil {
		log.Fatal(err)
	}
	defer func(scanner *portscan.Scanner) {
		err := scanner.Close()
		if err != nil {
			panic(err)
		}
	}(scanner)

	// Тестовые хосты
	hosts := []string{
		"localhost",        // DNS имя
		"127.0.0.1",        // IPv4
		"::1",              // IPv6
		"google.com",       // DNS с несколькими IP
		"",                 // Пустой хост (будет проигнорирован)
		"invalid.host.xyz", // Невалидный хост
		"192.168.1.1",      // IPv4
	}

	fmt.Println("📋 Список хостов:")
	for i, h := range hosts {
		fmt.Printf("  %d. %s\n", i+1, h)
	}

	// Разрешаем хосты
	hostsInfo, err := portscan.ValidateHosts(hosts)
	if err != nil {
		fmt.Printf("\n❌ Ошибка: %v\n", err)
	} else {
		fmt.Println("\n✅ Валидные хосты:")
		for _, info := range hostsInfo {
			fmt.Printf("  %s (%s): %v\n",
				info.Original,
				info.Type,
				info.Addresses)
		}
	}

	// Сканируем порты
	ports := []int{80, 443}

	fmt.Printf("\n🔍 Сканирование портов %v на валидных хостах...\n", ports)

	ctx := context.Background()
	results, err := scanner.Scan(ctx, hosts, ports)
	if err != nil {
		log.Fatal(err)
	}

	fmt.Println("\n📊 Результаты:")
	count := 0
	for result := range results {
		count++
		if result.IsOpen() {
			fmt.Printf("  ✅ %s:%d - ОТКРЫТ\n", result.Host, result.Port)
		} else {
			fmt.Printf("  ❌ %s:%d - %s\n", result.Host, result.Port, result.State)
		}
	}

	if count == 0 {
		fmt.Println("  Нет результатов")
	}
}
