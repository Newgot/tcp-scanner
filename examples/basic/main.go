package main

import (
	"context"
	"fmt"
	"log"

	portscan "github.com/Newgot/tcp-scanner"
)

func main() {
	fmt.Println("=== Базовое сканирование портов ===")

	// Создаем сканер с настройками по умолчанию
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

	// Сканируем популярные порты на localhost
	ports := []int{22, 80, 443, 3306, 5432, 6379, 8080, 8443}

	ctx := context.Background()
	results, err := scanner.Scan(ctx, []string{"localhost"}, ports)
	if err != nil {
		log.Fatal(err)
	}

	fmt.Println("\nРезультаты сканирования:")
	for result := range results {
		if result.IsOpen() {
			fmt.Printf("✅ %s - ОТКРЫТ\n", result)
		} else {
			fmt.Printf("❌ %s\n", result)
		}
	}
}
