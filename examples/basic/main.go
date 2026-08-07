package main

import (
	"context"
	"fmt"
	"log"

	portscan "github.com/Newgot/tcp-scanner"
)

func main() {
	fmt.Println("=== Базовое сканирование портов ===\n")

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

	// Сканируем популярные порты
	ports := []int{22, 80, 443, 3306, 5432, 6379, 8080, 8443}

	ctx := context.Background()
	results, err := scanner.Scan(ctx, []string{"localhost"}, ports)
	if err != nil {
		log.Fatal(err)
	}

	fmt.Println("Результаты сканирования:")
	for result := range results {
		if result.IsOpen() {
			fmt.Printf("✅ %s - ОТКРЫТ (IP: %s, %v)\n",
				result, result.IP, result.Duration)
		} else {
			fmt.Printf("❌ %s (IP: %s, %v)\n",
				result, result.IP, result.Duration)
		}
	}
}
