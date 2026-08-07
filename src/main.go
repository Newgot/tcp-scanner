package main

import (
	"context"
	"fmt"
	"log"

	"github.com/Newgot/tcp-scanner/internal/portscan"
)

func main() {
	// Создаем сканер с настройками по умолчанию
	scanner, err := portscan.New()
	if err != nil {
		log.Fatal(err)
	}
	defer scanner.Close()

	// Сканируем порты
	results, err := scanner.Scan(
		context.Background(),
		[]string{"localhost"},
		scanner.Range(1, 1000),
	)
	if err != nil {
		log.Fatal(err)
	}

	// Обрабатываем результаты
	for result := range results {
		fmt.Printf("%s:%d %s\n", result.Host, result.Port, result.State)
	}
}
