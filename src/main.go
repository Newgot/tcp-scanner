package main

import (
	"context"
	"fmt"
	"log"

	portscan "github.com/Newgot/tcp-scanner"
)

func main() {
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

	// Сканируем порты
	results, err := scanner.Scan(
		context.Background(),
		[]string{"localhost"},
		portscan.Range(1, 1000),
	)
	if err != nil {
		log.Fatal(err)
	}

	// Обрабатываем результаты
	for result := range results {
		fmt.Printf("%s:%d %s\n", result.Host, result.Port, result.State)
	}
}
