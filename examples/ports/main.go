package main

import (
	"context"
	"fmt"
	"log"

	portscan "github.com/Newgot/tcp-scanner"
)

func main() {
	fmt.Println("=== Различные способы указания портов ===")
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

	fmt.Println("1. Использование Range():")
	ports1 := portscan.Range(1, 10)
	fmt.Printf("   Порты: %v\n", ports1)
	fmt.Println()

	fmt.Println("2. Использование Ports():")
	ports2 := portscan.Ports(80, 443, 8080, 99999, 8443, 80)
	fmt.Printf("   Порты: %v (невалидные и дубликаты отфильтрованы)\n", ports2)
	fmt.Println()

	fmt.Println("3. Использование ParsePorts():")
	ports3, err := portscan.ParsePorts(
		"22,80,443",
		"8000-8010",
		"9000-9020",
	)
	if err != nil {
		log.Fatal(err)
	}
	fmt.Printf("   Порты: %v\n", ports3)
	fmt.Println()

	fmt.Println("4. Обратный диапазон (1000-1):")
	ports4 := portscan.Range(1000, 1)
	fmt.Printf("   Порты: %d портов (от 1 до 1000)\n", len(ports4))
	fmt.Println()

	fmt.Println("5. Объединение списков:")
	merged := portscan.MergePorts(ports1, ports2, ports3)
	fmt.Printf("   Всего уникальных портов: %d\n", len(merged))
	fmt.Println()

	fmt.Println("6. Тестирование валидации:")
	testCases := []struct {
		name  string
		ports []int
	}{
		{"Валидные порты", []int{22, 80, 443}},
		{"Порт 0", []int{0, 80, 443}},
		{"Порт > 65535", []int{80, 99999, 443}},
		{"Дубликаты", []int{80, 80, 443, 80}},
		{"Пустой список", []int{}},
	}

	for _, tc := range testCases {
		fmt.Printf("\n   %s: %v\n", tc.name, tc.ports)
		err := portscan.ValidatePorts(tc.ports)
		if err != nil {
			fmt.Printf("   ❌ Ошибка: %v\n", err)
		} else {
			fmt.Printf("   ✅ Валидно\n")
		}
	}
	fmt.Println()

	fmt.Println("7. Сканирование с комбинированными портами:")
	allPorts, err := portscan.ParsePorts("22,80,443", "8000-8005")
	if err != nil {
		log.Fatal(err)
	}

	ctx := context.Background()
	results, err := scanner.Scan(ctx, []string{"localhost"}, allPorts)
	if err != nil {
		log.Fatal(err)
	}

	fmt.Printf("   Сканируем %d портов на localhost:\n", len(allPorts))
	count := 0
	for result := range results {
		count++
		if count <= 10 || count > len(allPorts)-5 {
			fmt.Printf("      %s\n", result)
		} else if count == 11 {
			fmt.Printf("      ...\n")
		}
	}
	fmt.Printf("\n   Всего получено результатов: %d\n", count)
}
