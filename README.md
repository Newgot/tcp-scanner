# TCP Port Scanner

Go-пакет для сканирования TCP-портов с поддержкой конкурентности, контекста и гибкой настройки.

## Особенности

- Сканирование одного или нескольких хостов (IPv4, IPv6, DNS)
- Поддержка отдельных портов, диапазонов и их комбинаций
- Конкурентное сканирование с настраиваемым количеством воркеров
- Настраиваемый таймаут подключения
- Поддержка context.Context для отмены операций
- Потоковая обработка результатов через каналы
- Детальная информация о каждом сканировании (IP, длительность)
- Классификация состояний портов без сравнения текста ошибок
- Нет внешних зависимостей

## Установка

go get github.com/Newgot/tcp-scanner

## Быстрый старт

package main

import (
"context"
"fmt"
"log"

    portscan "github.com/Newgot/tcp-scanner"
)

func main() {
scanner, err := portscan.New()
if err != nil {
log.Fatal(err)
}
defer scanner.Close()

    results, err := scanner.Scan(
        context.Background(),
        []string{"localhost"},
        portscan.Range(1, 1000),
    )
    if err != nil {
        log.Fatal(err)
    }

    for result := range results {
        if result.IsOpen() {
            fmt.Printf("✅ %s:%d открыт (IP: %s, %v)\n",
                result.Host, result.Port, result.IP, result.Duration)
        } else {
            fmt.Printf("❌ %s:%d %s (IP: %s, %v)\n",
                result.Host, result.Port, result.State, result.IP, result.Duration)
        }
    }
}

## Настройка

scanner, err := portscan.New(
portscan.WithConcurrency(50),
portscan.WithConnectTimeout(200*time.Millisecond),
portscan.WithLocalAddr(&net.TCPAddr{IP: net.ParseIP("192.168.1.100")}),
)

## Способы указания портов

### 1. Диапазон

ports := portscan.Range(1, 1000)

### 2. Отдельные порты

ports := portscan.Ports(22, 80, 443, 8080)

### 3. Парсинг строк

ports, err := portscan.ParsePorts(
"22,80,443",
"8000-8100",
"9000-9020",
)

### 4. Объединение списков

ports1 := portscan.Range(1, 100)
ports2 := portscan.Ports(443, 8080)
allPorts := portscan.MergePorts(ports1, ports2)

## Результат сканирования

Структура Result содержит всю необходимую информацию:

type Result struct {
Host     string
IP       net.IP
Port     uint16
State    State
Duration time.Duration
Error    error
}

### Состояния портов

| Состояние | Описание |
|-----------|----------|
| open | TCP-соединение установлено |
| closed | Соединение явно отклонено |
| timeout | Подключение не завершилось за время |
| unreachable | Узел или сеть недоступны |
| filtered | Порт фильтруется |
| canceled | Проверка отменена через контекст |
| error | Произошла другая ошибка |

## Обработка хостов

Пакет поддерживает различные типы хостов:

hosts := []string{
"localhost",
"127.0.0.1",
"::1",
"google.com",
"192.168.1.1",
}

results, err := scanner.Scan(ctx, hosts, ports)

## Работа с контекстом

ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
defer cancel()

ctx, cancel := context.WithCancel(context.Background())

go func() {
time.Sleep(5 * time.Second)
cancel()
}()

## Примеры

### Базовое сканирование

scanner, _ := portscan.New()
results, _ := scanner.Scan(
context.Background(),
[]string{"localhost"},
portscan.Range(1, 100),
)
for result := range results {
fmt.Println(result)
}

### Сканирование с настройками

scanner, _ := portscan.New(
portscan.WithConcurrency(100),
portscan.WithConnectTimeout(500*time.Millisecond),
)

ports, _ := portscan.ParsePorts("22,80,443", "8000-8100")
results, _ := scanner.ScanAll(ctx, []string{"google.com", "github.com"}, ports)

stats := portscan.Stats(results)
fmt.Printf("Статистика: %s\n", stats)

for _, r := range portscan.OpenPorts(results) {
fmt.Printf("Открыт: %s:%d\n", r.Host, r.Port)
}

### Медленное чтение результатов

results, _ := scanner.Scan(ctx, hosts, ports)
for result := range results {
processResult(result)
}

### Повторное использование сканера

scanner, _ := portscan.New()

results1, _ := scanner.Scan(ctx, []string{"localhost"}, portscan.Range(1, 100))

results2, _ := scanner.Scan(ctx, []string{"google.com"}, portscan.Range(1, 1000))

## Тестирование

go test -v ./...

go test -cover ./...

go test -bench=. -benchmem ./benchmarks/...

go test -race ./...

## Примеры в репозитории

go run examples/basic/main.go

go run examples/advanced/main.go

go run examples/web/main.go

go run examples/hosts/main.go

go run examples/ports/main.go

## Требования

- Go 1.25 или выше
- Стандартная библиотека (нет внешних зависимостей)
