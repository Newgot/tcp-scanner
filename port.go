package portscan

import (
	"fmt"
	"strconv"
	"strings"
)

// task представляет задачу сканирования (внутренний тип)
type task struct {
	host string
	port int
}

// ParsePorts парсит строки с портами в различных форматах
// Поддерживаемые форматы:
//   - "80" - один порт
//   - "1-100" - диапазон портов
//   - "80,443,8080" - список портов через запятую
//   - "1-100,443,8080-8090" - комбинация
func ParsePorts(specs ...string) ([]int, error) {
	var ports []int
	seen := make(map[int]bool) // для удаления дубликатов

	for _, spec := range specs {
		// Разбиваем по запятой
		parts := strings.Split(spec, ",")
		for _, part := range parts {
			part = strings.TrimSpace(part)
			if part == "" {
				continue
			}

			// Проверяем, содержит ли диапазон
			if strings.Contains(part, "-") {
				rangePorts, err := parseRange(part)
				if err != nil {
					return nil, err
				}
				for _, p := range rangePorts {
					if !seen[p] {
						seen[p] = true
						ports = append(ports, p)
					}
				}
			} else {
				port, err := parseSingle(part)
				if err != nil {
					return nil, err
				}
				if !seen[port] {
					seen[port] = true
					ports = append(ports, port)
				}
			}
		}
	}

	return ports, nil
}

// parseRange парсит диапазон портов в формате "start-end"
func parseRange(spec string) ([]int, error) {
	parts := strings.SplitN(spec, "-", 2)
	if len(parts) != 2 {
		return nil, fmt.Errorf("invalid range format: %s", spec)
	}

	start, err := strconv.Atoi(strings.TrimSpace(parts[0]))
	if err != nil {
		return nil, fmt.Errorf("invalid start port: %w", err)
	}

	end, err := strconv.Atoi(strings.TrimSpace(parts[1]))
	if err != nil {
		return nil, fmt.Errorf("invalid end port: %w", err)
	}

	if err := validatePort(start); err != nil {
		return nil, err
	}
	if err := validatePort(end); err != nil {
		return nil, err
	}

	if start > end {
		start, end = end, start
	}

	// Ограничиваем максимальное количество портов
	if end-start+1 > 65535 {
		return nil, fmt.Errorf("range too large: %d-%d", start, end)
	}

	ports := make([]int, 0, end-start+1)
	for p := start; p <= end; p++ {
		ports = append(ports, p)
	}

	return ports, nil
}

// parseSingle парсит один порт
func parseSingle(spec string) (int, error) {
	port, err := strconv.Atoi(spec)
	if err != nil {
		return 0, fmt.Errorf("invalid port: %w", err)
	}
	if err := validatePort(port); err != nil {
		return 0, err
	}
	return port, nil
}

// validatePort проверяет корректность порта
func validatePort(port int) error {
	if port < 1 || port > 65535 {
		return fmt.Errorf("%w: %d", ErrInvalidPort, port)
	}
	return nil
}

// Range создает список портов в диапазоне [start, end]
func Range(start, end int) []int {
	if start < 1 {
		start = 1
	}
	if end > 65535 {
		end = 65535
	}
	if start > end {
		start, end = end, start
	}

	ports := make([]int, 0, end-start+1)
	for p := start; p <= end; p++ {
		ports = append(ports, p)
	}
	return ports
}

// Ports создает список портов из переданных значений
// Автоматически фильтрует невалидные порты
func Ports(ports ...int) []int {
	result := make([]int, 0, len(ports))
	seen := make(map[int]bool)

	for _, p := range ports {
		if p >= 1 && p <= 65535 && !seen[p] {
			seen[p] = true
			result = append(result, p)
		}
	}
	return result
}

// UniquePorts удаляет дубликаты из списка портов
func UniquePorts(ports []int) []int {
	seen := make(map[int]bool)
	result := make([]int, 0, len(ports))

	for _, p := range ports {
		if !seen[p] && p >= 1 && p <= 65535 {
			seen[p] = true
			result = append(result, p)
		}
	}
	return result
}

// ContainsPort проверяет наличие порта в списке
func ContainsPort(ports []int, port int) bool {
	for _, p := range ports {
		if p == port {
			return true
		}
	}
	return false
}

// CommonPorts возвращает список часто используемых портов
func CommonPorts() []int {
	return []int{
		21, 22, 23, 25, 53, 80, 110, 111, 135, 139,
		143, 443, 445, 993, 995, 1723, 3306, 3389,
		5432, 5900, 6379, 8080, 8443, 27017,
	}
}
