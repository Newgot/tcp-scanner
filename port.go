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

// PortSpec представляет спецификацию портов
type PortSpec struct {
	Start int
	End   int
}

// ParsePorts парсит строки с портами в различных форматах
// Поддерживаемые форматы:
//   - "80" - один порт
//   - "1-100" - диапазон портов
//   - "80,443,8080" - список портов через запятую
//   - "1-100,443,8080-8090" - комбинация
//   - "1-100,443,8080-8090,22" - комбинация с отдельными портами
func ParsePorts(specs ...string) ([]int, error) {
	if len(specs) == 0 {
		return nil, ErrNoPorts
	}

	var ports []int
	seen := make(map[int]bool) // для удаления дубликатов

	for _, spec := range specs {
		spec = strings.TrimSpace(spec)
		if spec == "" {
			continue
		}

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

	if len(ports) == 0 {
		return nil, ErrNoPorts
	}

	return ports, nil
}

// parseRange парсит диапазон портов в формате "start-end"
// Поддерживает обратные диапазоны (например, "1000-1")
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

	// Валидация портов
	if err := validatePort(start); err != nil {
		return nil, err
	}
	if err := validatePort(end); err != nil {
		return nil, err
	}

	// Поддержка обратных диапазонов
	if start > end {
		start, end = end, start
	}

	// Ограничиваем максимальное количество портов в диапазоне
	if end-start+1 > 65535 {
		return nil, fmt.Errorf("range too large: %d-%d (max 65535 ports)", start, end)
	}

	ports := make([]int, 0, end-start+1)
	for p := start; p <= end; p++ {
		ports = append(ports, p)
	}

	return ports, nil
}

// parseSingle парсит один порт
func parseSingle(spec string) (int, error) {
	port, err := strconv.Atoi(strings.TrimSpace(spec))
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
	if port < 1 {
		return fmt.Errorf("%w: %d (port must be >= 1)", ErrInvalidPort, port)
	}
	if port > 65535 {
		return fmt.Errorf("%w: %d (port must be <= 65535)", ErrInvalidPort, port)
	}
	return nil
}

// Range создает список портов в диапазоне [start, end]
// Поддерживает обратные диапазоны (например, Range(1000, 1))
func Range(start, end int) []int {
	// Автоматическая коррекция обратных диапазонов
	if start > end {
		start, end = end, start
	}

	// Ограничиваем значения
	if start < 1 {
		start = 1
	}
	if end > 65535 {
		end = 65535
	}
	if start > end {
		return []int{}
	}

	ports := make([]int, 0, end-start+1)
	for p := start; p <= end; p++ {
		ports = append(ports, p)
	}
	return ports
}

// Ports создает список портов из переданных значений
// Автоматически фильтрует невалидные порты и удаляет дубликаты
func Ports(ports ...int) []int {
	if len(ports) == 0 {
		return []int{}
	}

	result := make([]int, 0, len(ports))
	seen := make(map[int]bool)

	for _, p := range ports {
		// Пропускаем невалидные порты
		if p < 1 || p > 65535 {
			continue
		}
		if !seen[p] {
			seen[p] = true
			result = append(result, p)
		}
	}
	return result
}

// MergePorts объединяет несколько списков портов, удаляя дубликаты
func MergePorts(portLists ...[]int) []int {
	if len(portLists) == 0 {
		return []int{}
	}

	seen := make(map[int]bool)
	result := make([]int, 0)

	for _, list := range portLists {
		for _, p := range list {
			if p >= 1 && p <= 65535 && !seen[p] {
				seen[p] = true
				result = append(result, p)
			}
		}
	}
	return result
}

// ValidatePorts проверяет список портов на валидность
func ValidatePorts(ports []int) error {
	if len(ports) == 0 {
		return ErrNoPorts
	}

	for _, p := range ports {
		if p < 1 {
			return fmt.Errorf("%w: %d (port must be >= 1)", ErrInvalidPort, p)
		}
		if p > 65535 {
			return fmt.Errorf("%w: %d (port must be <= 65535)", ErrInvalidPort, p)
		}
	}
	return nil
}
