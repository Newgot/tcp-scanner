package portscan

import (
	"fmt"
	"strings"
)

// State представляет состояние порта
type State string

// Состояния портов
const (
	StateOpen     State = "open"     // порт открыт
	StateClosed   State = "closed"   // порт закрыт
	StateFiltered State = "filtered" // порт фильтруется (таймаут)
	StateError    State = "error"    // произошла ошибка
)

// Result представляет результат сканирования одного порта
type Result struct {
	Host  string // хост
	Port  int    // номер порта
	State State  // состояние порта
	Error error  // детали ошибки (если State == StateError)
}

// String возвращает строковое представление результата
func (r Result) String() string {
	if r.Error != nil {
		return fmt.Sprintf("%s:%d %s (%v)", r.Host, r.Port, r.State, r.Error)
	}
	return fmt.Sprintf("%s:%d %s", r.Host, r.Port, r.State)
}

// IsOpen проверяет, открыт ли порт
func (r Result) IsOpen() bool {
	return r.State == StateOpen
}

// IsClosed проверяет, закрыт ли порт
func (r Result) IsClosed() bool {
	return r.State == StateClosed
}

// IsFiltered проверяет, фильтруется ли порт
func (r Result) IsFiltered() bool {
	return r.State == StateFiltered
}

// IsError проверяет, произошла ли ошибка
func (r Result) IsError() bool {
	return r.State == StateError
}

// Success возвращает true, если сканирование прошло успешно (порт открыт или закрыт)
func (r Result) Success() bool {
	return r.State == StateOpen || r.State == StateClosed
}

// ResultStats содержит статистику сканирования
type ResultStats struct {
	Total    int // общее количество
	Open     int // открытые порты
	Closed   int // закрытые порты
	Filtered int // фильтруемые порты
	Errors   int // ошибки
}

// Stats собирает статистику из результатов
func Stats(results []Result) ResultStats {
	stats := ResultStats{Total: len(results)}
	for _, r := range results {
		switch r.State {
		case StateOpen:
			stats.Open++
		case StateClosed:
			stats.Closed++
		case StateFiltered:
			stats.Filtered++
		case StateError:
			stats.Errors++
		}
	}
	return stats
}

// String возвращает строковое представление статистики
func (s ResultStats) String() string {
	return fmt.Sprintf(
		"Total: %d, Open: %d, Closed: %d, Filtered: %d, Errors: %d",
		s.Total, s.Open, s.Closed, s.Filtered, s.Errors,
	)
}

// OpenPorts возвращает список открытых портов
func OpenPorts(results []Result) []Result {
	var open []Result
	for _, r := range results {
		if r.IsOpen() {
			open = append(open, r)
		}
	}
	return open
}

// ClosedPorts возвращает список закрытых портов
func ClosedPorts(results []Result) []Result {
	var closed []Result
	for _, r := range results {
		if r.IsClosed() {
			closed = append(closed, r)
		}
	}
	return closed
}

// GroupByHost группирует результаты по хостам
func GroupByHost(results []Result) map[string][]Result {
	groups := make(map[string][]Result)
	for _, r := range results {
		groups[r.Host] = append(groups[r.Host], r)
	}
	return groups
}

// FormatResults форматирует результаты в читаемый вид
func FormatResults(results []Result) string {
	var sb strings.Builder
	for _, r := range results {
		sb.WriteString(r.String())
		sb.WriteByte('\n')
	}
	return sb.String()
}
