package portscan

import (
	"fmt"
)

// State представляет состояние порта
type State string

// Состояния портов
const (
	StateOpen        State = "open"        // TCP-соединение установлено
	StateClosed      State = "closed"      // Соединение явно отклонено
	StateTimeout     State = "timeout"     // Подключение не завершилось за время
	StateUnreachable State = "unreachable" // Узел или сеть недоступны
	StateFiltered    State = "filtered"    // Порт фильтруется (таймаут)
	StateCanceled    State = "canceled"    // Проверка отменена
	StateError       State = "error"       // Произошла другая ошибка
)

// Result представляет результат сканирования одного порта
type Result struct {
	Host  string // хост
	Port  int    // Номер порта
	State State  // Состояние порта
	Error error  // Детали ошибки (если есть)
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

// IsTimeout проверяет, истекло ли время ожидания
func (r Result) IsTimeout() bool {
	return r.State == StateTimeout
}

// IsUnreachable проверяет, недоступен ли узел
func (r Result) IsUnreachable() bool {
	return r.State == StateUnreachable
}

// IsCanceled проверяет, отменена ли проверка
func (r Result) IsCanceled() bool {
	return r.State == StateCanceled
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
	Total    int // Общее количество
	Open     int // Открытые порты
	Closed   int // Закрытые порты
	Filtered int // Фильтруемые порты
	Errors   int // Ошибки
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

// GroupByHost группирует результаты по хостам
func GroupByHost(results []Result) map[string][]Result {
	groups := make(map[string][]Result)
	for _, r := range results {
		groups[r.Host] = append(groups[r.Host], r)
	}
	return groups
}
