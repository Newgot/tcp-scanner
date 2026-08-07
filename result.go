package portscan

import (
	"fmt"
	"net"
	"time"
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
	Host     string        // Исходное имя хоста (DNS имя или IP)
	IP       net.IP        // IP-адрес, к которому было выполнено подключение
	Port     uint16        // Номер порта (1-65535)
	State    State         // Состояние порта
	Duration time.Duration // Время выполнения проверки
	Error    error         // Детали ошибки (если есть)
}

// String возвращает строковое представление результата
func (r Result) String() string {
	hostStr := r.Host
	if r.IP != nil && r.IP.String() != r.Host {
		hostStr = fmt.Sprintf("%s (%s)", r.Host, r.IP)
	}

	if r.Error != nil {
		return fmt.Sprintf("%s:%d %s (%v) [%v]",
			hostStr, r.Port, r.State, r.Error, r.Duration)
	}
	return fmt.Sprintf("%s:%d %s [%v]",
		hostStr, r.Port, r.State, r.Duration)
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

// IsFiltered проверяет, фильтруется ли порт
func (r Result) IsFiltered() bool {
	return r.State == StateFiltered
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
	Total         int           // Общее количество
	Open          int           // Открытые порты
	Closed        int           // Закрытые порты
	Filtered      int           // Фильтруемые порты
	Timeout       int           // Таймауты
	Unreachable   int           // Недоступные узлы
	Canceled      int           // Отмененные проверки
	Errors        int           // Ошибки
	TotalDuration time.Duration // Общее время сканирования
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
		case StateTimeout:
			stats.Timeout++
		case StateUnreachable:
			stats.Unreachable++
		case StateCanceled:
			stats.Canceled++
		case StateError:
			stats.Errors++
		}
	}
	return stats
}

// String возвращает строковое представление статистики
func (s ResultStats) String() string {
	return fmt.Sprintf(
		"Total: %d, Open: %d, Closed: %d, Filtered: %d, Timeout: %d, Unreachable: %d, Canceled: %d, Errors: %d [%v]",
		s.Total, s.Open, s.Closed, s.Filtered, s.Timeout, s.Unreachable, s.Canceled, s.Errors, s.TotalDuration,
	)
}

// GroupByHost группирует результаты по хостам
func GroupByHost(results []Result) map[string][]Result {
	groups := make(map[string][]Result)
	for _, r := range results {
		groups[r.Host] = append(groups[r.Host], r)
	}
	return groups
}
