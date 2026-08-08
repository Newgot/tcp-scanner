// result.go - добавляем недостающую десериализацию
package portscan

import (
	"encoding/json"
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
	Host     string        `json:"host"`
	IP       net.IP        `json:"ip"`
	Port     uint16        `json:"port"`
	State    State         `json:"state"`
	Duration time.Duration `json:"duration"`
	Error    error         `json:"-"`
}

// MarshalJSON для Result
func (r Result) MarshalJSON() ([]byte, error) {
	type Alias Result
	return json.Marshal(&struct {
		Duration string `json:"duration"`
		ErrorMsg string `json:"error,omitempty"`
		*Alias
	}{
		Duration: r.Duration.String(),
		ErrorMsg: func() string {
			if r.Error != nil {
				return r.Error.Error()
			}
			return ""
		}(),
		Alias: (*Alias)(&r),
	})
}

// UnmarshalJSON для Result
func (r *Result) UnmarshalJSON(data []byte) error {
	type Alias Result
	aux := &struct {
		Duration string `json:"duration"`
		ErrorMsg string `json:"error,omitempty"`
		*Alias
	}{
		Alias: (*Alias)(r),
	}
	if err := json.Unmarshal(data, &aux); err != nil {
		return err
	}
	if aux.Duration != "" {
		if d, err := time.ParseDuration(aux.Duration); err == nil {
			r.Duration = d
		}
	}
	if aux.ErrorMsg != "" {
		r.Error = fmt.Errorf("%s", aux.ErrorMsg)
	}
	return nil
}

// ResultStats содержит статистику сканирования
type ResultStats struct {
	Total         int           `json:"total"`
	Open          int           `json:"open"`
	Closed        int           `json:"closed"`
	Filtered      int           `json:"filtered"`
	Timeout       int           `json:"timeout"`
	Unreachable   int           `json:"unreachable"`
	Canceled      int           `json:"canceled"`
	Errors        int           `json:"errors"`
	TotalDuration time.Duration `json:"total_duration"`
}

// MarshalJSON для ResultStats
func (s ResultStats) MarshalJSON() ([]byte, error) {
	type Alias ResultStats
	return json.Marshal(&struct {
		TotalDuration string `json:"total_duration"`
		*Alias
	}{
		TotalDuration: s.TotalDuration.String(),
		Alias:         (*Alias)(&s),
	})
}

// UnmarshalJSON для ResultStats
func (s *ResultStats) UnmarshalJSON(data []byte) error {
	type Alias ResultStats
	aux := &struct {
		TotalDuration string `json:"total_duration"`
		*Alias
	}{
		Alias: (*Alias)(s),
	}
	if err := json.Unmarshal(data, &aux); err != nil {
		return err
	}
	if aux.TotalDuration != "" {
		if d, err := time.ParseDuration(aux.TotalDuration); err == nil {
			s.TotalDuration = d
		}
	}
	return nil
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
