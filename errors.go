package portscan

import (
	"context"
	"errors"
)

// Определение ошибок пакета
var (
	// ErrNoHosts возникает, когда не указаны хосты для сканирования
	ErrNoHosts = errors.New("no hosts specified")

	// ErrNoPorts возникает, когда не указаны порты для сканирования
	ErrNoPorts = errors.New("no ports specified")

	// ErrInvalidPort возникает при указании неверного порта
	ErrInvalidPort = errors.New("invalid port number")

	// ErrScanCanceled возникает при отмене сканирования через контекст
	ErrScanCanceled = errors.New("scan canceled")

	// ErrTimeout возникает при превышении таймаута
	ErrTimeout = errors.New("operation timeout")

	// ErrClosed возникает при попытке использовать закрытый сканер
	ErrClosed = errors.New("portscan is closed")

	// ErrTooManyPorts возникает при указании слишком большого количества портов
	ErrTooManyPorts = errors.New("too many ports specified")
)

// IsTimeoutError проверяет, является ли ошибка таймаутом
func IsTimeoutError(err error) bool {
	if err == nil {
		return false
	}
	return errors.Is(err, ErrTimeout) || errors.Is(err, context.DeadlineExceeded)
}
