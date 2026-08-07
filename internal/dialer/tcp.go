package dialer

import (
	"context"
	"net"
	"time"
)

// Config содержит настройки TCP-диалера.
type Config struct {
	Timeout   time.Duration
	LocalAddr net.Addr
	KeepAlive time.Duration
}

// TCPDialer обертка над net.Dialer с поддержкой контекста.
type TCPDialer struct {
	config Config
}

// NewTCPDialer создает новый TCPDialer с заданной конфигурацией.
func NewTCPDialer(config Config) *TCPDialer {
	if config.Timeout == 0 {
		config.Timeout = 5 * time.Second // значение по умолчанию
	}
	return &TCPDialer{config: config}
}

// DialContext устанавливает TCP-соединение с учетом контекста.
func (d *TCPDialer) DialContext(ctx context.Context, network, address string) (net.Conn, error) {
	dialer := &net.Dialer{
		Timeout:   d.config.Timeout,
		LocalAddr: d.config.LocalAddr,
		KeepAlive: d.config.KeepAlive,
	}
	return dialer.DialContext(ctx, network, address)
}

// Dial — упрощенный метод без контекста (использует context.Background()).
func (d *TCPDialer) Dial(network, address string) (net.Conn, error) {
	return d.DialContext(context.Background(), network, address)
}
