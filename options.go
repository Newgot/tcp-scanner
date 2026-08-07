package portscan

import (
	"fmt"
	"net"
	"time"
)

// Config содержит конфигурацию сканера
type Config struct {
	Concurrency    int           // количество одновременных проверок
	ConnectTimeout time.Duration // таймаут подключения
	LocalAddr      net.Addr      // локальный адрес для исходящих соединений
	MaxPorts       int           // максимальное количество портов для сканирования
}

// DefaultConfig возвращает конфигурацию по умолчанию
func DefaultConfig() *Config {
	return &Config{
		Concurrency:    100,
		ConnectTimeout: 500 * time.Millisecond,
		LocalAddr:      &net.TCPAddr{IP: net.IPv4zero},
		MaxPorts:       65535,
	}
}

// Validate проверяет корректность конфигурации
func (c *Config) Validate() error {
	if c.Concurrency < 1 {
		return fmt.Errorf("concurrency must be at least 1, got %d", c.Concurrency)
	}
	if c.ConnectTimeout < 0 {
		return fmt.Errorf("timeout must be positive, got %v", c.ConnectTimeout)
	}
	if c.MaxPorts < 1 || c.MaxPorts > 65535 {
		return fmt.Errorf("max ports must be between 1 and 65535, got %d", c.MaxPorts)
	}
	return nil
}

// Option определяет функцию для настройки сканера
type Option func(*Config) error

// WithConcurrency устанавливает количество одновременных проверок
func WithConcurrency(n int) Option {
	return func(c *Config) error {
		if n < 1 {
			return fmt.Errorf("concurrency must be at least 1, got %d", n)
		}
		c.Concurrency = n
		return nil
	}
}

// WithConnectTimeout устанавливает таймаут TCP-подключения
func WithConnectTimeout(timeout time.Duration) Option {
	return func(c *Config) error {
		if timeout < 0 {
			return fmt.Errorf("timeout must be positive, got %v", timeout)
		}
		c.ConnectTimeout = timeout
		return nil
	}
}

// WithLocalAddr устанавливает локальный адрес для исходящих соединений
func WithLocalAddr(addr net.Addr) Option {
	return func(c *Config) error {
		if addr == nil {
			return fmt.Errorf("local address cannot be nil")
		}
		c.LocalAddr = addr
		return nil
	}
}

// WithMaxPorts устанавливает максимальное количество портов
func WithMaxPorts(max int) Option {
	return func(c *Config) error {
		if max < 1 || max > 65535 {
			return fmt.Errorf("max ports must be between 1 and 65535, got %d", max)
		}
		c.MaxPorts = max
		return nil
	}
}
