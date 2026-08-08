package dialer

import (
	"context"
	"net"
	"testing"
	"time"
)

func TestNewTCPDialer(t *testing.T) {
	tests := []struct {
		name    string
		config  Config
		wantErr bool
	}{
		{
			name: "default timeout",
			config: Config{
				Timeout:   0,
				LocalAddr: nil,
				KeepAlive: 0,
			},
			wantErr: false,
		},
		{
			name: "custom timeout",
			config: Config{
				Timeout:   1 * time.Second,
				LocalAddr: &net.TCPAddr{IP: net.IPv4zero},
				KeepAlive: 30 * time.Second,
			},
			wantErr: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			dialer := NewTCPDialer(tt.config)
			if dialer == nil {
				t.Error("NewTCPDialer returned nil")
			}
			if tt.config.Timeout == 0 && dialer.config.Timeout != 5*time.Second {
				t.Errorf("Expected default timeout 5s, got %v", dialer.config.Timeout)
			}
		})
	}
}

func TestTCPDialer_DialContext(t *testing.T) {
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer func() {
		if err := listener.Close(); err != nil {
			t.Logf("Error closing listener: %v", err)
		}
	}()

	go func() {
		for {
			conn, err := listener.Accept()
			if err != nil {
				return
			}
			if err := conn.Close(); err != nil {
				t.Logf("Error closing connection: %v", err)
			}
		}
	}()

	addr := listener.Addr().String()

	tests := []struct {
		name    string
		config  Config
		timeout time.Duration
		wantErr bool
	}{
		{
			name: "successful connection",
			config: Config{
				Timeout:   1 * time.Second,
				LocalAddr: &net.TCPAddr{IP: net.IPv4zero},
				KeepAlive: 30 * time.Second,
			},
			timeout: 1 * time.Second,
			wantErr: false,
		},
		{
			name: "short timeout",
			config: Config{
				Timeout:   1 * time.Nanosecond,
				LocalAddr: &net.TCPAddr{IP: net.IPv4zero},
				KeepAlive: -1,
			},
			timeout: 1 * time.Nanosecond,
			wantErr: true,
		},
		{
			name: "with context timeout",
			config: Config{
				Timeout:   5 * time.Second,
				LocalAddr: &net.TCPAddr{IP: net.IPv4zero},
				KeepAlive: 30 * time.Second,
			},
			timeout: 1 * time.Millisecond,
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			dialer := NewTCPDialer(tt.config)

			ctx := context.Background()
			if tt.timeout > 0 {
				var cancel context.CancelFunc
				ctx, cancel = context.WithTimeout(ctx, tt.timeout)
				defer cancel()
			}

			if tt.name == "with context timeout" {
				time.Sleep(2 * time.Millisecond)
			}

			conn, err := dialer.DialContext(ctx, "tcp", addr)
			if err != nil {
				if !tt.wantErr {
					t.Errorf("DialContext() unexpected error: %v", err)
				}
				return
			}
			if err := conn.Close(); err != nil {
				t.Logf("Error closing connection: %v", err)
			}

			if tt.wantErr {
				t.Error("DialContext() expected error, got nil")
			}
		})
	}
}

func TestTCPDialer_Dial(t *testing.T) {
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer func() {
		if err := listener.Close(); err != nil {
			t.Logf("Error closing listener: %v", err)
		}
	}()

	go func() {
		for {
			conn, err := listener.Accept()
			if err != nil {
				return
			}
			if err := conn.Close(); err != nil {
				t.Logf("Error closing connection: %v", err)
			}
		}
	}()

	addr := listener.Addr().String()

	dialer := NewTCPDialer(Config{
		Timeout:   1 * time.Second,
		LocalAddr: &net.TCPAddr{IP: net.IPv4zero},
		KeepAlive: 30 * time.Second,
	})

	conn, err := dialer.Dial("tcp", addr)
	if err != nil {
		t.Errorf("Dial() unexpected error: %v", err)
	}
	if conn != nil {
		if err := conn.Close(); err != nil {
			t.Logf("Error closing connection: %v", err)
		}
	}
}

func TestTCPDialer_ContextCancel(t *testing.T) {
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer func() {
		if err := listener.Close(); err != nil {
			t.Logf("Error closing listener: %v", err)
		}
	}()

	addr := listener.Addr().String()

	dialer := NewTCPDialer(Config{
		Timeout:   5 * time.Second,
		LocalAddr: &net.TCPAddr{IP: net.IPv4zero},
		KeepAlive: 30 * time.Second,
	})

	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	conn, err := dialer.DialContext(ctx, "tcp", addr)
	if err == nil {
		if conn != nil {
			if err := conn.Close(); err != nil {
				t.Logf("Error closing connection: %v", err)
			}
		}
		t.Error("DialContext() expected error with canceled context, got nil")
	}
}

func TestTCPDialer_InvalidAddress(t *testing.T) {
	dialer := NewTCPDialer(Config{
		Timeout:   1 * time.Second,
		LocalAddr: &net.TCPAddr{IP: net.IPv4zero},
		KeepAlive: 30 * time.Second,
	})

	_, err := dialer.Dial("tcp", "192.0.2.1:12345")
	if err == nil {
		t.Error("Dial() expected error for invalid address, got nil")
	}
}

func TestTCPDialer_KeepAlive(t *testing.T) {
	tests := []struct {
		name      string
		keepAlive time.Duration
	}{
		{"no keepalive", -1},
		{"default keepalive", 0},
		{"custom keepalive", 30 * time.Second},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			config := Config{
				Timeout:   1 * time.Second,
				LocalAddr: &net.TCPAddr{IP: net.IPv4zero},
				KeepAlive: tt.keepAlive,
			}
			dialer := NewTCPDialer(config)
			if dialer.config.KeepAlive != tt.keepAlive {
				if tt.keepAlive != 0 || dialer.config.KeepAlive != 0 {
					t.Errorf("KeepAlive = %v, want %v", dialer.config.KeepAlive, tt.keepAlive)
				}
			}
		})
	}
}

func TestTCPDialer_Timeout(t *testing.T) {
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer func() {
		if err := listener.Close(); err != nil {
			t.Logf("Error closing listener: %v", err)
		}
	}()

	addr := listener.Addr().String()

	dialer := NewTCPDialer(Config{
		Timeout:   1 * time.Microsecond,
		LocalAddr: &net.TCPAddr{IP: net.IPv4zero},
		KeepAlive: -1,
	})

	ctx := context.Background()
	start := time.Now()
	conn, err := dialer.DialContext(ctx, "tcp", addr)
	duration := time.Since(start)

	if err == nil {
		if conn != nil {
			if err := conn.Close(); err != nil {
				t.Logf("Error closing connection: %v", err)
			}
		}
		t.Error("DialContext() expected timeout error, got nil")
	}

	if duration > 1*time.Second {
		t.Logf("Timeout took %v, may be longer than expected", duration)
	}
}

func TestTCPDialer_NetworkProtocols(t *testing.T) {
	protocols := []string{"tcp", "tcp4", "tcp6"}

	for _, proto := range protocols {
		t.Run(proto, func(t *testing.T) {
			listener, err := net.Listen(proto, "127.0.0.1:0")
			if err != nil {
				if proto == "tcp6" {
					t.Skip("IPv6 not supported in this environment")
				}
				t.Fatal(err)
			}
			defer func() {
				if err := listener.Close(); err != nil {
					t.Logf("Error closing listener: %v", err)
				}
			}()

			go func() {
				for {
					conn, err := listener.Accept()
					if err != nil {
						return
					}
					if err := conn.Close(); err != nil {
						t.Logf("Error closing connection: %v", err)
					}
				}
			}()

			addr := listener.Addr().String()
			dialer := NewTCPDialer(Config{
				Timeout:   1 * time.Second,
				LocalAddr: &net.TCPAddr{IP: net.IPv4zero},
				KeepAlive: 30 * time.Second,
			})

			conn, err := dialer.Dial(proto, addr)
			if err != nil {
				t.Errorf("Dial() with protocol %s failed: %v", proto, err)
			}
			if conn != nil {
				if err := conn.Close(); err != nil {
					t.Logf("Error closing connection: %v", err)
				}
			}
		})
	}
}

func TestTCPDialer_MultipleConnections(t *testing.T) {
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer func() {
		if err := listener.Close(); err != nil {
			t.Logf("Error closing listener: %v", err)
		}
	}()

	go func() {
		for {
			conn, err := listener.Accept()
			if err != nil {
				return
			}
			if err := conn.Close(); err != nil {
				t.Logf("Error closing connection: %v", err)
			}
		}
	}()

	addr := listener.Addr().String()
	dialer := NewTCPDialer(Config{
		Timeout:   1 * time.Second,
		LocalAddr: &net.TCPAddr{IP: net.IPv4zero},
		KeepAlive: 30 * time.Second,
	})

	connections := 10
	for i := 0; i < connections; i++ {
		conn, err := dialer.Dial("tcp", addr)
		if err != nil {
			t.Errorf("Dial() failed on attempt %d: %v", i, err)
		}
		if conn != nil {
			if err := conn.Close(); err != nil {
				t.Logf("Error closing connection %d: %v", i, err)
			}
		}
	}
}

// Бенчмарк для DialContext
func BenchmarkTCPDialer_DialContext(b *testing.B) {
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		b.Fatal(err)
	}
	defer func() {
		if err := listener.Close(); err != nil {
			b.Logf("Error closing listener: %v", err)
		}
	}()

	go func() {
		for {
			conn, err := listener.Accept()
			if err != nil {
				return
			}
			if err := conn.Close(); err != nil {
				b.Logf("Error closing connection: %v", err)
			}
		}
	}()

	addr := listener.Addr().String()
	dialer := NewTCPDialer(Config{
		Timeout:   1 * time.Second,
		LocalAddr: &net.TCPAddr{IP: net.IPv4zero},
		KeepAlive: 30 * time.Second,
	})

	ctx := context.Background()

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		conn, err := dialer.DialContext(ctx, "tcp", addr)
		if err != nil {
			b.Fatal(err)
		}
		if err := conn.Close(); err != nil {
			b.Logf("Error closing connection: %v", err)
		}
	}
}

// Бенчмарк для Dial
func BenchmarkTCPDialer_Dial(b *testing.B) {
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		b.Fatal(err)
	}
	defer func() {
		if err := listener.Close(); err != nil {
			b.Logf("Error closing listener: %v", err)
		}
	}()

	go func() {
		for {
			conn, err := listener.Accept()
			if err != nil {
				return
			}
			if err := conn.Close(); err != nil {
				b.Logf("Error closing connection: %v", err)
			}
		}
	}()

	addr := listener.Addr().String()
	dialer := NewTCPDialer(Config{
		Timeout:   1 * time.Second,
		LocalAddr: &net.TCPAddr{IP: net.IPv4zero},
		KeepAlive: 30 * time.Second,
	})

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		conn, err := dialer.Dial("tcp", addr)
		if err != nil {
			b.Fatal(err)
		}
		if err := conn.Close(); err != nil {
			b.Logf("Error closing connection: %v", err)
		}
	}
}

// Бенчмарк для подключения к недоступному адресу
func BenchmarkTCPDialer_InvalidAddress(b *testing.B) {
	dialer := NewTCPDialer(Config{
		Timeout:   100 * time.Millisecond,
		LocalAddr: &net.TCPAddr{IP: net.IPv4zero},
		KeepAlive: -1,
	})

	ctx := context.Background()

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, err := dialer.DialContext(ctx, "tcp", "192.0.2.1:12345")
		if err == nil {
			b.Error("Expected error for invalid address")
		}
	}
}
