package portscan

import (
	"testing"
)

func TestResolveHosts(t *testing.T) {
	tests := []struct {
		name    string
		hosts   []string
		wantLen int
		wantErr bool
	}{
		{
			name:    "valid IPv4",
			hosts:   []string{"192.168.1.1"},
			wantLen: 1,
			wantErr: false,
		},
		{
			name:    "valid IPv6",
			hosts:   []string{"::1"},
			wantLen: 1,
			wantErr: false,
		},
		{
			name:    "valid DNS",
			hosts:   []string{"localhost"},
			wantLen: 1,
			wantErr: false,
		},
		{
			name:    "empty host",
			hosts:   []string{""},
			wantLen: 0,
			wantErr: true,
		},
		{
			name:    "duplicate hosts",
			hosts:   []string{"localhost", "localhost", "127.0.0.1"},
			wantLen: 2,
			wantErr: false,
		},
		{
			name:    "mixed valid and invalid",
			hosts:   []string{"localhost", "invalid.domain", "192.168.1.1"},
			wantLen: 2,
			wantErr: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			info, err := ValidateHosts(tt.hosts)
			if (err != nil) != tt.wantErr {
				t.Errorf("ValidateHosts() error = %v, wantErr %v", err, tt.wantErr)
			}
			if !tt.wantErr && len(info) != tt.wantLen {
				t.Errorf("ValidateHosts() got %d hosts, want %d", len(info), tt.wantLen)
			}
		})
	}
}
