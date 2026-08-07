package portscan

import (
	"testing"
)

func TestParsePorts(t *testing.T) {
	tests := []struct {
		name    string
		specs   []string
		want    []int
		wantErr bool
	}{
		{
			name:    "single port",
			specs:   []string{"80"},
			want:    []int{80},
			wantErr: false,
		},
		{
			name:    "port range",
			specs:   []string{"1-5"},
			want:    []int{1, 2, 3, 4, 5},
			wantErr: false,
		},
		{
			name:    "reverse range",
			specs:   []string{"10-1"},
			want:    []int{1, 2, 3, 4, 5, 6, 7, 8, 9, 10},
			wantErr: false,
		},
		{
			name:    "mixed",
			specs:   []string{"80", "443", "1-10"},
			want:    []int{80, 443, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10},
			wantErr: false,
		},
		{
			name:    "port 0",
			specs:   []string{"0"},
			want:    nil,
			wantErr: true,
		},
		{
			name:    "port > 65535",
			specs:   []string{"99999"},
			want:    nil,
			wantErr: true,
		},
		{
			name:    "duplicate ports",
			specs:   []string{"80,80,443,80"},
			want:    []int{80, 443},
			wantErr: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ports, err := ParsePorts(tt.specs...)
			if (err != nil) != tt.wantErr {
				t.Errorf("ParsePorts() error = %v, wantErr %v", err, tt.wantErr)
			}
			if !tt.wantErr {
				if len(ports) != len(tt.want) {
					t.Errorf("ParsePorts() got %d ports, want %d", len(ports), len(tt.want))
				}
				for i, p := range ports {
					if i < len(tt.want) && p != tt.want[i] {
						t.Errorf("ParsePorts() port[%d] = %d, want %d", i, p, tt.want[i])
					}
				}
			}
		})
	}
}

func TestRange(t *testing.T) {
	tests := []struct {
		name  string
		start int
		end   int
		want  []int
	}{
		{
			name:  "normal range",
			start: 1,
			end:   5,
			want:  []int{1, 2, 3, 4, 5},
		},
		{
			name:  "reverse range",
			start: 10,
			end:   1,
			want:  []int{1, 2, 3, 4, 5, 6, 7, 8, 9, 10},
		},
		{
			name:  "out of bounds",
			start: 0,
			end:   10,
			want:  []int{1, 2, 3, 4, 5, 6, 7, 8, 9, 10},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ports := Range(tt.start, tt.end)
			if len(ports) != len(tt.want) {
				t.Errorf("Range() got %d ports, want %d", len(ports), len(tt.want))
			}
			for i, p := range ports {
				if i < len(tt.want) && p != tt.want[i] {
					t.Errorf("Range() port[%d] = %d, want %d", i, p, tt.want[i])
				}
			}
		})
	}
}

func TestValidatePorts(t *testing.T) {
	tests := []struct {
		name    string
		ports   []int
		wantErr bool
	}{
		{
			name:    "valid ports",
			ports:   []int{80, 443, 8080},
			wantErr: false,
		},
		{
			name:    "port 0",
			ports:   []int{0, 80, 443},
			wantErr: true,
		},
		{
			name:    "port > 65535",
			ports:   []int{80, 99999, 443},
			wantErr: true,
		},
		{
			name:    "empty list",
			ports:   []int{},
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := ValidatePorts(tt.ports)
			if (err != nil) != tt.wantErr {
				t.Errorf("ValidatePorts() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}
