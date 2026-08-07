package portscan

import (
	"net"
	"testing"
	"time"
)

func TestResult_String(t *testing.T) {
	ip := net.ParseIP("127.0.0.1")

	result := Result{
		Host:     "localhost",
		IP:       ip,
		Port:     80,
		State:    StateOpen,
		Duration: 10 * time.Millisecond,
	}

	str := result.String()
	if str == "" {
		t.Error("String() returned empty string")
	}
}

func TestResult_IsOpen(t *testing.T) {
	result := Result{State: StateOpen}
	if !result.IsOpen() {
		t.Error("IsOpen() returned false for open state")
	}

	result = Result{State: StateClosed}
	if result.IsOpen() {
		t.Error("IsOpen() returned true for closed state")
	}
}

func TestResult_IsClosed(t *testing.T) {
	result := Result{State: StateClosed}
	if !result.IsClosed() {
		t.Error("IsClosed() returned false for closed state")
	}

	result = Result{State: StateOpen}
	if result.IsClosed() {
		t.Error("IsClosed() returned true for open state")
	}
}

func TestStats(t *testing.T) {
	ip := net.ParseIP("127.0.0.1")

	results := []Result{
		{Host: "localhost", IP: ip, Port: 80, State: StateOpen},
		{Host: "localhost", IP: ip, Port: 443, State: StateClosed},
		{Host: "localhost", IP: ip, Port: 22, State: StateTimeout},
		{Host: "localhost", IP: ip, Port: 25, State: StateUnreachable},
		{Host: "localhost", IP: ip, Port: 110, State: StateError},
	}

	stats := Stats(results)

	if stats.Total != 5 {
		t.Errorf("Expected Total=5, got %d", stats.Total)
	}
	if stats.Open != 1 {
		t.Errorf("Expected Open=1, got %d", stats.Open)
	}
	if stats.Closed != 1 {
		t.Errorf("Expected Closed=1, got %d", stats.Closed)
	}
	if stats.Timeout != 1 {
		t.Errorf("Expected Timeout=1, got %d", stats.Timeout)
	}
	if stats.Unreachable != 1 {
		t.Errorf("Expected Unreachable=1, got %d", stats.Unreachable)
	}
	if stats.Errors != 1 {
		t.Errorf("Expected Errors=1, got %d", stats.Errors)
	}
}

func TestGroupByHost(t *testing.T) {
	ip := net.ParseIP("127.0.0.1")

	results := []Result{
		{Host: "host1", IP: ip, Port: 80, State: StateOpen},
		{Host: "host1", IP: ip, Port: 443, State: StateOpen},
		{Host: "host2", IP: ip, Port: 80, State: StateClosed},
	}

	groups := GroupByHost(results)

	if len(groups) != 2 {
		t.Errorf("Expected 2 groups, got %d", len(groups))
	}

	if len(groups["host1"]) != 2 {
		t.Errorf("Expected host1 to have 2 results, got %d", len(groups["host1"]))
	}

	if len(groups["host2"]) != 1 {
		t.Errorf("Expected host2 to have 1 result, got %d", len(groups["host2"]))
	}
}
