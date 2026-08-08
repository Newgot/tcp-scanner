package main

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	portscan "github.com/Newgot/tcp-scanner"
)

func TestHealthHandler(t *testing.T) {
	req, err := http.NewRequest("GET", "/health", nil)
	if err != nil {
		t.Fatal(err)
	}

	rr := httptest.NewRecorder()
	handler := http.HandlerFunc(healthHandler)

	handler.ServeHTTP(rr, req)

	if status := rr.Code; status != http.StatusOK {
		t.Errorf("Health handler returned wrong status code: got %v want %v", status, http.StatusOK)
	}

	if contentType := rr.Header().Get("Content-Type"); contentType != "application/json" {
		t.Errorf("Health handler returned wrong Content-Type: got %v want application/json", contentType)
	}

	var response map[string]string
	if err := json.NewDecoder(rr.Body).Decode(&response); err != nil {
		t.Fatal(err)
	}

	if response["status"] != "ok" {
		t.Errorf("Expected status 'ok', got '%s'", response["status"])
	}
	if response["service"] != "port-scanner" {
		t.Errorf("Expected service 'port-scanner', got '%s'", response["service"])
	}
}

func TestIndexHandler(t *testing.T) {
	req, err := http.NewRequest("GET", "/", nil)
	if err != nil {
		t.Fatal(err)
	}

	rr := httptest.NewRecorder()
	handler := http.HandlerFunc(indexHandler)

	handler.ServeHTTP(rr, req)

	if status := rr.Code; status != http.StatusOK {
		t.Errorf("Index handler returned wrong status code: got %v want %v", status, http.StatusOK)
	}

	if contentType := rr.Header().Get("Content-Type"); contentType != "text/html" {
		t.Errorf("Index handler returned wrong Content-Type: got %v want text/html", contentType)
	}

	body := rr.Body.String()
	// Проверяем, что HTML содержит основные элементы
	expectedTexts := []string{
		"Port Scanner API",
		"/scan",
		"/health",
		"curl",
	}
	for _, text := range expectedTexts {
		if !contains(body, text) {
			t.Errorf("Index HTML missing expected text: %s", text)
		}
	}
}

func TestScanHandler(t *testing.T) {
	testScanner, err := portscan.New(
		portscan.WithConcurrency(10),
		portscan.WithConnectTimeout(100*time.Millisecond),
	)
	if err != nil {
		t.Fatal(err)
	}
	defer func() {
		if err := testScanner.Close(); err != nil {
			t.Logf("Error closing scanner: %v", err)
		}
	}()

	originalScanner := scanner
	scanner = testScanner
	defer func() {
		scanner = originalScanner
	}()

	tests := []struct {
		name       string
		request    ScanRequest
		statusCode int
	}{
		{
			name: "valid request",
			request: ScanRequest{
				Hosts: []string{"localhost"},
				Ports: []int{80, 443},
			},
			statusCode: http.StatusOK,
		},
		{
			name: "no hosts",
			request: ScanRequest{
				Hosts: []string{},
				Ports: []int{80, 443},
			},
			statusCode: http.StatusBadRequest,
		},
		{
			name: "no ports",
			request: ScanRequest{
				Hosts: []string{"localhost"},
				Ports: []int{},
			},
			statusCode: http.StatusBadRequest,
		},
		{
			name: "with timeout",
			request: ScanRequest{
				Hosts:   []string{"localhost"},
				Ports:   []int{80, 443},
				Timeout: "1s",
			},
			statusCode: http.StatusOK,
		},
		{
			name: "with concurrency",
			request: ScanRequest{
				Hosts:       []string{"localhost"},
				Ports:       []int{80, 443},
				Concurrency: 50,
			},
			statusCode: http.StatusOK,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			body, err := json.Marshal(tt.request)
			if err != nil {
				t.Fatal(err)
			}

			req, err := http.NewRequest("POST", "/scan", bytes.NewBuffer(body))
			if err != nil {
				t.Fatal(err)
			}
			req.Header.Set("Content-Type", "application/json")

			rr := httptest.NewRecorder()
			handler := http.HandlerFunc(scanHandler)

			handler.ServeHTTP(rr, req)

			if status := rr.Code; status != tt.statusCode {
				t.Errorf("Scan handler returned wrong status code: got %v want %v", status, tt.statusCode)
			}

			if tt.statusCode == http.StatusOK {
				var response ScanResponse
				if err := json.NewDecoder(rr.Body).Decode(&response); err != nil {
					t.Errorf("Failed to decode response: %v", err)
				}
			}
		})
	}
}

func TestScanHandlerInvalidJSON(t *testing.T) {
	req, err := http.NewRequest("POST", "/scan", bytes.NewBuffer([]byte(`{invalid json}`)))
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set("Content-Type", "application/json")

	rr := httptest.NewRecorder()
	handler := http.HandlerFunc(scanHandler)

	handler.ServeHTTP(rr, req)

	if status := rr.Code; status != http.StatusBadRequest {
		t.Errorf("Expected status 400, got %v", status)
	}
}

func TestScanHandlerWrongMethod(t *testing.T) {
	methods := []string{"GET", "PUT", "DELETE", "PATCH"}

	for _, method := range methods {
		t.Run(method, func(t *testing.T) {
			req, err := http.NewRequest(method, "/scan", nil)
			if err != nil {
				t.Fatal(err)
			}

			rr := httptest.NewRecorder()
			handler := http.HandlerFunc(scanHandler)

			handler.ServeHTTP(rr, req)

			if status := rr.Code; status != http.StatusMethodNotAllowed {
				t.Errorf("Expected status 405, got %v", status)
			}
		})
	}
}

func TestHealthHandlerWrongMethod(t *testing.T) {
	req, err := http.NewRequest("POST", "/health", nil)
	if err != nil {
		t.Fatal(err)
	}

	rr := httptest.NewRecorder()
	handler := http.HandlerFunc(healthHandler)

	handler.ServeHTTP(rr, req)

	if status := rr.Code; status != http.StatusMethodNotAllowed {
		t.Errorf("Expected status 405, got %v", status)
	}
}

func TestIndexHandlerWrongMethod(t *testing.T) {
	req, err := http.NewRequest("POST", "/", nil)
	if err != nil {
		t.Fatal(err)
	}

	rr := httptest.NewRecorder()
	handler := http.HandlerFunc(indexHandler)

	handler.ServeHTTP(rr, req)

	if status := rr.Code; status != http.StatusMethodNotAllowed {
		t.Errorf("Expected status 405, got %v", status)
	}
}

func TestRealScanRequest(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping real scan test in short mode")
	}

	testScanner, err := portscan.New(
		portscan.WithConcurrency(10),
		portscan.WithConnectTimeout(100*time.Millisecond),
	)
	if err != nil {
		t.Fatal(err)
	}
	defer func() {
		if err := testScanner.Close(); err != nil {
			t.Logf("Error closing scanner: %v", err)
		}
	}()

	originalScanner := scanner
	scanner = testScanner
	defer func() {
		scanner = originalScanner
	}()

	request := ScanRequest{
		Hosts: []string{"localhost"},
		Ports: []int{80, 443, 8080},
	}

	body, err := json.Marshal(request)
	if err != nil {
		t.Fatal(err)
	}

	req, err := http.NewRequest("POST", "/scan", bytes.NewBuffer(body))
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set("Content-Type", "application/json")

	rr := httptest.NewRecorder()
	handler := http.HandlerFunc(scanHandler)

	handler.ServeHTTP(rr, req)

	if status := rr.Code; status != http.StatusOK {
		t.Errorf("Expected status 200, got %v: %s", status, rr.Body.String())
	}

	var response ScanResponse
	if err := json.NewDecoder(rr.Body).Decode(&response); err != nil {
		t.Fatal(err)
	}

	t.Logf("Scan completed in %s", response.Time)
	t.Logf("Results: %d", len(response.Results))
	t.Logf("Stats: %s", response.Stats)

	if len(response.Results) != len(request.Ports) {
		t.Logf("Expected %d results, got %d", len(request.Ports), len(response.Results))
	}
}

func TestScanWithMultipleHosts(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping multi-host scan test in short mode")
	}

	testScanner, err := portscan.New(
		portscan.WithConcurrency(10),
		portscan.WithConnectTimeout(100*time.Millisecond),
	)
	if err != nil {
		t.Fatal(err)
	}
	defer func() {
		if err := testScanner.Close(); err != nil {
			t.Logf("Error closing scanner: %v", err)
		}
	}()

	originalScanner := scanner
	scanner = testScanner
	defer func() {
		scanner = originalScanner
	}()

	request := ScanRequest{
		Hosts: []string{"localhost", "google.com"},
		Ports: []int{80, 443},
	}

	body, err := json.Marshal(request)
	if err != nil {
		t.Fatal(err)
	}

	req, err := http.NewRequest("POST", "/scan", bytes.NewBuffer(body))
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set("Content-Type", "application/json")

	rr := httptest.NewRecorder()
	handler := http.HandlerFunc(scanHandler)

	handler.ServeHTTP(rr, req)

	if status := rr.Code; status != http.StatusOK {
		t.Errorf("Expected status 200, got %v", status)
	}

	var response ScanResponse
	if err := json.NewDecoder(rr.Body).Decode(&response); err != nil {
		t.Fatal(err)
	}

	t.Logf("Multi-host scan: %d results", len(response.Results))
}

func TestScanTimeout(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping timeout test in short mode")
	}

	testScanner, err := portscan.New(
		portscan.WithConcurrency(10),
		portscan.WithConnectTimeout(100*time.Millisecond),
	)
	if err != nil {
		t.Fatal(err)
	}
	defer func() {
		if err := testScanner.Close(); err != nil {
			t.Logf("Error closing scanner: %v", err)
		}
	}()

	originalScanner := scanner
	scanner = testScanner
	defer func() {
		scanner = originalScanner
	}()

	request := ScanRequest{
		Hosts:   []string{"localhost"},
		Ports:   portscan.Range(1, 100),
		Timeout: "100ms",
	}

	body, err := json.Marshal(request)
	if err != nil {
		t.Fatal(err)
	}

	req, err := http.NewRequest("POST", "/scan", bytes.NewBuffer(body))
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set("Content-Type", "application/json")

	rr := httptest.NewRecorder()
	handler := http.HandlerFunc(scanHandler)

	start := time.Now()
	handler.ServeHTTP(rr, req)
	duration := time.Since(start)

	t.Logf("Scan with timeout completed in %v", duration)

	if duration > 2*time.Second {
		t.Logf("Scan took %v, may be longer than expected", duration)
	}
}

func TestScanWithLargeRequest(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping large request test in short mode")
	}

	testScanner, err := portscan.New(
		portscan.WithConcurrency(50),
		portscan.WithConnectTimeout(100*time.Millisecond),
	)
	if err != nil {
		t.Fatal(err)
	}
	defer func() {
		if err := testScanner.Close(); err != nil {
			t.Logf("Error closing scanner: %v", err)
		}
	}()

	originalScanner := scanner
	scanner = testScanner
	defer func() {
		scanner = originalScanner
	}()

	request := ScanRequest{
		Hosts: []string{"localhost", "127.0.0.1", "::1"},
		Ports: portscan.Range(1, 50),
	}

	body, err := json.Marshal(request)
	if err != nil {
		t.Fatal(err)
	}

	req, err := http.NewRequest("POST", "/scan", bytes.NewBuffer(body))
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set("Content-Type", "application/json")

	rr := httptest.NewRecorder()
	handler := http.HandlerFunc(scanHandler)

	handler.ServeHTTP(rr, req)

	if status := rr.Code; status != http.StatusOK {
		t.Errorf("Expected status 200, got %v", status)
	}

	var response ScanResponse
	if err := json.NewDecoder(rr.Body).Decode(&response); err != nil {
		t.Fatal(err)
	}

	expectedResults := len(request.Hosts) * len(request.Ports)
	t.Logf("Large scan: %d results (expected up to %d)", len(response.Results), expectedResults)
}

// Вспомогательная функция для проверки наличия подстроки
func contains(s, substr string) bool {
	return len(s) >= len(substr) && (s == substr || len(s) > 0 && containsHelper(s, substr))
}

func containsHelper(s, substr string) bool {
	for i := 0; i <= len(s)-len(substr); i++ {
		if s[i:i+len(substr)] == substr {
			return true
		}
	}
	return false
}

// Бенчмарк для HTTP обработчиков
func BenchmarkHealthHandler(b *testing.B) {
	req, err := http.NewRequest("GET", "/health", nil)
	if err != nil {
		b.Fatal(err)
	}

	for i := 0; i < b.N; i++ {
		rr := httptest.NewRecorder()
		handler := http.HandlerFunc(healthHandler)
		handler.ServeHTTP(rr, req)
	}
}

func BenchmarkIndexHandler(b *testing.B) {
	req, err := http.NewRequest("GET", "/", nil)
	if err != nil {
		b.Fatal(err)
	}

	for i := 0; i < b.N; i++ {
		rr := httptest.NewRecorder()
		handler := http.HandlerFunc(indexHandler)
		handler.ServeHTTP(rr, req)
	}
}

func BenchmarkScanHandler(b *testing.B) {
	if testing.Short() {
		b.Skip("Skipping benchmark in short mode")
	}

	testScanner, err := portscan.New(
		portscan.WithConcurrency(10),
		portscan.WithConnectTimeout(100*time.Millisecond),
	)
	if err != nil {
		b.Fatal(err)
	}
	defer func() {
		if err := testScanner.Close(); err != nil {
			b.Logf("Error closing scanner: %v", err)
		}
	}()

	originalScanner := scanner
	scanner = testScanner
	defer func() {
		scanner = originalScanner
	}()

	request := ScanRequest{
		Hosts: []string{"localhost"},
		Ports: []int{80, 443},
	}

	body, err := json.Marshal(request)
	if err != nil {
		b.Fatal(err)
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		req, err := http.NewRequest("POST", "/scan", bytes.NewBuffer(body))
		if err != nil {
			b.Fatal(err)
		}
		req.Header.Set("Content-Type", "application/json")

		rr := httptest.NewRecorder()
		handler := http.HandlerFunc(scanHandler)
		handler.ServeHTTP(rr, req)
	}
}

func BenchmarkScanHandlerWithLargePorts(b *testing.B) {
	if testing.Short() {
		b.Skip("Skipping benchmark in short mode")
	}

	testScanner, err := portscan.New(
		portscan.WithConcurrency(50),
		portscan.WithConnectTimeout(100*time.Millisecond),
	)
	if err != nil {
		b.Fatal(err)
	}
	defer func() {
		if err := testScanner.Close(); err != nil {
			b.Logf("Error closing scanner: %v", err)
		}
	}()

	originalScanner := scanner
	scanner = testScanner
	defer func() {
		scanner = originalScanner
	}()

	request := ScanRequest{
		Hosts: []string{"localhost"},
		Ports: portscan.Range(1, 50),
	}

	body, err := json.Marshal(request)
	if err != nil {
		b.Fatal(err)
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		req, err := http.NewRequest("POST", "/scan", bytes.NewBuffer(body))
		if err != nil {
			b.Fatal(err)
		}
		req.Header.Set("Content-Type", "application/json")

		rr := httptest.NewRecorder()
		handler := http.HandlerFunc(scanHandler)
		handler.ServeHTTP(rr, req)
	}
}
