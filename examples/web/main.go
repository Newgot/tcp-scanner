package main

import (
	"context"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"time"

	portscan "github.com/Newgot/tcp-scanner"
)

type ScanRequest struct {
	Hosts       []string `json:"hosts"`
	Ports       []int    `json:"ports"`
	Concurrency int      `json:"concurrency,omitempty"`
	Timeout     string   `json:"timeout,omitempty"`
}

type ScanResponse struct {
	Results []portscan.Result    `json:"results"`
	Stats   portscan.ResultStats `json:"stats"`
	Time    string               `json:"time"`
}

var scanner *portscan.Scanner

func init() {
	var err error
	scanner, err = portscan.New(
		portscan.WithConcurrency(100),
		portscan.WithConnectTimeout(500*time.Millisecond),
	)
	if err != nil {
		log.Fatal(err)
	}
}

func main() {
	defer func() {
		if err := scanner.Close(); err != nil {
			log.Printf("Error closing scanner: %v", err)
		}
	}()

	http.HandleFunc("/scan", scanHandler)
	http.HandleFunc("/health", healthHandler)
	http.HandleFunc("/", indexHandler)

	fmt.Println("🌐 HTTP сервер запущен на http://localhost:8080")
	fmt.Println("📡 Используйте POST /scan для сканирования")
	fmt.Println("   Пример: curl -X POST http://localhost:8080/scan -d '{\"hosts\":[\"localhost\"],\"ports\":[80,443,8080]}'")

	if err := http.ListenAndServe(":8080", nil); err != nil {
		log.Fatal(err)
	}
}

func scanHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	var req ScanRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "Invalid JSON: "+err.Error(), http.StatusBadRequest)
		return
	}

	if len(req.Hosts) == 0 {
		http.Error(w, "No hosts specified", http.StatusBadRequest)
		return
	}
	if len(req.Ports) == 0 {
		http.Error(w, "No ports specified", http.StatusBadRequest)
		return
	}

	timeout := 30 * time.Second
	if req.Timeout != "" {
		if d, err := time.ParseDuration(req.Timeout); err == nil {
			timeout = d
		}
	}

	start := time.Now()
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()

	results, err := scanner.Scan(ctx, req.Hosts, req.Ports)
	if err != nil {
		http.Error(w, "Scan failed: "+err.Error(), http.StatusInternalServerError)
		return
	}

	var allResults []portscan.Result
	for result := range results {
		allResults = append(allResults, result)
	}

	response := ScanResponse{
		Results: allResults,
		Stats:   portscan.Stats(allResults),
		Time:    time.Since(start).String(),
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	if err := json.NewEncoder(w).Encode(response); err != nil {
		http.Error(w, "Failed to encode response: "+err.Error(), http.StatusInternalServerError)
	}
}

func healthHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	if err := json.NewEncoder(w).Encode(map[string]string{
		"status":  "ok",
		"service": "port-scanner",
	}); err != nil {
		http.Error(w, "Failed to encode response: "+err.Error(), http.StatusInternalServerError)
	}
}

func indexHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	html := `<!DOCTYPE html>
<html>
<head>
    <title>Port Scanner API</title>
    <style>
        body { font-family: Arial, sans-serif; margin: 40px; background: #f5f5f5; }
        .container { max-width: 800px; margin: 0 auto; background: white; padding: 30px; border-radius: 10px; box-shadow: 0 2px 10px rgba(0,0,0,0.1); }
        h1 { color: #333; }
        .endpoint { background: #f0f0f0; padding: 15px; margin: 15px 0; border-radius: 5px; border-left: 4px solid #007bff; }
        .endpoint h3 { margin-top: 0; color: #007bff; }
        code { background: #e0e0e0; padding: 2px 6px; border-radius: 3px; font-family: monospace; }
        pre { background: #2d2d2d; color: #f8f8f2; padding: 15px; border-radius: 5px; overflow-x: auto; }
        .method { display: inline-block; padding: 2px 8px; border-radius: 3px; font-weight: bold; }
        .get { background: #28a745; color: white; }
        .post { background: #007bff; color: white; }
        .footer { margin-top: 30px; color: #666; font-size: 14px; }
    </style>
</head>
<body>
    <div class="container">
        <h1>🚀 Port Scanner API</h1>
        <p>HTTP API для сканирования TCP-портов</p>
        
        <div class="endpoint">
            <h3><span class="method post">POST</span> /scan</h3>
            <p>Сканирование портов на указанных хостах</p>
            <p><strong>Тело запроса (JSON):</strong></p>
            <pre>{
    "hosts": ["localhost", "google.com"],
    "ports": [80, 443, 8080],
    "concurrency": 50,
    "timeout": "10s"
}</pre>
            <p><strong>Пример cURL:</strong></p>
            <pre>curl -X POST http://localhost:8080/scan \
  -H "Content-Type: application/json" \
  -d '{"hosts":["localhost"],"ports":[80,443,8080]}'</pre>
        </div>
        
        <div class="endpoint">
            <h3><span class="method get">GET</span> /health</h3>
            <p>Проверка статуса сервиса</p>
            <pre>curl http://localhost:8080/health</pre>
        </div>
        
        <div class="footer">
            <p>🔍 Port Scanner v1.0.0 | Go TCP Scanner</p>
        </div>
    </div>
</body>
</html>`

	w.Header().Set("Content-Type", "text/html")
	w.WriteHeader(http.StatusOK)
	if _, err := w.Write([]byte(html)); err != nil {
		log.Printf("Failed to write response: %v", err)
	}
}
