package main

import (
	"context"
	"crypto/x509"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"strings"
	"sync"
	"time"

	ctclient "github.com/google/certificate-transparency-go/client"
	"github.com/google/certificate-transparency-go/jsonclient"
	"github.com/gorilla/websocket"
)

type LogList struct {
	Operators []struct {
		Logs []struct {
			Description string `json:"description"`
			URL         string `json:"url"`
			State       struct {
				Usable struct {
					Timestamp string `json:"timestamp"`
					Version   string `json:"version"`
				} `json:"usable"`
			} `json:"state"`
		} `json:"logs"`
	} `json:"operators"`
}


var (
	broadcast     = make(chan []byte)
	clients       = make(map[*websocket.Conn]bool)
	seenDomains   = make(map[string]time.Time)
	cacheDuration = 5 * time.Minute
	mu            sync.Mutex
	upgrader      = websocket.Upgrader{}
)

func main() {
	ctLogURLs := fetchCTLogURLs()

	if len(ctLogURLs) == 0 {
		log.Fatal("No usable CT logs found.")
	}

	for _, logURL := range ctLogURLs {
		go pollCT(logURL)
	}

	go handleBroadcast()
	go trackRate()

	http.HandleFunc("/ws", handleWS)
	fmt.Println("[+] WebSocket server running at :8080/ws")
	log.Fatal(http.ListenAndServe(":8080", nil))
}

func fetchCTLogURLs() []string {
	url := "https://www.gstatic.com/ct/log_list/v3/log_list.json"
	resp, err := http.Get(url)
	if err != nil {
		log.Fatalf("Failed to fetch CT log list: %v", err)
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		log.Fatalf("Failed to read CT log list response: %v", err)
	}

	var raw map[string]interface{}
	if err := json.Unmarshal(body, &raw); err != nil {
		log.Fatalf("Failed to parse CT log list JSON: %v", err)
	}

	var ctLogs []string
	operators := raw["operators"].([]interface{})
	for _, operator := range operators {
		logs := operator.(map[string]interface{})["logs"].([]interface{})
		for _, l := range logs {
			logEntry := l.(map[string]interface{})
			state, ok := logEntry["state"].(map[string]interface{})
			if ok {
				if _, usable := state["usable"]; usable {
					url := logEntry["url"].(string)
					ctLogs = append(ctLogs, url)
				}
			}
		}
	}

	fmt.Printf("[*] Found %d usable CT logs.\n", len(ctLogs))
	return ctLogs
}



func pollCT(ctLogURL string) {
	ctx := context.Background()

	client, err := ctclient.New(ctLogURL, nil, jsonclient.Options{})
	if err != nil {
		log.Printf("CT client error on %s: %v", ctLogURL, err)
		return
	}

	start := int64(-1)

	for {
		if start == -1 {
			sth, err := client.GetSTH(ctx)
			if err != nil {
				log.Printf("Initial GetSTH error on %s: %v", ctLogURL, err)
				time.Sleep(2 * time.Second)
				continue
			}
			start = int64(sth.TreeSize)
			fmt.Printf("[*] [%s] Starting from TreeSize: %d\n", ctLogURL, start)
		}

		sth, err := client.GetSTH(ctx)
		if err != nil {
			log.Printf("GetSTH error on %s: %v", ctLogURL, err)
			time.Sleep(2 * time.Second)
			continue
		}

		treeSize := int64(sth.TreeSize)
		if start >= treeSize {
			time.Sleep(1 * time.Second)
			continue
		}

		batch := int64(100)
		end := start + batch
		if end > treeSize {
			end = treeSize
		}

		entries, err := client.GetEntries(ctx, start, end)
		if err != nil {
			log.Printf("GetEntries error on %s: %v", ctLogURL, err)
			time.Sleep(2 * time.Second)
			continue
		}

		for _, e := range entries {
			if e.X509Cert != nil {
				cert, err := x509.ParseCertificate(e.X509Cert.Raw)
				if err != nil {
					continue
				}
				processCert(cert)
			} else if len(e.Chain) > 0 {
				cert, err := x509.ParseCertificate(e.Chain[0].Data)
				if err != nil {
					continue
				}
				processCert(cert)
			}
		}

		start = end
		time.Sleep(100 * time.Millisecond)
	}
}

func processCert(cert *x509.Certificate) {
	if cert == nil {
		return
	}

	domain := cert.Subject.CommonName
	if domain == "" && len(cert.DNSNames) > 0 {
		domain = cert.DNSNames[0]
	}

	if domain == "" || len(domain) < 4 || strings.Contains(strings.ToLower(domain), "intermediate") {
		return
	}

	now := time.Now()
	mu.Lock()
	lastSeen, seen := seenDomains[domain]
	if seen && now.Sub(lastSeen) < cacheDuration {
		mu.Unlock()
		return
	}
	seenDomains[domain] = now
	mu.Unlock()

	msg := map[string]interface{}{
		"domain":     domain,
		"sans":       cert.DNSNames,
		"issuer":     cert.Issuer.CommonName,
		"not_before": cert.NotBefore,
		"not_after":  cert.NotAfter,
		"timestamp":  now.UTC(),
	}

	payload, _ := json.Marshal(msg)
	fmt.Printf("[+] %s\n", domain)
	broadcast <- payload
}

func handleWS(w http.ResponseWriter, r *http.Request) {
	conn, err := upgrader.Upgrade(w, r, nil)
	if err != nil {
		log.Printf("WS upgrade failed: %v", err)
		return
	}
	defer conn.Close()

	mu.Lock()
	clients[conn] = true
	mu.Unlock()

	for {
		if _, _, err := conn.NextReader(); err != nil {
			mu.Lock()
			delete(clients, conn)
			mu.Unlock()
			return
		}
	}
}

func handleBroadcast() {
	for {
		msg := <-broadcast
		mu.Lock()
		for conn := range clients {
			if err := conn.WriteMessage(websocket.TextMessage, msg); err != nil {
				conn.Close()
				delete(clients, conn)
			}
		}
		mu.Unlock()
	}
}

func trackRate() {
	ticker := time.NewTicker(1 * time.Second)
	var count int
	for {
		select {
		case <-ticker.C:
			fmt.Printf("Domains/sec: %d\n", count)
			count = 0
		case <-broadcast:
			count++
		}
	}
}
