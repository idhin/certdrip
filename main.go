package main

import (
	"context"
	"crypto/x509"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"sync"
	"time"

	ct "github.com/google/certificate-transparency-go"
	ctclient "github.com/google/certificate-transparency-go/client"
	"github.com/google/certificate-transparency-go/jsonclient"
	"github.com/gorilla/websocket"
)

var (
	ctLogURL   = "https://ct.googleapis.com/logs/argon2023"
	broadcast  = make(chan []byte)
	clients    = make(map[*websocket.Conn]bool)
	mu         sync.Mutex
	upgrader   = websocket.Upgrader{}
)

func main() {
	go pollCT()
	go handleBroadcast()

	http.HandleFunc("/ws", handleWS)
	fmt.Println("[+] WebSocket server running at :8080/ws")
	log.Fatal(http.ListenAndServe(":8080", nil))
}

func pollCT() {
	ctx := context.Background()

	client, err := ctclient.New(ctLogURL, nil, jsonclient.Options{})
	if err != nil {
		log.Fatalf("Failed to create CT client: %v", err)
	}

	sth, err := client.GetSTH(ctx)
	if err != nil {
		log.Fatalf("Failed to get STH: %v", err)
	}

	start := int64(sth.TreeSize - 50)
	if start < 0 {
		start = 0
	}

	for {
		entries, err := client.GetEntries(ctx, start, start+10)
		if err != nil {
			log.Printf("GetEntries error: %v", err)
			time.Sleep(5 * time.Second)
			continue
		}

		for _, e := range entries {
			if e.X509Cert != nil {
				processCert(e.X509Cert)
			} else if len(e.Chain) > 0 {
				processCert(e.Chain[0])
			}
		}

		start += 10
		time.Sleep(2 * time.Second)
	}
}

func processCert(cert *x509.Certificate) {
	if cert == nil {
		return
	}

	msg := map[string]interface{}{
		"domain":     cert.Subject.CommonName,
		"sans":       cert.DNSNames,
		"issuer":     cert.Issuer.CommonName,
		"not_before": cert.NotBefore,
		"not_after":  cert.NotAfter,
		"timestamp":  time.Now().UTC(),
	}
	payload, _ := json.Marshal(msg)
	broadcast <- payload
}

func handleWS(w http.ResponseWriter, r *http.Request) {
	conn, err := upgrader.Upgrade(w, r, nil)
	if err != nil {
		log.Printf("WebSocket upgrade failed: %v", err)
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
