package main

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
)

var webhookSecret string = os.Getenv("WEBHOOK_SECRET")

func validateSignature(payload []byte, signature string) bool {
	if len(signature) != 71 || signature[:7] != "sha256=" {
		return false
	}

	mac := hmac.New(sha256.New, []byte(webhookSecret))
	mac.Write(payload)
	expectedMAC := hex.EncodeToString(mac.Sum(nil))

	return hmac.Equal([]byte(expectedMAC), []byte(signature[7:]))
}

func webhookHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	body, err := io.ReadAll(r.Body)
	if err != nil {
		http.Error(w, "Error reading request body", http.StatusInternalServerError)
		return
	}

	signature := r.Header.Get("X-Hub-Signature-256")
	if !validateSignature(body, signature) {
		http.Error(w, "Invalid signature", http.StatusUnauthorized)
		return
	}

	fmt.Println("Signature: ", signature)
	fmt.Println("Received request:", r)
	fmt.Printf("Payload: %s\n", string(body))

	w.WriteHeader(http.StatusOK)

}

func main() {
	http.HandleFunc("/webhook", webhookHandler)

	fmt.Println("Starting webhook listener on :8080")
	if err := http.ListenAndServe(":8080", nil); err != nil {
		log.Fatal(err)
	}
}
