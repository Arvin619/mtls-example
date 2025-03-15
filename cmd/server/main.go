package main

import (
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"log"
	"net/http"
	"os"
)

const (
	port = 8443
)

func mTLSMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.TLS == nil || len(r.TLS.PeerCertificates) == 0 {
			http.Error(w, "required client certificate", http.StatusUnauthorized)
			return
		}

		fmt.Println(r.TLS.PeerCertificates[0].Subject.CommonName)

		next.ServeHTTP(w, r)
	})
}

func ping(w http.ResponseWriter, _ *http.Request) {
	w.WriteHeader(http.StatusOK)
	w.Write([]byte("pong"))
}

func main() {
	handler := http.NewServeMux()
	handler.Handle("GET /ping", mTLSMiddleware(http.HandlerFunc(ping)))

	clientCaCertPool := x509.NewCertPool()
	clientCaCertPem, err := os.ReadFile("./cert/client-ca.pem")
	if err != nil {
		log.Fatal(err)
	}
	if !clientCaCertPool.AppendCertsFromPEM(clientCaCertPem) {
		log.Fatal("failed to append certs from pem")
	}

	tlsCfg := &tls.Config{
		ClientCAs:  clientCaCertPool,
		ClientAuth: tls.RequireAndVerifyClientCert,
	}

	srv := http.Server{
		Addr:      fmt.Sprintf(":%d", port),
		Handler:   handler,
		TLSConfig: tlsCfg,
	}

	log.Printf("HTTPS Server listen on :%d\n", port)
	if err := srv.ListenAndServeTLS("./cert/server.pem", "./cert/server-key.pem"); err != nil {
		log.Fatal(err)
	}
}
