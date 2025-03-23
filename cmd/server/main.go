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

func mTLSMiddleware(clientCAs *x509.CertPool, verifyPeerCertificate func(*x509.Certificate) error, next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.TLS == nil || len(r.TLS.PeerCertificates) == 0 {
			http.Error(w, "required client certificate", http.StatusUnauthorized)
			return
		}

		opts := x509.VerifyOptions{
			Intermediates: x509.NewCertPool(),
			Roots:         clientCAs,
			KeyUsages:     []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
		}

		for _, cert := range r.TLS.PeerCertificates[1:] {
			opts.Intermediates.AddCert(cert)
		}

		cert := r.TLS.PeerCertificates[0]

		if _, err := cert.Verify(opts); err != nil {
			http.Error(w, "failed to verify certificate: "+err.Error(), http.StatusUnauthorized)
			return
		}

		if verifyPeerCertificate != nil {
			if err := verifyPeerCertificate(cert); err != nil {
				http.Error(w, "failed to verify peer certificate: "+err.Error(), http.StatusUnauthorized)
				return
			}
		}

		next.ServeHTTP(w, r)
	})
}

func ping(w http.ResponseWriter, _ *http.Request) {
	w.WriteHeader(http.StatusOK)
	w.Write([]byte("pong"))
}

func main() {
	clientCaCertPool := x509.NewCertPool()
	clientCaCertPem, err := os.ReadFile("./cert/client-ca.pem")
	if err != nil {
		log.Fatal(err)
	}

	if !clientCaCertPool.AppendCertsFromPEM(clientCaCertPem) {
		log.Fatal("failed to append certs from pem")
	}

	handler := http.NewServeMux()
	handler.Handle("GET /ping", mTLSMiddleware(clientCaCertPool, nil, http.HandlerFunc(ping)))

	tlsCfg := &tls.Config{
		ClientAuth: tls.RequestClientCert,
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
