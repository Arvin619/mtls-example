package main

import (
	"crypto/tls"
	"crypto/x509"
	"io"
	"log"
	"net/http"
	"os"
)

func main() {
	serverCaCertPool := x509.NewCertPool()
	serverCaCertPem, err := os.ReadFile("./cert/server-ca.pem")
	if err != nil {
		log.Fatal(err)
	}
	if !serverCaCertPool.AppendCertsFromPEM(serverCaCertPem) {
		log.Fatal("failed to append certs from pem")
	}

	cert, err := tls.LoadX509KeyPair("./cert/client.pem", "./cert/client-key.pem")
	if err != nil {
		log.Fatal(err)
	}

	client := &http.Client{
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{
				RootCAs:      serverCaCertPool,
				Certificates: []tls.Certificate{cert},
			},
		},
	}

	req, err := http.NewRequest(http.MethodGet, "https://localhost:8443/ping", nil)
	if err != nil {
		log.Fatal(err)
	}

	resp, err := client.Do(req)
	if err != nil {
		log.Fatal(err)
	}
	defer resp.Body.Close()

	io.Copy(os.Stdout, resp.Body)
}
