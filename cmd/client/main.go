package main

import (
	"crypto/tls"
	"crypto/x509"
	"errors"
	"flag"
	"io"
	"log"
	"net/http"
	"os"
)

var (
	sendPriv bool
	sendPub  bool
	useMTLS  bool
)

func setFlag() {
	flag.BoolVar(&sendPriv, "private", false, "send private ping api")
	flag.BoolVar(&sendPub, "public", false, "send public ping api")
	flag.BoolVar(&useMTLS, "use-mtls", false, "set http client to use mtls")
}

func setHttpClient() (*http.Client, error) {
	serverCaCertPool := x509.NewCertPool()
	serverCaCertPem, err := os.ReadFile("./cert/server-ca.pem")
	if err != nil {
		return nil, err
	}
	if !serverCaCertPool.AppendCertsFromPEM(serverCaCertPem) {
		return nil, errors.New("failed to append certs from pem")
	}

	var certs []tls.Certificate
	if useMTLS {
		cert, err := tls.LoadX509KeyPair("./cert/client.pem", "./cert/client-key.pem")
		if err != nil {
			return nil, err
		}
		certs = append(certs, cert)
	}

	client := &http.Client{
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{
				RootCAs:      serverCaCertPool,
				Certificates: certs,
			},
		},
	}

	return client, nil
}

func sendPrivatePing(client *http.Client) error {
	req, err := http.NewRequest(http.MethodGet, "https://localhost:8443/private/ping", nil)
	if err != nil {
		return err
	}
	resp, err := client.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	io.Copy(os.Stdout, resp.Body)

	return nil
}

func sendPublicPing(client *http.Client) error {
	req, err := http.NewRequest(http.MethodGet, "https://localhost:8443/public/ping", nil)
	if err != nil {
		return err
	}
	resp, err := client.Do(req)
	if err != nil {
		log.Fatal(err)
	}
	defer resp.Body.Close()

	io.Copy(os.Stdout, resp.Body)

	return nil
}

func main() {
	setFlag()
	flag.Parse()

	client, err := setHttpClient()
	if err != nil {
		log.Fatal(err)
	}

	if sendPriv {
		if err := sendPrivatePing(client); err != nil {
			log.Fatal(err)
		}
	}

	if sendPub {
		if err := sendPublicPing(client); err != nil {
			log.Fatal(err)
		}
	}
}
