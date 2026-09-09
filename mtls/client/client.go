package main

import (
	"crypto/tls"
	"crypto/x509"
	"io"
	"log"
	"net/http"
	"os"
)

func debugTLS(tlsConnection *tls.ConnectionState) {
	clientCert := tlsConnection.PeerCertificates[0]
	log.Printf(
		"Public key alg: %s, signature alg: %s, TLS version: %s, cipher suite: %v\n",
		clientCert.PublicKeyAlgorithm.String(),
		clientCert.SignatureAlgorithm.String(),
		tls.VersionName(tlsConnection.Version),
		tls.CipherSuiteName(tlsConnection.CipherSuite),
	)

	for i, chain := range tlsConnection.VerifiedChains {
		for j, cert := range chain {
			log.Printf(
				"\tVerified chain: %d/%d subject: %v issuer: %v ca: %t\n",
				i,
				j,
				cert.Subject,
				cert.Issuer,
				cert.IsCA)
		}
	}
}

func main() {
	client := mtlsClient()

	uri := "https://mellon.skybert:9443/ping"
	resp, err := client.Get(uri)
	if err != nil {
		log.Fatal(err)
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		log.Fatal(err)
	}
	log.Printf(
		"status: %s, headers: %v, body: %s",
		resp.Status,
		resp.Header,
		body,
	)
	debugTLS(resp.TLS)

}

func certPool(caFile string) *x509.CertPool {
	pem, err := os.ReadFile(caFile)
	if err != nil {
		log.Fatal(err)
	}
	pool := x509.NewCertPool()
	if !pool.AppendCertsFromPEM(pem) {
		log.Fatal("Couldn't load CA certificates")
	}

	return pool

}

func mtlsClient() *http.Client {
	cert, err := tls.LoadX509KeyPair(
		"etc/certs/client.crt",
		"etc/certs/client.key",
	)
	if err != nil {
		log.Fatal(err)
	}
	certPool := certPool("etc/certs/ca.crt")
	t := http.Transport{
		TLSClientConfig: &tls.Config{
			RootCAs:      certPool,
			Certificates: []tls.Certificate{cert},
		},
	}

	client := http.Client{
		Transport: &t,
	}

	return &client
}
