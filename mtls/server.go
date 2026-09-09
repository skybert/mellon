package main

import (
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
)

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

const port = 9443

func debugTLS(tlsConnection *tls.ConnectionState) {
	clientCert := tlsConnection.PeerCertificates[0]
	log.Printf("Public key alg: %s, signature alg: %s, TLS version: %s, cipher suite: %v\n",
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

func addRoutes(router *http.ServeMux) {
	router.HandleFunc(
		"/ping",
		func(w http.ResponseWriter, req *http.Request) {
			debugTLS(req.TLS)
			io.WriteString(w, "pong\n")
		})
}

func mtlsServer() *http.Server {
	certPool := certPool("etc/certs/ca.crt")
	router := http.NewServeMux()
	addRoutes(router)

	srv := &http.Server{
		Addr:    fmt.Sprintf(":%d", port),
		Handler: router,
		TLSConfig: &tls.Config{
			ClientAuth: tls.RequireAndVerifyClientCert,
			ClientCAs:  certPool,
			MinVersion: tls.VersionTLS13,
		},
	}

	return srv

}

func main() {
	srv := mtlsServer()
	log.Printf("Starting mTLS server on port %d", port)
	err := srv.ListenAndServeTLS(
		"etc/certs/server.crt",
		"etc/certs/server.key",
	)

	if err != nil {
		log.Fatal(err)
	}
}
