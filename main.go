package main

import (
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"log"
	"net/http"
	"os"
)

func main() {
	router := http.NewServeMux()
	router.HandleFunc("/ping", func(writer http.ResponseWriter, req *http.Request) {
		for i, vc := range req.TLS.VerifiedChains {
			for j, vcc := range vc {
				log.Printf("%d/%d verified chain: %v\n", i, j, vcc.Subject.String())
			}
		}

		log.Printf(
			"tls version: %v, cipher suite: %v\n",
			tls.VersionName(req.TLS.Version),
			tls.CipherSuiteName(req.TLS.CipherSuite),
		)

	})
	srv := &http.Server{
		Addr:    fmt.Sprintf(":%d", 9443),
		Handler: router,
		TLSConfig: &tls.Config{
			ClientCAs:  certPool(),
			ClientAuth: tls.RequireAndVerifyClientCert,
			MinVersion: tls.VersionTLS13,
		},
	}

	log.Printf("Running on %v\n", srv.Addr)
	err := srv.ListenAndServeTLS(
		"etc/certs/server.crt",
		"etc/certs/server.key")

	if err != nil {
		log.Fatal(err)
	}
}

func certPool() *x509.CertPool {
	caPEM, err := os.ReadFile("etc/certs/ca.crt")
	if err != nil {
		log.Fatal(err)
	}

	pool := x509.NewCertPool()
	if !pool.AppendCertsFromPEM(caPEM) {
		log.Fatal("cannot load CA")
	}

	return pool
}
