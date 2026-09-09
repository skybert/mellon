package main

import (
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"path"
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

type mtlsClient struct {
	clientID   string
	clientCert *x509.Certificate
	// either subject distinguished name (DN), or single subject
	// alternative name (SAN)
	clientSubject string
}

type cnf struct {
	X5tS256 string `json:"x5t#S256"`
}

type mtlsToken struct {
	Iss string `json:"iss"`
	Sub string `json:"sub"`
	Exp int64  `json:"exp"`
	Nbf int64  `json:"nbf"`
	Cnf cnf    `json:"cnf"`
}

func (c *mtlsClient) CertThumbPrint() string {
	// https://www.rfc-editor.org/rfc/rfc8705.html#section-3.1-2
	// (1) DER encode cert, returned in clientCert.Raw
	// (2) sha256 encode it
	sum := sha256.Sum256(c.clientCert.Raw)

	// (3) base 64 URL encode
	//
	// (4) remove trailing padding, equal signs (RawURLEncoding
	// does this)
	urlEncodedHash := base64.RawURLEncoding.EncodeToString(sum[:])
	return string(urlEncodedHash)
}

func addRoutes(router *http.ServeMux, allowedClients []mtlsClient) {
	router.HandleFunc(
		"/ping",
		func(w http.ResponseWriter, req *http.Request) {
			debugTLS(req.TLS)
			io.WriteString(w, "pong\n")
		})
	router.HandleFunc(
		"/mtls-token",
		func(w http.ResponseWriter, req *http.Request) {
			debugTLS(req.TLS)
			if a, ac := allowedClient(req, allowedClients); a {
				t := mtlsToken{
					Iss: "",
					Sub: "",
					Exp: 0,
					Nbf: 0,
					Cnf: cnf{
						ac.CertThumbPrint(),
					},
				}
				j, err := json.Marshal(t)
				if err != nil {
					log.Printf("err=%v\n", err)

				}

				io.WriteString(w, string(j))
			} else {
				// See:
				// - https://www.rfc-editor.org/rfc/rfc8705.html#section-2-3
				// - https://www.rfc-editor.org/info/rfc6749/#section-5.2
				w.WriteHeader(400)
				io.WriteString(w, "invalid_client")
			}

		})
	router.HandleFunc(
		"/mtls-introspect",
		func(w http.ResponseWriter, req *http.Request) {
			debugTLS(req.TLS)
			t := ""
			io.WriteString(w, t)
		})
}

func allowedClient(req *http.Request, allowedClients []mtlsClient) (bool, mtlsClient) {
	if err := req.ParseForm(); err != nil {
		return false, mtlsClient{}
	}
	clientID := req.FormValue("client_id")

	// exit/fail fast
	if clientID == "" {
		return false, mtlsClient{}
	}

	for _, allowedClient := range allowedClients {
		if allowedClient.clientID == clientID {
			// validates according to spec
			// https://www.rfc-editor.org/rfc/rfc8705.html#section-2.1
			reqSubject := req.TLS.PeerCertificates[0].Subject.String()
			log.Printf(
				"\treq sub=%s, registered client_id=%s has defined allowed sub=%s, match=%t\n",
				reqSubject,
				allowedClient.clientID,
				allowedClient.clientSubject,
				reqSubject == allowedClient.clientSubject,
			)

			if reqSubject == allowedClient.clientSubject {
				return true, allowedClient
			}
		}
	}

	return false, mtlsClient{}
}

func mtlsServer(allowedClients []mtlsClient) *http.Server {
	certPool := certPool("etc/certs/ca.crt")
	router := http.NewServeMux()
	addRoutes(router, allowedClients)

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
	clients := registerClients("etc/certs/client.crt")
	fmt.Printf("Allowed mTLS clients: %v\n", clients)

	srv := mtlsServer(clients)
	log.Printf("Starting mTLS server on port %d", port)
	err := srv.ListenAndServeTLS(
		"etc/certs/server.crt",
		"etc/certs/server.key",
	)

	if err != nil {
		log.Fatal(err)
	}
}

func registerClients(fn string) []mtlsClient {
	// TODO read a list of client certs

	s, err := os.ReadFile(fn)
	if err != nil {
		log.Fatal(err)
	}

	// The clients public certificates are all in PEM format, see
	// ../bin/create-certs
	block, _ := pem.Decode(s)
	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		log.Fatal(err)
	}

	// client id is the base name of fn
	return []mtlsClient{
		{
			// the base file name is the client id
			clientID:   path.Base(fn),
			clientCert: cert,
			// TODO check for SAN, then subject
			clientSubject: cert.Subject.String(),
		},
	}
}
