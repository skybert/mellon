package main

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"log"
	"net/http"
	"os"

	"github.com/danielgtaylor/huma/v2"
	"github.com/danielgtaylor/huma/v2/adapters/humago"
	"github.com/danielgtaylor/huma/v2/humacli"

	_ "github.com/danielgtaylor/huma/v2/formats/cbor"
)

func main() {
	pool := certPool("etc/certs/ca.crt")

	cli := humacli.New(func(hooks humacli.Hooks, options *Options) {
		router := http.NewServeMux()
		srv := &http.Server{
			Addr:    fmt.Sprintf(":%d", options.Port),
			Handler: router,
			TLSConfig: &tls.Config{
				ClientAuth: tls.RequireAndVerifyClientCert,
				ClientCAs:  pool,
				MinVersion: tls.VersionTLS13,
			},
		}
		api := humago.New(router, huma.DefaultConfig(
			"Mellon - speak friend and enter",
			"0.0.1"))
		addMiddleware(api)
		addRoutes(api)
		hooks.OnStart(func() {
			fmt.Printf("Mellon listening on port %v\n", options.Port)
			err := srv.ListenAndServeTLS(
				"etc/certs/server.crt",
				"etc/certs/server.key",
			)
			if err != nil {
				panic(err)
			}
		})
	})

	cli.Run()
}

type ctxKey string

const (
	reqKey ctxKey = "http.request"
	tlsKey ctxKey = "tls.state"
)

func addMiddleware(api huma.API) {
	api.UseMiddleware(
		func(ctx huma.Context, next func(huma.Context)) {
			// read the original request, ignore the response
			r, _ := humago.Unwrap(ctx)
			ctx = huma.WithValue(ctx, reqKey, r)
			ctx = huma.WithValue(ctx, tlsKey, ctx.TLS())
			next(ctx)
		},
	)
}

func certPool(caCert string) *x509.CertPool {
	caPEM, err := os.ReadFile(caCert)
	if err != nil {
		log.Fatal(err)
	}
	pool := x509.NewCertPool()
	if !pool.AppendCertsFromPEM(caPEM) {
		log.Fatal("couldn't add certificates")
	}

	return pool
}

func addRoutes(api huma.API) {
	huma.Get(api, "/greeting/{name}", func(ctx context.Context, input *GreetingInput) (*GreetingOutput, error) {
		treq, _ := ctx.Value(tlsKey).(*tls.ConnectionState)
		if treq == nil {
			return nil, huma.Error400BadRequest("Only mTLS is supported")
		}

		resp := &GreetingOutput{}
		for i, vc := range treq.VerifiedChains {
			for j, vcc := range vc {
				fmt.Printf(
					"Verified chain: %d/%d, subject: %v, issuer: %v, ca: %t\n",
					i,
					j,
					vcc.Subject,
					vcc.Issuer.String(),
					vcc.IsCA)
			}
		}

		if len(treq.PeerCertificates) == 0 {
			// Impossible as long as we're using
			// ClientAuth: tls.RequireAndVerifyClientCert,
			// see above.
			return nil, huma.Error400BadRequest("Only mTLS is supported")
		}

		// The First leaf in the verified chain(s) is be
		// the client's certificate according to the standard lib doc.
		clientCertInVerifiedChain := treq.VerifiedChains[0][0]
		clientCert := treq.PeerCertificates[0]
		if clientCertInVerifiedChain.Subject.String() == clientCert.Subject.String() {
			resp.Body.Message = fmt.Sprintf(
				"Hi, %s you're connected using mTLS", clientCert.Subject.CommonName)
			resp.Body.ClientCert = fmt.Sprintf(
				"subject: %s, issuer: %s",
				clientCert.Subject.String(),
				clientCert.Issuer.String())
			resp.Body.Crypto = cryptoInfo(treq, clientCert)
		}

		return resp, nil
	})
}

func cryptoInfo(treq *tls.ConnectionState, cert *x509.Certificate) string {
	return fmt.Sprintf(
		"public key alg: %s, signing alg: %s, TLS version: %v, TLS cipher suite used: %v",
		cert.PublicKeyAlgorithm.String(),
		cert.SignatureAlgorithm.String(),
		tls.VersionName(treq.Version),
		tls.CipherSuiteName(treq.CipherSuite),
	)
}
