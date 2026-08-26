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

// Options for the CLI. Pass `--port` or set the `SERVICE_PORT` env var.
type Options struct {
	Port int `help:"Port to listen on" short:"p" default:"8888"`
}

// GreetingOutput represents the greeting operation response.
type GreetingOutput struct {
	Body struct {
		Message string `json:"message" example:"Hello, world!" doc:"Greeting message"`
	}
}

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
				MinVersion: tls.VersionTLS12,
			},
		}
		api := humago.New(router, huma.DefaultConfig("Mellon", "0.0.1"))
		addRoutes(api)
		addMiddleware(api)
		hooks.OnStart(func() {
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
			// read the request, ignore the response
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
		log.Fatal("couldn't add certs")
	}

	return pool
}

func addRoutes(api huma.API) {
	huma.Get(api, "/greeting/{name}", func(ctx context.Context, input *struct {
		Name string `path:"name" maxLength:"30" example:"world" doc:"Name to greet"`
	}) (*GreetingOutput, error) {
		treq, _ := ctx.Value(tlsKey).(*tls.ConnectionState)
		fmt.Printf("%v\n", treq)

		resp := &GreetingOutput{}
		resp.Body.Message = fmt.Sprintf("Hello, %s!", input.Name)
		return resp, nil
	})
}
