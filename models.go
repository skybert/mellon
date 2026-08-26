package main

// Options for the CLI. Pass `--port` or set the `SERVICE_PORT` env var.
type Options struct {
	Port int `help:"Port to listen on" short:"p" default:"9443"`
}

type GreetingInput struct {
	Name string `path:"name" maxLength:"30" example:"world" doc:"Name to greet"`
}

// GreetingOutput represents the greeting operation response.
type GreetingOutput struct {
	Body struct {
		Message    string `json:"message" example:"Mate" doc:"Speak friend and enter"`
		ClientCert string `json:"client_cert"`
		Crypto     string `json:"crypto"`
	}
}
