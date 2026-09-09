package main

import (
	"crypto/tls"
	"testing"
)

func Test_mtlsClient_CertThumbPrint(t *testing.T) {
	cert, err := tls.LoadX509KeyPair(
		"../etc/certs/client.crt",
		"../etc/certs/client.key",
	)
	if err != nil {
		t.Errorf("CertThumbPrint() failed: %v", err)
	}

	tests := []struct {
		name string // description of this test case
		want string
	}{
		{
			"happy",
			"v6furmGsYkdrAML-3B0vK6jXkbj9fSF0cjgmP_FElYY",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// TODO: construct the receiver type.
			var c mtlsClient = mtlsClient{
				clientID:      "foo-client-id",
				clientCert:    cert.Leaf,
				clientSubject: "foo",
			}
			got := c.CertThumbPrint()
			if tt.want != got {
				t.Errorf("CertThumbPrint() = %v, want %v", got, tt.want)
			}
		})
	}
}
