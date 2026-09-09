package server

import (
	"testing"
)

func TestListenerFailsClosedWithoutTLS(t *testing.T) {
	for _, name := range []string{"RABBIT_TLS_CERT_PEM", "RABBIT_TLS_KEY_PEM", "RABBIT_TLS_CERT_FILE", "RABBIT_TLS_KEY_FILE", "RABBIT_ALLOW_INSECURE_LOCAL"} {
		t.Setenv(name, "")
	}
	if l, err := controlListener("127.0.0.1:0"); err == nil {
		l.Close()
		t.Fatal("TLS not required")
	}
	t.Setenv("RABBIT_ALLOW_INSECURE_LOCAL", "true")
	t.Setenv("ENVIRONMENT", "development")
	l, err := controlListener("127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	l.Close()
	if l, err := controlListener("0.0.0.0:0"); err == nil {
		l.Close()
		t.Fatal("allowed publicly bound plaintext")
	}
	t.Setenv("ENVIRONMENT", "production")
	if l, err := controlListener("127.0.0.1:0"); err == nil {
		l.Close()
		t.Fatal("allowed production plaintext")
	}
}
