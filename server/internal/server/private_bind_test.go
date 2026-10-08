package server

import (
	"net"
	"testing"
)

type privateAddress string

func (a privateAddress) Network() string { return "test" }
func (a privateAddress) String() string  { return string(a) }

func TestPrivateBindRequiresExplicitPrivateScope(t *testing.T) {
	for _, bind := range []string{"127.0.0.1:14443", "10.0.0.4:14443", "[::1]:14443", "[fd00::4]:14443"} {
		if got, err := privateBindAddress(bind, ""); err != nil || got != bind {
			t.Fatalf("private bind rejected: %q %v", got, err)
		}
	}
	for _, bind := range []string{":14443", "0.0.0.0:14443", "[::]:14443", "8.8.8.8:14443", "localhost:14443", "127.0.0.1:014443", "127.0.0.1:0", "[fe80::1%eth0]:14443"} {
		if _, err := privateBindAddress(bind, ""); err == nil {
			t.Fatal("public or ambiguous bind accepted", bind)
		}
	}
	if _, err := privateBindAddress(":14443", "rabbit-missing-interface-fixture"); err == nil {
		t.Fatal("missing interface accepted")
	}
	if _, err := privateBindAddress("10.0.0.4:14443", "eth0"); err == nil {
		t.Fatal("both interface and literal host accepted")
	}
}

func TestPrivateInterfaceRequiresOneDistinctPrivateAddress(t *testing.T) {
	for _, tc := range []struct {
		name      string
		addresses []net.Addr
		want      string
	}{
		{"private ipv4", []net.Addr{privateAddress("10.0.0.4/24")}, "10.0.0.4"},
		{"private ipv6", []net.Addr{privateAddress("fd00::4/64")}, "fd00::4"},
		{"duplicate address", []net.Addr{privateAddress("10.0.0.4/24"), privateAddress("10.0.0.4/32")}, "10.0.0.4"},
		{"skip public and link local", []net.Addr{privateAddress("8.8.8.8/32"), privateAddress("fe80::1/64"), privateAddress("10.0.0.4/24")}, "10.0.0.4"},
		{"missing", nil, ""},
		{"public only", []net.Addr{privateAddress("8.8.8.8/32")}, ""},
		{"loopback only", []net.Addr{privateAddress("127.0.0.1/8")}, ""},
		{"invalid", []net.Addr{privateAddress("not-an-address")}, ""},
		{"multiple ipv4", []net.Addr{privateAddress("10.0.0.4/24"), privateAddress("10.0.0.5/24")}, ""},
		{"dual stack", []net.Addr{privateAddress("10.0.0.4/24"), privateAddress("fd00::4/64")}, ""},
	} {
		t.Run(tc.name, func(t *testing.T) {
			got, err := onePrivateInterfaceAddress(tc.addresses)
			if tc.want == "" {
				if err == nil {
					t.Fatal("ambiguous interface accepted", got)
				}
			} else if err != nil || got != tc.want {
				t.Fatalf("got %q %v; want %q", got, err, tc.want)
			}
		})
	}
}
