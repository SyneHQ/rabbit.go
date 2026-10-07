package tunnel

import (
	"bufio"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"io"
	"net"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"golang.org/x/crypto/ssh"
	"golang.org/x/crypto/ssh/knownhosts"
)

func testSSHKey(t *testing.T) ssh.PublicKey {
	t.Helper()
	public, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	key, err := ssh.NewPublicKey(public)
	if err != nil {
		t.Fatal(err)
	}
	return key
}

func TestSSHKnownHostsRejectsUnknownAndChangedKeys(t *testing.T) {
	trusted, different := testSSHKey(t), testSSHKey(t)
	path := filepath.Join(t.TempDir(), "known_hosts")
	contents := knownhosts.Line([]string{"db.example", "[db.example]:2222"}, trusted) + "\n"
	if err := os.WriteFile(path, []byte(contents), 0600); err != nil {
		t.Fatal(err)
	}
	callback, err := sshKnownHostsCallback(path)
	if err != nil {
		t.Fatal(err)
	}
	for _, hostname := range []string{"db.example:22", "db.example:2222"} {
		_, port, _ := net.SplitHostPort(hostname)
		remote, err := net.ResolveTCPAddr("tcp", "127.0.0.1:"+port)
		if err != nil {
			t.Fatal(err)
		}
		if err := callback(hostname, remote, trusted); err != nil {
			t.Fatalf("rejected known host %q: %v", hostname, err)
		}
		var keyError *knownhosts.KeyError
		if err := callback(hostname, remote, different); err == nil || !errors.As(err, &keyError) || len(keyError.Want) == 0 {
			t.Fatalf("wrong host key was not rejected as a mismatch: %v", err)
		}
	}
	remote := &net.TCPAddr{IP: net.ParseIP("127.0.0.1"), Port: 22}
	var keyError *knownhosts.KeyError
	if err := callback("unknown.example:22", remote, trusted); err == nil || !errors.As(err, &keyError) || len(keyError.Want) != 0 || !strings.Contains(err.Error(), "unknown SSH host") {
		t.Fatalf("unknown host was not rejected explicitly: %v", err)
	}
	after, err := os.ReadFile(path)
	if err != nil || string(after) != contents {
		t.Fatalf("verification modified known_hosts: %v", err)
	}
}

func TestSSHKnownHostsFailsClosedWhenUnavailableOrEmpty(t *testing.T) {
	path := filepath.Join(t.TempDir(), "known_hosts")
	if callback, err := sshKnownHostsCallback(path); err == nil || callback != nil {
		t.Fatal("missing known_hosts did not fail closed")
	}
	if err := os.WriteFile(path, nil, 0600); err != nil {
		t.Fatal(err)
	}
	callback, err := sshKnownHostsCallback(path)
	if err != nil {
		t.Fatal(err)
	}
	if err := callback("db.example:22", &net.TCPAddr{IP: net.ParseIP("127.0.0.1"), Port: 22}, testSSHKey(t)); err == nil {
		t.Fatal("empty known_hosts trusted an unknown key")
	}
}

func TestSSHKnownHostsDefaultAndExplicitPaths(t *testing.T) {
	home, err := os.UserHomeDir()
	if err != nil {
		t.Fatal(err)
	}
	client, err := NewTunnel(TunnelConfig{SSHKeyPath: "/custom/client-key"})
	if err != nil {
		t.Fatal(err)
	}
	if client.Config.SSHKnownHostsPath != filepath.Join(home, ".ssh", "known_hosts") || client.Config.SSHKeyPath != "/custom/client-key" {
		t.Fatal("default trust path changed the explicit client key")
	}
	client, err = NewTunnel(TunnelConfig{SSHKnownHostsPath: "/custom/known_hosts", SSHKeyPath: "/custom/client-key"})
	if err != nil || client.Config.SSHKnownHostsPath != "/custom/known_hosts" {
		t.Fatalf("explicit known_hosts path was not preserved: %v", err)
	}
}

func TestSSHStopClosesIdleLocalStreams(t *testing.T) {
	_, private, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	signer, err := ssh.NewSignerFromKey(private)
	if err != nil {
		t.Fatal(err)
	}
	listener := testTCPListener(t)
	config := &ssh.ServerConfig{NoClientAuth: true}
	config.AddHostKey(signer)
	ready, serverDone := make(chan error, 1), make(chan struct{})
	go func() {
		defer close(serverDone)
		conn, err := listener.AcceptTCP()
		if err != nil {
			ready <- err
			return
		}
		defer conn.Close()
		_ = conn.SetDeadline(time.Now().Add(5 * time.Second))
		server, channels, requests, err := ssh.NewServerConn(conn, config)
		if err != nil {
			ready <- err
			return
		}
		defer server.Close()
		go ssh.DiscardRequests(requests)
		request, ok := <-channels
		if !ok {
			ready <- errors.New("SSH transport closed before opening stream")
			return
		}
		if request.ChannelType() != "direct-tcpip" {
			ready <- errors.New("unexpected SSH channel type")
			return
		}
		channel, channelRequests, err := request.Accept()
		if err != nil {
			ready <- err
			return
		}
		defer channel.Close()
		go ssh.DiscardRequests(channelRequests)
		ready <- nil
		_, _ = io.Copy(io.Discard, channel)
	}()
	keyDER, err := x509.MarshalPKCS8PrivateKey(private)
	if err != nil {
		t.Fatal(err)
	}
	dir := t.TempDir()
	keyPath, hostsPath := filepath.Join(dir, "key.pem"), filepath.Join(dir, "known_hosts")
	if err := os.WriteFile(keyPath, pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: keyDER}), 0600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(hostsPath, []byte(knownhosts.Line([]string{knownhosts.Normalize(listener.Addr().String())}, signer.PublicKey())+"\n"), 0600); err != nil {
		t.Fatal(err)
	}
	host, port, _ := net.SplitHostPort(listener.Addr().String())
	client, err := NewTunnel(TunnelConfig{SSHHost: host, SSHPort: port, SSHUser: "test", SSHKeyPath: keyPath,
		SSHKnownHostsPath: hostsPath, BindAddress: "127.0.0.1", LocalPort: "0", RemoteHost: "127.0.0.1", RemotePort: "5432"})
	if err != nil {
		t.Fatal(err)
	}
	defer client.Stop()
	if err := client.Start(); err != nil {
		t.Fatal(err)
	}
	local, err := net.DialTimeout("tcp", client.listener.Addr().String(), time.Second)
	if err != nil {
		t.Fatal(err)
	}
	defer local.Close()
	select {
	case err := <-ready:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(time.Second):
		t.Fatal("SSH stream did not open")
	}
	stopped := make(chan struct{})
	go func() { client.Stop(); client.Stop(); close(stopped) }()
	select {
	case <-stopped:
	case <-time.After(time.Second):
		t.Fatal("Stop left the local-to-SSH copy blocked on an idle client")
	}
	_ = local.SetReadDeadline(time.Now().Add(time.Second))
	if _, err := local.Read(make([]byte, 1)); err == nil {
		t.Fatal("idle local connection survived Stop")
	} else if timeout, ok := err.(net.Error); ok && timeout.Timeout() {
		t.Fatal("idle local connection was not closed")
	}
	client.mu.Lock()
	remaining := len(client.active)
	client.mu.Unlock()
	if remaining != 0 {
		t.Fatal("SSH Stop retained active connection records")
	}
	select {
	case <-serverDone:
	case <-time.After(time.Second):
		t.Fatal("SSH fixture transport survived client Stop")
	}
}

func stalledSSHClient(t *testing.T, listener *net.TCPListener, timeout time.Duration) *Tunnel {
	t.Helper()
	_, private, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	signer, err := ssh.NewSignerFromKey(private)
	if err != nil {
		t.Fatal(err)
	}
	der, err := x509.MarshalPKCS8PrivateKey(private)
	if err != nil {
		t.Fatal(err)
	}
	dir := t.TempDir()
	keyPath, hostsPath := filepath.Join(dir, "key.pem"), filepath.Join(dir, "known_hosts")
	if err := os.WriteFile(keyPath, pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: der}), 0600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(hostsPath, []byte(knownhosts.Line([]string{knownhosts.Normalize(listener.Addr().String())}, signer.PublicKey())+"\n"), 0600); err != nil {
		t.Fatal(err)
	}
	host, port, _ := net.SplitHostPort(listener.Addr().String())
	client, err := NewTunnel(TunnelConfig{SSHHost: host, SSHPort: port, SSHUser: "test", SSHKeyPath: keyPath,
		SSHKnownHostsPath: hostsPath, ConnectionTimeout: timeout, BindAddress: "127.0.0.1", LocalPort: "0"})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { client.Stop() })
	return client
}

func TestSSHStopCancelsUnfinishedNegotiation(t *testing.T) {
	listener := testTCPListener(t)
	client := stalledSSHClient(t, listener, 10*time.Second)
	started := make(chan error, 1)
	go func() { started <- client.Start() }()
	peer := acceptTestConn(t, listener)
	// Read the client's version; never send the server's version in reply.
	peer.SetReadDeadline(time.Now().Add(time.Second))
	if _, err := bufio.NewReader(peer).ReadString('\n'); err != nil {
		t.Fatal(err)
	}
	stopped := make(chan struct{})
	go func() { client.Stop(); close(stopped) }()
	select {
	case <-stopped:
	case <-time.After(time.Second):
		t.Fatal("SSH Stop did not cancel unfinished negotiation")
	}
	select {
	case err := <-started:
		if err == nil {
			t.Fatal("canceled SSH negotiation reported success")
		}
	case <-time.After(time.Second):
		t.Fatal("unfinished Start did not return after Stop")
	}
	peer.SetReadDeadline(time.Now().Add(time.Second))
	if _, err := peer.Read(make([]byte, 1)); err == nil {
		t.Fatal("canceled SSH startup left the TCP connection open")
	} else if timeout, ok := err.(net.Error); ok && timeout.Timeout() {
		t.Fatal("SSH startup socket remained open after Stop")
	}
	client.mu.Lock()
	active, published := len(client.active), client.listener != nil || client.client != nil
	client.mu.Unlock()
	if active != 0 || published {
		t.Fatal("canceled SSH startup published or retained resources")
	}
}

func TestSSHNegotiationHasDeadlineWithoutStop(t *testing.T) {
	listener := testTCPListener(t)
	client := stalledSSHClient(t, listener, 200*time.Millisecond)
	started := make(chan error, 1)
	go func() { started <- client.Start() }()
	peer := acceptTestConn(t, listener)
	peer.SetReadDeadline(time.Now().Add(time.Second))
	if _, err := bufio.NewReader(peer).ReadString('\n'); err != nil {
		t.Fatal(err)
	}
	select {
	case err := <-started:
		if err == nil {
			t.Fatal("stalled SSH negotiation reported success")
		}
	case <-time.After(time.Second):
		t.Fatal("SSH negotiation exceeded its configured timeout")
	}
	if _, err := NewTunnel(TunnelConfig{ConnectionTimeout: -time.Second}); err == nil {
		t.Fatal("negative SSH negotiation timeout accepted")
	}
}
