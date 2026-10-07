package tunnel

import (
	"bufio"
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"io"
	"log"
	"net"
	"strconv"
	"strings"
	"sync"
	"time"
)

const (
	maxControlLine               = 4096
	defaultConcurrentConnections = 64
)

// TunnelClient forwards opaque database streams. Config must not be changed
// concurrently with Start or a dial; trust files may be replaced between dials.
type TunnelClient struct {
	Config TunnelClientConfig

	mu      sync.Mutex
	started bool
	stopped bool
	ctx     context.Context
	cancel  context.CancelFunc
	done    chan struct{}

	tlsMu     sync.Mutex
	tlsKey    tlsConfigKey
	tlsConfig *tls.Config
}

// TunnelClientConfig holds configuration for the database tunnel client.
type TunnelClientConfig struct {
	ServerAddress            string
	CAFile                   string
	ServerName               string
	InsecureLocal            bool
	LocalPort                string
	Token                    string
	MaxReconnectAttempts     int // Zero means unlimited retries.
	InitialRetryDelay        time.Duration
	MaxRetryDelay            time.Duration
	HealthCheckInterval      time.Duration
	ConnectionTimeout        time.Duration
	MaxConcurrentConnections int // Zero selects the default of 64.
}

func NewTunnelClient(config TunnelClientConfig) (*TunnelClient, error) {
	if config.Token == "" || config.Token == "default" || len(config.Token) >= maxControlLine || strings.ContainsAny(config.Token, "\r\n") {
		return nil, errors.New("a valid tunnel token is required")
	}
	if config.ServerAddress == "" {
		return nil, errors.New("server address is required")
	}
	if config.LocalPort == "" {
		config.LocalPort = "5432"
	}
	if !validPort(config.LocalPort) {
		return nil, errors.New("local port must be between 1 and 65535")
	}
	if config.InitialRetryDelay == 0 {
		config.InitialRetryDelay = time.Second
	}
	if config.MaxRetryDelay == 0 {
		config.MaxRetryDelay = time.Minute
	}
	if config.HealthCheckInterval == 0 {
		config.HealthCheckInterval = 30 * time.Second
	}
	if config.ConnectionTimeout == 0 {
		config.ConnectionTimeout = 10 * time.Second
	}
	if config.MaxConcurrentConnections == 0 {
		config.MaxConcurrentConnections = defaultConcurrentConnections
	}
	if config.MaxReconnectAttempts < 0 || config.InitialRetryDelay < 0 || config.MaxRetryDelay < config.InitialRetryDelay ||
		config.HealthCheckInterval < 0 || config.HealthCheckInterval > 24*time.Hour || config.ConnectionTimeout < 0 ||
		config.MaxConcurrentConnections < 1 || config.MaxConcurrentConnections > 4096 {
		return nil, errors.New("invalid tunnel retry, timeout or connection limit")
	}
	ctx, cancel := context.WithCancel(context.Background())
	return &TunnelClient{Config: config, ctx: ctx, cancel: cancel, done: make(chan struct{})}, nil
}

func validPort(value string) bool {
	port, err := strconv.Atoi(value)
	return err == nil && port > 0 && port <= 65535 && strconv.Itoa(port) == value
}

// Start starts a single connection manager. Stop is safe before or after Start.
func (tc *TunnelClient) Start() error {
	tc.mu.Lock()
	defer tc.mu.Unlock()
	if tc.stopped {
		return errors.New("tunnel client has stopped")
	}
	if tc.started {
		return errors.New("tunnel client already started")
	}
	tc.started = true
	go tc.connectionManager()
	return nil
}

func (tc *TunnelClient) connectionManager() {
	defer close(tc.done)
	attempt := 0
	for tc.ctx.Err() == nil {
		attempt++
		established, err := tc.runSession(tc.ctx)
		if tc.ctx.Err() != nil {
			return
		}
		if established {
			attempt = 0
		}
		if err != nil {
			log.Printf("Tunnel connection ended: %v", err)
		}
		if tc.Config.MaxReconnectAttempts > 0 && attempt >= tc.Config.MaxReconnectAttempts {
			log.Printf("Tunnel retry limit reached")
			return
		}
		timer := time.NewTimer(tc.calculateBackoffDelay(max(attempt, 1)))
		select {
		case <-tc.ctx.Done():
			timer.Stop()
			return
		case <-timer.C:
		}
	}
}

// runSession waits for all of this control connection's data streams before
// returning. No goroutine or dial can migrate to the next control connection.
func (tc *TunnelClient) runSession(parent context.Context) (established bool, err error) {
	ctx, cancel := context.WithCancel(parent)
	defer cancel()
	conn, err := tc.dialServerContext(ctx)
	if err != nil {
		return false, fmt.Errorf("connect to tunnel server: %w", err)
	}
	defer conn.Close()
	control := &sessionControl{conn: conn}
	closed := make(chan struct{})
	stop := context.AfterFunc(ctx, func() {
		defer close(closed)
		control.close(parent.Err() != nil)
	})
	defer func() {
		if !stop() {
			<-closed
		}
	}()
	if err := control.write(tc.Config.Token+"\n"+tc.Config.LocalPort+"\n", tc.Config.ConnectionTimeout); err != nil {
		return false, errors.New("write tunnel request")
	}
	if err := conn.SetReadDeadline(time.Now().Add(tc.Config.ConnectionTimeout)); err != nil {
		return false, err
	}
	reader := bufio.NewReaderSize(conn, maxControlLine)
	response, err := controlLine(reader)
	if err != nil {
		return false, errors.New("read tunnel response")
	}
	parts := strings.Split(response, ":")
	if len(parts) != 3 || parts[0] != "SUCCESS" || parts[1] == "" || !validPort(parts[2]) {
		return false, errors.New("tunnel request rejected or response invalid")
	}
	control.mu.Lock()
	control.ready = true
	control.mu.Unlock()
	log.Printf("Tunnel established: local port %s, remote port %s", tc.Config.LocalPort, parts[2])

	var workers sync.WaitGroup
	defer func() {
		cancel()
		conn.Close()
		workers.Wait()
	}()
	workers.Add(1)
	go func() {
		defer workers.Done()
		tc.healthMonitor(ctx, cancel, control)
	}()
	slots := make(chan struct{}, tc.Config.MaxConcurrentConnections)
	overloaded := false
	for {
		if err := conn.SetReadDeadline(time.Now().Add(3 * tc.Config.HealthCheckInterval)); err != nil {
			return true, err
		}
		line, err := controlLine(reader)
		if err != nil {
			return true, fmt.Errorf("read tunnel control: %w", err)
		}
		switch line {
		case "PONG":
			continue
		case "CONNECT":
			line, err = controlLine(reader)
			if err != nil {
				return true, errors.New("read data connection identifier")
			}
			id, ok := strings.CutPrefix(line, "CONN_ID:")
			if !ok || !runtimeDigest.MatchString(id) {
				return true, errors.New("invalid data connection identifier")
			}
			select {
			case slots <- struct{}{}:
				overloaded = false
				workers.Add(1)
				go func() {
					defer workers.Done()
					defer func() { <-slots }()
					tc.handleDataConnection(ctx, id)
				}()
			default:
				// The server's existing pairing timeout rejects this request.
				// Keep processing PONGs and preserve established data streams.
				if !overloaded {
					log.Printf("Tunnel data connection limit reached")
					overloaded = true
				}
			}
		default:
			return true, errors.New("invalid tunnel control message")
		}
	}
}

func controlLine(reader *bufio.Reader) (string, error) {
	line, err := reader.ReadSlice('\n')
	if err != nil || len(line) > maxControlLine {
		if err == nil || errors.Is(err, bufio.ErrBufferFull) {
			err = errors.New("tunnel control line exceeds limit")
		}
		return "", err
	}
	return strings.TrimSuffix(strings.TrimSuffix(string(line), "\n"), "\r"), nil
}

type sessionControl struct {
	conn  net.Conn
	mu    sync.Mutex
	ready bool
}

func (c *sessionControl) write(frame string, timeout time.Duration) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	return writeControl(c.conn, frame, timeout)
}

func (c *sessionControl) close(notify bool) {
	if !notify {
		c.conn.Close()
		return
	}
	// Bound both lock acquisition and a stalled write. A user-requested Stop
	// still sends the existing DISCONNECT frame when the peer is responsive.
	timer := time.AfterFunc(100*time.Millisecond, func() { c.conn.Close() })
	defer timer.Stop()
	c.mu.Lock()
	if notify && c.ready {
		_ = writeControl(c.conn, "DISCONNECT\n", 100*time.Millisecond)
	}
	c.conn.Close()
	c.mu.Unlock()
}

func writeControl(conn net.Conn, frame string, timeout time.Duration) error {
	if err := conn.SetWriteDeadline(time.Now().Add(timeout)); err != nil {
		return err
	}
	n, err := io.WriteString(conn, frame)
	if err == nil && n != len(frame) {
		err = io.ErrShortWrite
	}
	clearErr := conn.SetWriteDeadline(time.Time{})
	if err != nil {
		return err
	}
	return clearErr
}

func (tc *TunnelClient) calculateBackoffDelay(attempt int) time.Duration {
	delay := tc.Config.InitialRetryDelay
	for i := 1; i < attempt && delay < tc.Config.MaxRetryDelay; i++ {
		if delay > tc.Config.MaxRetryDelay/2 {
			return tc.Config.MaxRetryDelay
		}
		delay *= 2
	}
	return delay
}

func (tc *TunnelClient) healthMonitor(ctx context.Context, cancel context.CancelFunc, control *sessionControl) {
	ticker := time.NewTicker(tc.Config.HealthCheckInterval)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			if err := control.write("PING\n", min(tc.Config.ConnectionTimeout, tc.Config.HealthCheckInterval)); err != nil {
				cancel()
				return
			}
		}
	}
}

func (tc *TunnelClient) handleDataConnection(ctx context.Context, id string) {
	data, err := tc.dialServerContext(ctx)
	if err != nil {
		if ctx.Err() == nil {
			log.Printf("Tunnel data connection failed: %v", err)
		}
		return
	}
	defer data.Close()
	stopData := context.AfterFunc(ctx, func() { data.Close() })
	defer stopData()
	if err := writeControl(data, "DATA:"+id+"\n", tc.Config.ConnectionTimeout); err != nil {
		return
	}
	local, err := (&net.Dialer{Timeout: tc.Config.ConnectionTimeout}).DialContext(ctx, "tcp", net.JoinHostPort("localhost", tc.Config.LocalPort))
	if err != nil {
		if ctx.Err() == nil {
			log.Printf("Tunnel local service connection failed: %v", err)
		}
		return
	}
	defer local.Close()
	stopLocal := context.AfterFunc(ctx, func() { local.Close() })
	defer stopLocal()
	bridgeData(data, local)
}

// bridgeData retains clean EOF half-closes so a database may respond after the
// caller finishes writing. A hard error tears down both directions immediately.
func bridgeData(first, second net.Conn) {
	defer first.Close()
	defer second.Close()
	done := make(chan struct{}, 2)
	copyDirection := func(dst, src net.Conn) {
		_, err := io.Copy(dst, src)
		if err == nil {
			if half, ok := dst.(interface{ CloseWrite() error }); ok {
				err = half.CloseWrite()
			} else {
				err = errors.New("connection does not support half-close")
			}
		}
		if err != nil {
			dst.Close()
			src.Close()
		}
		done <- struct{}{}
	}
	go copyDirection(first, second)
	go copyDirection(second, first)
	<-done
	<-done
}

// Stop cancels connection setup and active streams, and waits for all workers.
func (tc *TunnelClient) Stop() error {
	tc.mu.Lock()
	tc.stopped = true
	tc.cancel()
	started := tc.started
	tc.mu.Unlock()
	if started {
		<-tc.done
	}
	return nil
}
