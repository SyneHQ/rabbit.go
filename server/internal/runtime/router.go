package runtime

import (
	"bufio"
	"context"
	"crypto/rand"
	"crypto/subtle"
	"encoding/hex"
	"encoding/json"
	"io"
	"net"
	"strings"
	"sync"
	"time"
)

const RegisterFrame = "RUNTIME-V2"
const OpenFrame = "RUNTIME-OPEN-V2"
const DataFrame = "RUNTIME-DATA-V2"
const maxStreams = 8

type OpenRequest struct {
	Scope
	BrokerToken string `json:"brokerToken"`
}
type DataRequest struct {
	Registration
	ConnectionID string `json:"connectionId"`
}
type offer struct {
	conn  net.Conn
	ready chan struct{}
}
type pending struct {
	session  *session
	incoming chan offer
}

type session struct {
	registration Registration
	control      net.Conn
	writeMu      sync.Mutex
	authMu       sync.Mutex
	until        time.Time // Router.mu protects the lease and all maps.
	closed       bool
	streams      map[net.Conn]struct{}
	openCount    int
}

// Router has no listener of its own. It handles private frames on Rabbit's TLS listener.
type Router struct {
	mu          sync.Mutex
	authority   Authorizer
	brokerToken string
	sessions    map[string]*session
	pending     map[string]*pending
	closed      bool
	done        chan struct{}
	wg          sync.WaitGroup
	closeWG     sync.WaitGroup
	handlersWG  sync.WaitGroup
}

func NewRouter(authority Authorizer, brokerToken string) (*Router, error) {
	if authority == nil || len(brokerToken) < 32 {
		return nil, ErrUnavailable
	}
	r := &Router{authority: authority, brokerToken: brokerToken, sessions: make(map[string]*session), pending: make(map[string]*pending), done: make(chan struct{})}
	r.wg.Add(1)
	go r.expire()
	return r, nil
}

func key(scope Scope) string { return scope.TeamID + "/" + scope.RuntimeID }

func readJSON(reader *bufio.Reader, target any) error {
	line, err := reader.ReadSlice('\n')
	if err != nil || len(line) > 4096 {
		return ErrUnavailable
	}
	decoder := json.NewDecoder(strings.NewReader(string(line)))
	decoder.DisallowUnknownFields()
	if decoder.Decode(target) != nil {
		return ErrUnavailable
	}
	if decoder.Decode(new(any)) != io.EOF {
		return ErrUnavailable
	}
	return nil
}

func writeLine(conn net.Conn, line string) error {
	_ = conn.SetWriteDeadline(time.Now().Add(2 * time.Second))
	_, err := io.WriteString(conn, line+"\n")
	_ = conn.SetWriteDeadline(time.Time{})
	return err
}

func (r *Router) Handle(frame string, conn net.Conn, reader *bufio.Reader) {
	r.mu.Lock()
	if r.closed {
		r.mu.Unlock()
		conn.Close()
		return
	}
	r.handlersWG.Add(1)
	r.mu.Unlock()
	defer r.handlersWG.Done()
	_ = conn.SetDeadline(time.Now().Add(5 * time.Second))
	switch frame {
	case RegisterFrame:
		r.register(conn, reader)
	case OpenFrame:
		r.open(conn, reader)
	case DataFrame:
		r.data(conn, reader)
	default:
		conn.Close()
	}
}

func (r *Router) authorize(reg Registration) (time.Time, error) {
	if !reg.Scope.valid() || len(reg.Credential) < 32 || len(reg.Credential) > 100 {
		return time.Time{}, ErrUnavailable
	}
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	until, err := r.authority.Authorize(ctx, reg)
	if err != nil || !until.After(time.Now()) || until.After(time.Now().Add(10*time.Second)) {
		return time.Time{}, ErrUnavailable
	}
	return until, nil
}

func (r *Router) refresh(s *session, pendingID ...string) bool {
	s.authMu.Lock()
	defer s.authMu.Unlock()
	r.mu.Lock()
	if s.closed || r.sessions[key(s.registration.Scope)] != s || !s.until.After(time.Now()) {
		r.closeLocked(s)
		r.mu.Unlock()
		return false
	}
	if len(pendingID) != 0 {
		p := r.pending[pendingID[0]]
		if p == nil || p.session != s {
			r.mu.Unlock()
			return false
		}
	}
	r.mu.Unlock()
	until, err := r.authorize(s.registration)
	r.mu.Lock()
	defer r.mu.Unlock()
	if err != nil || s.closed || r.sessions[key(s.registration.Scope)] != s {
		r.closeLocked(s)
		return false
	}
	// An expired lease cannot be resurrected by an in-flight refresh.
	if !s.until.After(time.Now()) {
		r.closeLocked(s)
		return false
	}
	s.until = until
	return true
}

func (r *Router) register(conn net.Conn, reader *bufio.Reader) {
	defer conn.Close()
	var reg Registration
	if readJSON(reader, &reg) != nil {
		return
	}
	until, err := r.authorize(reg)
	if err != nil {
		return
	}
	s := &session{registration: reg, control: conn, until: until, streams: make(map[net.Conn]struct{})}
	r.mu.Lock()
	if r.closed || len(r.sessions) >= 1024 || r.sessions[key(reg.Scope)] != nil {
		r.mu.Unlock()
		return
	}
	r.sessions[key(reg.Scope)] = s
	r.mu.Unlock()
	defer func() { r.mu.Lock(); r.closeLocked(s); r.mu.Unlock() }()
	// Recheck authority after publication. An initial lease never bypasses this check.
	if !r.refresh(s) {
		return
	}
	_ = conn.SetDeadline(time.Time{})
	if s.write("READY") != nil {
		return
	}
	for {
		_ = conn.SetReadDeadline(time.Now().Add(10 * time.Second))
		line, err := reader.ReadSlice('\n')
		if err != nil || string(line) != "PING\n" || !r.refresh(s) {
			return
		}
		if s.write("PONG") != nil {
			return
		}
	}
}

func (s *session) write(line string) error {
	s.writeMu.Lock()
	defer s.writeMu.Unlock()
	return writeLine(s.control, line)
}

func (r *Router) open(conn net.Conn, reader *bufio.Reader) {
	defer conn.Close()
	var request OpenRequest
	if readJSON(reader, &request) != nil || !request.Scope.valid() ||
		subtle.ConstantTimeCompare([]byte(request.BrokerToken), []byte(r.brokerToken)) != 1 {
		return
	}
	r.mu.Lock()
	s := r.sessions[key(request.Scope)]
	r.mu.Unlock()
	if s == nil || s.registration.Scope != request.Scope || !r.refresh(s) {
		return
	}
	idBytes := make([]byte, 32)
	if _, err := rand.Read(idBytes); err != nil {
		return
	}
	id := hex.EncodeToString(idBytes)
	p := &pending{session: s, incoming: make(chan offer, 1)}
	r.mu.Lock()
	if s.closed || !s.until.After(time.Now()) || s.openCount >= maxStreams || len(r.pending) >= 128 {
		r.mu.Unlock()
		return
	}
	s.openCount++
	s.streams[conn] = struct{}{}
	r.pending[id] = p
	r.mu.Unlock()
	defer func() {
		r.mu.Lock()
		delete(r.pending, id)
		delete(s.streams, conn)
		s.openCount--
		select {
		case orphan := <-p.incoming:
			r.closeConnection(orphan.conn)
			delete(s.streams, orphan.conn)
		default:
		}
		r.mu.Unlock()
	}()
	if s.write("OPEN "+id) != nil {
		return
	}
	timer := time.NewTimer(5 * time.Second)
	defer timer.Stop()
	var offered offer
	select {
	case offered = <-p.incoming:
	case <-timer.C:
		return
	case <-r.done:
		return
	}
	defer offered.conn.Close()
	defer func() { r.mu.Lock(); delete(s.streams, offered.conn); r.mu.Unlock() }()
	select {
	case <-offered.ready:
	case <-timer.C:
		return
	case <-r.done:
		return
	}
	if !r.refresh(s) {
		return
	}
	_ = conn.SetDeadline(time.Now().Add(180 * time.Second))
	_ = offered.conn.SetDeadline(time.Now().Add(180 * time.Second))
	if writeLine(conn, "READY") != nil {
		return
	}
	bridge(&bufferedConn{Conn: conn, reader: reader}, offered.conn)
}

func (r *Router) data(conn net.Conn, reader *bufio.Reader) {
	owned := false
	defer func() {
		if !owned {
			conn.Close()
		}
	}()
	var request DataRequest
	if readJSON(reader, &request) != nil || len(request.ConnectionID) != 64 {
		return
	}
	r.mu.Lock()
	p := r.pending[request.ConnectionID]
	r.mu.Unlock()
	if p == nil || p.session.registration != request.Registration || !r.refresh(p.session, request.ConnectionID) {
		return
	}
	r.mu.Lock()
	if r.pending[request.ConnectionID] != p || p.session.closed || !p.session.until.After(time.Now()) {
		r.mu.Unlock()
		return
	}
	delete(r.pending, request.ConnectionID)
	buffered := &bufferedConn{Conn: conn, reader: reader}
	ready := make(chan struct{})
	p.session.streams[buffered] = struct{}{}
	p.incoming <- offer{conn: buffered, ready: ready}
	owned = true
	r.mu.Unlock()
	// The broker waits until this acknowledgement is fully written before sending bytes.
	if writeLine(conn, "PAIRED") != nil {
		conn.Close()
	}
	close(ready)
}

type bufferedConn struct {
	net.Conn
	reader *bufio.Reader
}

func (c *bufferedConn) Read(p []byte) (int, error) { return c.reader.Read(p) }

func bridge(a, b net.Conn) {
	done := make(chan struct{}, 2)
	copyOne := func(dst, src net.Conn) { _, _ = io.Copy(dst, src); a.Close(); b.Close(); done <- struct{}{} }
	go copyOne(a, b)
	go copyOne(b, a)
	<-done
	<-done
}

func (r *Router) closeLocked(s *session) {
	if s.closed {
		return
	}
	s.closed = true
	if r.sessions[key(s.registration.Scope)] == s {
		delete(r.sessions, key(s.registration.Scope))
	}
	r.closeConnection(s.control)
	for conn := range s.streams {
		r.closeConnection(conn)
	}
	for id, p := range r.pending {
		if p.session == s {
			delete(r.pending, id)
		}
	}
}

// Mark the session unavailable before closing sockets. TLS close-notify may
// block; it must never hold the shared routing lock or delay another lease.
func (r *Router) closeConnection(conn net.Conn) {
	r.closeWG.Add(1)
	go func() {
		defer r.closeWG.Done()
		_ = conn.SetDeadline(time.Now())
		_ = conn.Close()
	}()
}

func (r *Router) expire() {
	defer r.wg.Done()
	ticker := time.NewTicker(100 * time.Millisecond)
	defer ticker.Stop()
	for {
		select {
		case <-r.done:
			return
		case now := <-ticker.C:
			r.mu.Lock()
			for _, s := range r.sessions {
				if !s.until.After(now) {
					r.closeLocked(s)
				}
			}
			r.mu.Unlock()
		}
	}
}

func (r *Router) Close() {
	r.mu.Lock()
	if !r.closed {
		r.closed = true
		close(r.done)
		for _, s := range r.sessions {
			r.closeLocked(s)
		}
	}
	r.mu.Unlock()
	r.wg.Wait()
	r.handlersWG.Wait()
	r.closeWG.Wait()
}
