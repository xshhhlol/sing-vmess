package vmess

import (
	"bytes"
	"context"
	"crypto/rand"
	"io"
	"net"
	"sync"
	"testing"
	"time"

	"github.com/sagernet/sing/common/buf"
	"github.com/sagernet/sing/common/bufio"
	M "github.com/sagernet/sing/common/metadata"
	N "github.com/sagernet/sing/common/network"

	"github.com/gofrs/uuid/v5"
)

// captureConn records what a client writes, to build probes from real requests.
type captureConn struct {
	net.Conn
	data bytes.Buffer
}

func (c *captureConn) Write(p []byte) (int, error) { return c.data.Write(p) }
func (c *captureConn) Close() error                { return nil }

func clientRequest(t *testing.T, client *Client, payload []byte) []byte {
	t.Helper()
	capture := &captureConn{}
	conn := client.DialEarlyConn(capture, M.ParseSocksaddr("example.com:443"))
	if _, err := conn.Write(payload); err != nil {
		t.Fatal(err)
	}
	return capture.data.Bytes()
}

// recordingConn records the size of every write the server makes.
type recordingConn struct {
	net.Conn
	access sync.Mutex
	writes []int
}

func (c *recordingConn) Write(p []byte) (int, error) {
	c.access.Lock()
	c.writes = append(c.writes, len(p))
	c.access.Unlock()
	return c.Conn.Write(p)
}

func (c *recordingConn) writeSizes() []int {
	c.access.Lock()
	defer c.access.Unlock()
	return append([]int(nil), c.writes...)
}

type fallbackResult struct {
	data []byte
	at   time.Time
}

// webFallback stands in for a web server: it reads what arrives within a short
// window, reports it and answers 400.
type webFallback struct {
	results chan fallbackResult
}

func (f *webFallback) NewConnectionEx(ctx context.Context, conn net.Conn, source M.Socksaddr, destination M.Socksaddr, onClose N.CloseHandlerFunc) {
	defer conn.Close()
	conn.SetReadDeadline(time.Now().Add(200 * time.Millisecond))
	data, _ := io.ReadAll(conn)
	f.results <- fallbackResult{data, time.Now()}
	conn.Write([]byte("HTTP/1.1 400 Bad Request\r\nContent-Length: 0\r\n\r\n"))
}

type writeMode int

const (
	writeModeWrite writeMode = iota
	writeModeBuffer
	writeModeReadFrom
)

// sendHandler writes a fixed response through one of the write paths.
type sendHandler struct {
	users chan int
	data  []byte
	mode  writeMode
}

func (h *sendHandler) NewConnectionEx(ctx context.Context, conn net.Conn, source M.Socksaddr, destination M.Socksaddr, onClose N.CloseHandlerFunc) {
	defer conn.Close()
	request := make([]byte, 64)
	if _, err := conn.Read(request); err != nil {
		return
	}
	switch h.mode {
	case writeModeWrite:
		conn.Write(h.data)
	case writeModeBuffer:
		headroom := N.CalculateFrontHeadroom(conn)
		buffer := buf.NewSize(headroom + len(h.data) + N.CalculateRearHeadroom(conn))
		buffer.Resize(headroom, 0)
		buffer.Write(h.data)
		bufio.NewExtendedWriter(conn).WriteBuffer(buffer)
	case writeModeReadFrom:
		conn.(io.ReaderFrom).ReadFrom(bytes.NewReader(h.data))
	}
	h.users <- 0
}

func (h *sendHandler) NewPacketConnectionEx(ctx context.Context, conn N.PacketConn, source M.Socksaddr, destination M.Socksaddr, onClose N.CloseHandlerFunc) {
	conn.Close()
}

type probeServer struct {
	service  *Service[int]
	listener net.Listener
	conns    chan *recordingConn
	errors   chan error
}

func newProbeServer(t *testing.T, handler Handler, options ...ServiceOption) *probeServer {
	t.Helper()
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	server := &probeServer{
		service:  NewService[int](handler, append([]ServiceOption{ServiceWithHandshakeTimeout(testHandshakeTimeout)}, options...)...),
		listener: listener,
		conns:    make(chan *recordingConn, 16),
		errors:   make(chan error, 16),
	}
	go func() {
		for {
			conn, err := listener.Accept()
			if err != nil {
				return
			}
			recording := &recordingConn{Conn: conn}
			server.conns <- recording
			go func() {
				err := server.service.NewConnection(context.Background(), recording, M.SocksaddrFromNet(conn.RemoteAddr()), nil)
				if err != nil {
					conn.Close()
				}
				server.errors <- err
			}()
		}
	}()
	t.Cleanup(func() { listener.Close() })
	return server
}

func (s *probeServer) dial(t *testing.T) (*net.TCPConn, *recordingConn) {
	t.Helper()
	conn, err := net.Dial("tcp", s.listener.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { conn.Close() })
	return conn.(*net.TCPConn), <-s.conns
}

type probe struct {
	name string
	data []byte
}

func randomBytes(n int) []byte {
	b := make([]byte, n)
	rand.Read(b)
	return b
}

// probes covers each way a request can fail before it is served.
func makeProbes(t *testing.T, ids []string, replayed []byte) []probe {
	stale, _ := NewClient(ids[1], "auto", 0, ClientWithTimeFunc(func() time.Time { return time.Now().Add(-10 * time.Minute) }))
	unknown, _ := NewClient(uuid.Must(uuid.NewV4()).String(), "auto", 0)
	valid, _ := NewClient(ids[2], "aes-128-gcm", 0)
	tampered := clientRequest(t, valid, []byte("hello"))
	tampered[60] ^= 0x01
	tlsHello := append([]byte{0x16, 0x03, 0x01, 0x00, 0xc8}, randomBytes(200)...)
	return []probe{
		{"http_get", []byte("GET / HTTP/1.1\r\nHost: example.com\r\n\r\n")},
		{"random_short", randomBytes(50)},
		{"random_99", randomBytes(99)},
		{"random_long", randomBytes(300)},
		{"tls_hello", tlsHello},
		{"stale_timestamp", clientRequest(t, stale, []byte("hello"))},
		{"unknown_user", clientRequest(t, unknown, []byte("hello"))},
		{"tampered_header", tampered},
		{"replay", replayed},
	}
}

func sendFirstRequest(t *testing.T, server *probeServer, request []byte) {
	t.Helper()
	conn, _ := server.dial(t)
	if _, err := conn.Write(request); err != nil {
		t.Fatal(err)
	}
	select {
	case err := <-server.errors:
		if err != nil {
			t.Fatalf("first request rejected: %v", err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("timeout")
	}
}

func TestProbesReachFallbackWithExactBytes(t *testing.T) {
	fallback := &webFallback{results: make(chan fallbackResult, 16)}
	handler := &sendHandler{users: make(chan int, 16), data: []byte("ok")}
	server := newProbeServer(t, handler, ServiceWithFallback(fallback))
	users, ids, alterIds := testUsers(50)
	server.service.UpdateUsers(users, ids, alterIds)

	client, _ := NewClient(ids[5], "auto", 0)
	replayed := clientRequest(t, client, []byte("hello"))
	sendFirstRequest(t, server, replayed)

	for _, p := range makeProbes(t, ids, replayed) {
		t.Run(p.name, func(t *testing.T) {
			conn, recording := server.dial(t)
			if _, err := conn.Write(p.data); err != nil {
				t.Fatal(err)
			}
			var result fallbackResult
			select {
			case result = <-fallback.results:
			case <-time.After(5 * time.Second):
				t.Fatal("fallback not reached")
			}
			if !bytes.Equal(result.data, p.data) {
				t.Fatalf("fallback got %d bytes, want the %d probe bytes", len(result.data), len(p.data))
			}
			if err := <-server.errors; err != nil {
				t.Fatalf("fallback reported as error: %v", err)
			}
			response, _ := io.ReadAll(conn)
			if !bytes.HasPrefix(response, []byte("HTTP/1.1 400")) {
				t.Fatalf("got %q from fallback", response)
			}
			if got := recording.writeSizes(); len(got) != 1 {
				t.Fatalf("server wrote %v, want only the fallback reply", got)
			}
		})
	}
}

func TestSilentProbeReachesFallbackAtDeadline(t *testing.T) {
	fallback := &webFallback{results: make(chan fallbackResult, 1)}
	server := newProbeServer(t, &echoHandler{users: make(chan int, 1)}, ServiceWithFallback(fallback))
	users, ids, alterIds := testUsers(5)
	server.service.UpdateUsers(users, ids, alterIds)

	start := time.Now()
	conn, _ := server.dial(t)
	result := <-fallback.results
	// The read side is reported finished, so the fallback does not wait again.
	if elapsed := result.at.Sub(start); elapsed < testHandshakeTimeout || elapsed > testHandshakeTimeout+150*time.Millisecond {
		t.Fatalf("fallback reached after %v", elapsed)
	}
	if len(result.data) != 0 {
		t.Fatalf("fallback got %q", result.data)
	}
	response, _ := io.ReadAll(conn)
	if !bytes.HasPrefix(response, []byte("HTTP/1.1 400")) {
		t.Fatalf("got %q", response)
	}
}

func TestProbesDrainedWithoutFallback(t *testing.T) {
	handler := &sendHandler{users: make(chan int, 16), data: []byte("ok")}
	server := newProbeServer(t, handler)
	users, ids, alterIds := testUsers(50)
	server.service.UpdateUsers(users, ids, alterIds)

	client, _ := NewClient(ids[5], "auto", 0)
	replayed := clientRequest(t, client, []byte("hello"))
	sendFirstRequest(t, server, replayed)

	for _, p := range makeProbes(t, ids, replayed) {
		t.Run(p.name, func(t *testing.T) {
			// Held open until the handshake deadline, whatever was sent.
			start := time.Now()
			conn, recording := server.dial(t)
			conn.Write(p.data)
			response, _ := io.ReadAll(conn)
			elapsed := time.Since(start)
			if len(response) != 0 {
				t.Fatalf("server answered %q", response)
			}
			if elapsed < testHandshakeTimeout-50*time.Millisecond || elapsed > testHandshakeTimeout+300*time.Millisecond {
				t.Fatalf("closed after %v, want about %v", elapsed, testHandshakeTimeout)
			}
			if got := recording.writeSizes(); len(got) != 0 {
				t.Fatalf("server wrote %v", got)
			}
			if err := <-server.errors; err == nil {
				t.Fatal("probe accepted")
			}
		})
	}

	t.Run("peer_close", func(t *testing.T) {
		// Draining ends as soon as the peer closes.
		conn, _ := server.dial(t)
		conn.Write(randomBytes(300))
		time.Sleep(50 * time.Millisecond)
		start := time.Now()
		conn.CloseWrite()
		select {
		case <-server.errors:
		case <-time.After(testHandshakeTimeout):
			t.Fatal("drain ignored peer close")
		}
		if elapsed := time.Since(start); elapsed > 200*time.Millisecond {
			t.Fatalf("drain ended %v after peer close", elapsed)
		}
	})
}

func TestRequireEncryption(t *testing.T) {
	fallback := &webFallback{results: make(chan fallbackResult, 4)}
	handler := &sendHandler{users: make(chan int, 4), data: []byte("ok")}
	server := newProbeServer(t, handler, ServiceWithFallback(fallback), ServiceWithRequireEncryption())
	users, ids, alterIds := testUsers(5)
	server.service.UpdateUsers(users, ids, alterIds)

	for _, security := range []string{"none", "aes-128-cfb"} {
		client, _ := NewClient(ids[1], security, 0)
		request := clientRequest(t, client, []byte("hello"))
		conn, _ := server.dial(t)
		conn.Write(request)
		if result := <-fallback.results; !bytes.Equal(result.data, request) {
			t.Fatalf("%s: fallback got %d bytes, want %d", security, len(result.data), len(request))
		}
		<-server.errors
	}
	for _, security := range []string{"auto", "aes-128-gcm", "chacha20-poly1305"} {
		client, _ := NewClient(ids[1], security, 0)
		conn, _ := server.dial(t)
		vmessConn := client.DialEarlyConn(conn, M.ParseSocksaddr("example.com:443"))
		vmessConn.Write([]byte("hello"))
		response, err := io.ReadAll(vmessConn)
		if err != nil || string(response) != "ok" {
			t.Fatalf("%s: got %q, %v", security, response, err)
		}
		<-handler.users
	}
}

func readResponse(t *testing.T, server *probeServer, client *Client) ([]byte, []int) {
	t.Helper()
	conn, recording := server.dial(t)
	vmessConn := client.DialEarlyConn(conn, M.ParseSocksaddr("example.com:443"))
	if _, err := vmessConn.Write([]byte("hello")); err != nil {
		t.Fatal(err)
	}
	response, err := io.ReadAll(vmessConn)
	if err != nil {
		t.Fatal(err)
	}
	return response, recording.writeSizes()
}

func TestResponseWritesCoalesced(t *testing.T) {
	data := randomBytes(40000)
	for name, mode := range map[string]writeMode{"write": writeModeWrite, "buffer": writeModeBuffer, "read_from": writeModeReadFrom} {
		for _, security := range []string{"none", "aes-128-cfb", "aes-128-gcm", "chacha20-poly1305"} {
			t.Run(name+"/"+security, func(t *testing.T) {
				handler := &sendHandler{users: make(chan int, 1), data: data, mode: mode}
				server := newProbeServer(t, handler)
				users, ids, alterIds := testUsers(3)
				server.service.UpdateUsers(users, ids, alterIds)
				client, _ := NewClient(ids[1], security, 0, ClientWithGlobalPadding())
				response, writes := readResponse(t, server, client)
				if !bytes.Equal(response, data) {
					t.Fatalf("got %d bytes, want %d", len(response), len(data))
				}
				// 40000 bytes are three chunks of at most WriteChunkSize.
				if len(writes) > 3 {
					t.Fatalf("server wrote %v, want one write per chunk", writes)
				}
				if writes[0] <= 2+CipherOverhead+4+CipherOverhead {
					t.Fatalf("response header written alone: %v", writes)
				}
			})
		}
	}
}

func TestResponseShaping(t *testing.T) {
	data := randomBytes(1000)
	handler := &sendHandler{users: make(chan int, 1), data: data}
	server := newProbeServer(t, handler, ServiceWithResponseShaping(ResponseShapingOptions{
		MinRecordSize: 100, MaxRecordSize: 100, MinRecords: 3, MaxRecords: 3,
	}))
	users, ids, alterIds := testUsers(3)
	server.service.UpdateUsers(users, ids, alterIds)
	client, _ := NewClient(ids[1], "aes-128-gcm", 0)
	response, writes := readResponse(t, server, client)
	if !bytes.Equal(response, data) {
		t.Fatalf("got %d bytes, want %d", len(response), len(data))
	}
	const chunk = 2 + CipherOverhead
	const header = 2 + CipherOverhead + 4 + CipherOverhead
	want := []int{header + 100 + chunk, 100 + chunk, 100 + chunk, 700 + chunk}
	if len(writes) != len(want) {
		t.Fatalf("writes %v, want %v", writes, want)
	}
	for i := range want {
		if writes[i] != want[i] {
			t.Fatalf("writes %v, want %v", writes, want)
		}
	}
}

func TestResponseShapingRandomSizes(t *testing.T) {
	data := randomBytes(20000)
	handler := &sendHandler{users: make(chan int, 1), data: data, mode: writeModeBuffer}
	server := newProbeServer(t, handler, ServiceWithResponseShaping(ResponseShapingOptions{}))
	users, ids, alterIds := testUsers(3)
	server.service.UpdateUsers(users, ids, alterIds)
	client, _ := NewClient(ids[1], "chacha20-poly1305", 0, ClientWithGlobalPadding(), ClientWithAuthenticatedLength())
	response, writes := readResponse(t, server, client)
	if !bytes.Equal(response, data) {
		t.Fatalf("got %d bytes, want %d", len(response), len(data))
	}
	if len(writes) < 9 || len(writes) > 18 {
		t.Fatalf("got %d writes %v, want 8 to 16 shaped records and the rest", len(writes), writes)
	}
}
