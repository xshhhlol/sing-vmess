// Package xray checks the sing-vmess server against the VMess client encoding
// of Xray-core, which v2rayN and most Xray based clients use. It sets the
// request options the way Xray's outbound does.
package xray

import (
	"bytes"
	"context"
	"crypto/rand"
	"fmt"
	"io"
	"net"
	"testing"
	"time"

	vmess "github.com/sagernet/sing-vmess"
	"github.com/sagernet/sing/common/auth"
	sbuf "github.com/sagernet/sing/common/buf"
	M "github.com/sagernet/sing/common/metadata"
	N "github.com/sagernet/sing/common/network"

	"github.com/xtls/xray-core/common/buf"
	xnet "github.com/xtls/xray-core/common/net"
	"github.com/xtls/xray-core/common/protocol"
	"github.com/xtls/xray-core/common/uuid"
	xvmess "github.com/xtls/xray-core/proxy/vmess"
	"github.com/xtls/xray-core/proxy/vmess/encoding"
)

type echoHandler struct {
	users chan int
}

func (h *echoHandler) NewConnectionEx(ctx context.Context, conn net.Conn, source M.Socksaddr, destination M.Socksaddr, onClose N.CloseHandlerFunc) {
	user, _ := auth.UserFromContext[int](ctx)
	h.users <- user
	defer conn.Close()
	io.Copy(conn, conn)
}

func (h *echoHandler) NewPacketConnectionEx(ctx context.Context, conn N.PacketConn, source M.Socksaddr, destination M.Socksaddr, onClose N.CloseHandlerFunc) {
	user, _ := auth.UserFromContext[int](ctx)
	h.users <- user
	defer conn.Close()
	for {
		buffer := sbuf.NewPacket()
		destination, err := conn.ReadPacket(buffer)
		if err != nil {
			buffer.Release()
			return
		}
		headroom := N.CalculateFrontHeadroom(conn)
		response := sbuf.NewSize(headroom + buffer.Len() + N.CalculateRearHeadroom(conn))
		response.Resize(headroom, 0)
		response.Write(buffer.Bytes())
		buffer.Release()
		if err = conn.WritePacket(response, destination); err != nil {
			return
		}
	}
}

func newServer(t *testing.T, options ...vmess.ServiceOption) (string, *echoHandler, []string) {
	t.Helper()
	handler := &echoHandler{users: make(chan int, 64)}
	service := vmess.NewService[int](handler, options...)
	ids := make([]string, 200)
	users := make([]int, len(ids))
	for i := range ids {
		users[i] = i
		id := uuid.New()
		ids[i] = id.String()
	}
	if err := service.UpdateUsers(users, ids, make([]int, len(ids))); err != nil {
		t.Fatal(err)
	}
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { listener.Close() })
	go func() {
		for {
			conn, err := listener.Accept()
			if err != nil {
				return
			}
			go func() {
				if err := service.NewConnection(context.Background(), conn, M.SocksaddrFromNet(conn.RemoteAddr()), nil); err != nil {
					conn.Close()
				}
			}()
		}
	}()
	return listener.Addr().String(), handler, ids
}

// newRequest mirrors proxy/vmess/outbound of Xray-core.
func newRequest(id string, security protocol.SecurityType, command protocol.RequestCommand, authenticatedLength bool) *protocol.RequestHeader {
	parsed, _ := uuid.ParseString(id)
	request := &protocol.RequestHeader{
		Version: encoding.Version,
		User:    &protocol.MemoryUser{Account: &xvmess.MemoryAccount{ID: protocol.NewID(parsed), Security: security}},
		Command: command,
		Address: xnet.DomainAddress("example.com"),
		Port:    443,
		Option:  protocol.RequestOptionChunkStream,
	}
	request.Security = security
	if security == protocol.SecurityType_AES128_GCM || security == protocol.SecurityType_NONE || security == protocol.SecurityType_CHACHA20_POLY1305 {
		request.Option.Set(protocol.RequestOptionChunkMasking)
	}
	if (security == protocol.SecurityType_AES128_GCM || security == protocol.SecurityType_CHACHA20_POLY1305) && request.Option.Has(protocol.RequestOptionChunkMasking) {
		request.Option.Set(protocol.RequestOptionGlobalPadding)
	}
	if security == protocol.SecurityType_ZERO {
		request.Security = protocol.SecurityType_NONE
		request.Option.Clear(protocol.RequestOptionChunkStream)
		request.Option.Clear(protocol.RequestOptionChunkMasking)
	}
	if authenticatedLength {
		request.Option.Set(protocol.RequestOptionAuthenticatedLength)
	}
	return request
}

type session struct {
	conn       net.Conn
	client     *encoding.ClientSession
	request    *protocol.RequestHeader
	writer     *buf.BufferedWriter
	bodyWriter buf.Writer
	reader     *buf.BufferedReader
	bodyReader buf.Reader
}

func dial(t *testing.T, addr string, request *protocol.RequestHeader, first []byte) *session {
	t.Helper()
	conn, err := net.Dial("tcp", addr)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { conn.Close() })
	conn.SetDeadline(time.Now().Add(10 * time.Second))
	s := &session{
		conn:    conn,
		client:  encoding.NewClientSession(context.Background(), time.Now().UnixNano()),
		request: request,
		writer:  buf.NewBufferedWriter(buf.NewWriter(conn)),
		reader:  &buf.BufferedReader{Reader: buf.NewReader(conn)},
	}
	if err := s.client.EncodeRequestHeader(request, s.writer); err != nil {
		t.Fatal(err)
	}
	if s.bodyWriter, err = s.client.EncodeRequestBody(request, s.writer); err != nil {
		t.Fatal(err)
	}
	// Like Xray, the header and the first payload leave in one write.
	s.write(t, first)
	if err := s.writer.SetBuffered(false); err != nil {
		t.Fatal(err)
	}
	return s
}

func (s *session) write(t *testing.T, payload []byte) {
	t.Helper()
	b := buf.New()
	b.Write(payload)
	if err := s.bodyWriter.WriteMultiBuffer(buf.MultiBuffer{b}); err != nil {
		t.Fatal(err)
	}
}

func (s *session) read(t *testing.T, n int) []byte {
	t.Helper()
	if s.bodyReader == nil {
		if _, err := s.client.DecodeResponseHeader(s.reader); err != nil {
			t.Fatal("response header: ", err)
		}
		var err error
		if s.bodyReader, err = s.client.DecodeResponseBody(s.request, s.reader); err != nil {
			t.Fatal(err)
		}
	}
	var out []byte
	for len(out) < n {
		mb, err := s.bodyReader.ReadMultiBuffer()
		for _, b := range mb {
			out = append(out, b.Bytes()...)
		}
		buf.ReleaseMulti(mb)
		if err != nil {
			t.Fatalf("read after %d of %d bytes: %v", len(out), n, err)
		}
	}
	return out
}

func randomBytes(n int) []byte {
	b := make([]byte, n)
	rand.Read(b)
	return b
}

var securities = map[string]protocol.SecurityType{
	"aes-128-gcm":       protocol.SecurityType_AES128_GCM,
	"chacha20-poly1305": protocol.SecurityType_CHACHA20_POLY1305,
	"none":              protocol.SecurityType_NONE,
	"zero":              protocol.SecurityType_ZERO,
}

func TestXrayClient(t *testing.T) {
	servers := map[string][]vmess.ServiceOption{
		"default": nil,
		"shaped":  {vmess.ServiceWithResponseShaping(vmess.ResponseShapingOptions{})},
	}
	for serverName, options := range servers {
		addr, handler, ids := newServer(t, options...)
		for name, security := range securities {
			for _, authenticatedLength := range []bool{false, true} {
				t.Run(fmt.Sprintf("%s/%s/authenticated_length=%v", serverName, name, authenticatedLength), func(t *testing.T) {
					if security == protocol.SecurityType_NONE && authenticatedLength {
						// Xray ignores AuthenticatedLength for "none" while
						// sing-vmess encrypts the length; upstream has always
						// differed here and either choice breaks one client.
						t.Skip("none with authenticated length differs between Xray and sing-box")
					}
					user := len(name) * 7
					s := dial(t, addr, newRequest(ids[user], security, protocol.RequestCommandTCP, authenticatedLength), []byte("ping"))
					if got := <-handler.users; got != user {
						t.Fatalf("authenticated as %d, want %d", got, user)
					}
					if got := s.read(t, 4); string(got) != "ping" {
						t.Fatalf("got %q", got)
					}
					// A large transfer after the first round trip crosses the
					// shaping window and several chunks.
					large := randomBytes(100000)
					go func() {
						for i := 0; i < len(large); i += 8192 {
							s.write(t, large[i:min(i+8192, len(large))])
						}
					}()
					if got := s.read(t, len(large)); !bytes.Equal(got, large) {
						t.Fatal("large transfer corrupted")
					}
				})
			}
		}
	}
}

func TestXrayClientUDP(t *testing.T) {
	addr, handler, ids := newServer(t, vmess.ServiceWithResponseShaping(vmess.ResponseShapingOptions{}))
	for name, security := range securities {
		if security == protocol.SecurityType_ZERO {
			continue // Xray sends UDP over zero without chunks, which VMess cannot frame.
		}
		t.Run(name, func(t *testing.T) {
			request := newRequest(ids[3], security, protocol.RequestCommandUDP, false)
			packets := [][]byte{[]byte("first packet"), randomBytes(1200), randomBytes(1)}
			s := dial(t, addr, request, packets[0])
			<-handler.users
			for i, packet := range packets {
				if i > 0 {
					s.write(t, packet)
				}
				// Each packet must come back whole, not split by shaping.
				if s.bodyReader == nil {
					s.read(t, 0)
				}
				mb, err := s.bodyReader.ReadMultiBuffer()
				if err != nil {
					t.Fatal(err)
				}
				var got []byte
				for _, b := range mb {
					got = append(got, b.Bytes()...)
				}
				buf.ReleaseMulti(mb)
				if !bytes.Equal(got, packet) {
					t.Fatalf("packet %d: got %d bytes, want %d", i, len(got), len(packet))
				}
			}
		})
	}
}

func TestXrayProbeFallback(t *testing.T) {
	fallback := make(chan []byte, 1)
	addr, _, ids := newServer(t, vmess.ServiceWithFallback(fallbackFunc(func(conn net.Conn) {
		conn.SetReadDeadline(time.Now().Add(200 * time.Millisecond))
		data, _ := io.ReadAll(conn)
		fallback <- data
		conn.Close()
	})), vmess.ServiceWithRequireEncryption())
	// An Xray client choosing "none" on a node that requires encryption
	// reaches the fallback with its request intact.
	conn, err := net.Dial("tcp", addr)
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	capture := &captureConn{Conn: conn}
	request := newRequest(ids[1], protocol.SecurityType_NONE, protocol.RequestCommandTCP, false)
	client := encoding.NewClientSession(context.Background(), 1)
	writer := buf.NewBufferedWriter(buf.NewWriter(capture))
	client.EncodeRequestHeader(request, writer)
	bodyWriter, _ := client.EncodeRequestBody(request, writer)
	b := buf.New()
	b.WriteString("hello")
	bodyWriter.WriteMultiBuffer(buf.MultiBuffer{b})
	writer.SetBuffered(false)
	if got := <-fallback; !bytes.Equal(got, capture.sent.Bytes()) {
		t.Fatalf("fallback got %d bytes, want %d", len(got), capture.sent.Len())
	}
}

type captureConn struct {
	net.Conn
	sent bytes.Buffer
}

func (c *captureConn) Write(p []byte) (int, error) {
	c.sent.Write(p)
	return c.Conn.Write(p)
}

type fallbackFunc func(net.Conn)

func (f fallbackFunc) NewConnectionEx(ctx context.Context, conn net.Conn, source M.Socksaddr, destination M.Socksaddr, onClose N.CloseHandlerFunc) {
	f(conn)
}
