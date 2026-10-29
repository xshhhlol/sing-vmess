package vmess

import (
	"bytes"
	"context"
	"crypto/rand"
	"errors"
	"fmt"
	"io"
	"net"
	"net/netip"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/sagernet/sing/common/auth"
	"github.com/sagernet/sing/common/buf"
	M "github.com/sagernet/sing/common/metadata"
	N "github.com/sagernet/sing/common/network"

	"github.com/gofrs/uuid/v5"
)

type echoHandler struct {
	users chan int
}

func (h *echoHandler) NewConnectionEx(ctx context.Context, conn net.Conn, source M.Socksaddr, destination M.Socksaddr, onClose N.CloseHandlerFunc) {
	user, _ := auth.UserFromContext[int](ctx)
	h.users <- user
	defer conn.Close()
	payload := make([]byte, 64)
	n, err := conn.Read(payload)
	if err != nil {
		return
	}
	conn.Write(payload[:n])
}

func (h *echoHandler) NewPacketConnectionEx(ctx context.Context, conn N.PacketConn, source M.Socksaddr, destination M.Socksaddr, onClose N.CloseHandlerFunc) {
	user, _ := auth.UserFromContext[int](ctx)
	h.users <- user
	defer conn.Close()
	buffer := buf.New()
	defer buffer.Release()
	destination, err := conn.ReadPacket(buffer)
	if err != nil {
		return
	}
	headroom := N.CalculateFrontHeadroom(conn)
	response := buf.NewSize(headroom + buffer.Len() + N.CalculateRearHeadroom(conn))
	response.Resize(headroom, 0)
	response.Write(buffer.Bytes())
	conn.WritePacket(response, destination)
}

func testUsers(n int) ([]int, []string, []int) {
	users := make([]int, n)
	ids := make([]string, n)
	alterIds := make([]int, n)
	for i := range users {
		users[i] = i
		ids[i] = uuid.Must(uuid.NewV4()).String()
	}
	return users, ids, alterIds
}

const testHandshakeTimeout = 500 * time.Millisecond

type testServer struct {
	service  *Service[int]
	handler  *echoHandler
	listener net.Listener
	errors   chan error
}

func newTestServer(t *testing.T, options ...ServiceOption) *testServer {
	t.Helper()
	handler := &echoHandler{users: make(chan int, 16)}
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	server := &testServer{
		service:  NewService[int](handler, append([]ServiceOption{ServiceWithHandshakeTimeout(testHandshakeTimeout)}, options...)...),
		handler:  handler,
		listener: listener,
		errors:   make(chan error, 16),
	}
	go func() {
		for {
			conn, err := listener.Accept()
			if err != nil {
				return
			}
			go func() {
				err := server.service.NewConnection(context.Background(), conn, M.SocksaddrFromNet(conn.RemoteAddr()), nil)
				if err != nil {
					conn.Close()
					server.errors <- err
				}
			}()
		}
	}()
	t.Cleanup(func() { listener.Close() })
	return server
}

func (s *testServer) dial(t *testing.T) net.Conn {
	t.Helper()
	conn, err := net.Dial("tcp", s.listener.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { conn.Close() })
	return conn
}

func (s *testServer) expectUser(t *testing.T, want int) {
	t.Helper()
	select {
	case got := <-s.handler.users:
		if got != want {
			t.Fatalf("authenticated as user %d, want %d", got, want)
		}
	case err := <-s.errors:
		t.Fatalf("server rejected connection: %v", err)
	case <-time.After(5 * time.Second):
		t.Fatal("timeout waiting for server")
	}
}

func (s *testServer) expectError(t *testing.T, want error) {
	t.Helper()
	select {
	case user := <-s.handler.users:
		t.Fatalf("authenticated as user %d, want %v", user, want)
	case err := <-s.errors:
		if !errors.Is(err, want) {
			t.Fatalf("got error %v, want %v", err, want)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("timeout waiting for server")
	}
}

func echoTCP(t *testing.T, server *testServer, client *Client, user int) {
	t.Helper()
	conn := client.DialEarlyConn(server.dial(t), M.ParseSocksaddr("example.com:443"))
	payload := []byte("hello vmess " + fmt.Sprint(user))
	if _, err := conn.Write(payload); err != nil {
		t.Fatal(err)
	}
	server.expectUser(t, user)
	response := make([]byte, len(payload))
	if _, err := io.ReadFull(conn, response); err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(payload, response) {
		t.Fatalf("echo mismatch: %q", response)
	}
}

func TestServiceClientCompatibility(t *testing.T) {
	server := newTestServer(t)
	users, ids, alterIds := testUsers(300)
	if err := server.service.UpdateUsers(users, ids, alterIds); err != nil {
		t.Fatal(err)
	}
	clientOptions := map[string][]ClientOption{
		"default":              nil,
		"global_padding":       {ClientWithGlobalPadding()},
		"authenticated_length": {ClientWithAuthenticatedLength()},
		"padding_and_length":   {ClientWithGlobalPadding(), ClientWithAuthenticatedLength()},
	}
	for _, security := range []string{"auto", "none", "zero", "aes-128-cfb", "aes-128-gcm", "chacha20-poly1305"} {
		for name, options := range clientOptions {
			t.Run(security+"/"+name, func(t *testing.T) {
				user := 1 + len(security)*len(name)%len(users)
				client, err := NewClient(ids[user], security, 0, options...)
				if err != nil {
					t.Fatal(err)
				}
				echoTCP(t, server, client, user)

				packetConn := client.DialEarlyPacketConn(server.dial(t), M.ParseSocksaddr("1.1.1.1:53"))
				payload := []byte("udp payload")
				if _, err := packetConn.WriteTo(payload, M.ParseSocksaddr("1.1.1.1:53").UDPAddr()); err != nil {
					t.Fatal(err)
				}
				server.expectUser(t, user)
				response := make([]byte, 64)
				n, _, err := packetConn.ReadFrom(response)
				if err != nil {
					t.Fatal(err)
				}
				if !bytes.Equal(payload, response[:n]) {
					t.Fatalf("udp echo mismatch: %q", response[:n])
				}
			})
		}
	}
}

func TestServiceLegacyAlterId(t *testing.T) {
	server := newTestServer(t)
	if err := server.service.Start(); err != nil {
		t.Fatal(err)
	}
	defer server.service.Close()
	users, ids, alterIds := testUsers(20)
	alterIds[7] = 4
	if err := server.service.UpdateUsers(users, ids, alterIds); err != nil {
		t.Fatal(err)
	}
	client, err := NewClient(ids[7], "aes-128-gcm", 4)
	if err != nil {
		t.Fatal(err)
	}
	echoTCP(t, server, client, 7)
}

func TestServiceUsesTimeFunc(t *testing.T) {
	offset := time.Hour
	shifted := func() time.Time { return time.Now().Add(offset) }
	server := newTestServer(t, ServiceWithTimeFunc(shifted))
	users, ids, alterIds := testUsers(10)
	if err := server.service.UpdateUsers(users, ids, alterIds); err != nil {
		t.Fatal(err)
	}

	client, _ := NewClient(ids[3], "auto", 0, ClientWithTimeFunc(shifted))
	echoTCP(t, server, client, 3)

	client, _ = NewClient(ids[3], "auto", 0)
	conn := client.DialEarlyConn(server.dial(t), M.ParseSocksaddr("example.com:443"))
	conn.Write([]byte("hello"))
	server.expectError(t, ErrBadTimestamp)
}

func TestServiceUpdateUsers(t *testing.T) {
	server := newTestServer(t)
	users, ids, alterIds := testUsers(50)
	if err := server.service.UpdateUsers(users, ids, alterIds); err != nil {
		t.Fatal(err)
	}
	before := server.service.users.Load()

	client, _ := NewClient(ids[20], "auto", 0)
	echoTCP(t, server, client, 20) // now remembered for this source

	// Drop user 10, so every later user shifts down by one, as sing-box does.
	shiftedIds := append(append([]string{}, ids[:10]...), ids[11:]...)
	if err := server.service.UpdateUsers(users[:49], shiftedIds, alterIds[:49]); err != nil {
		t.Fatal(err)
	}
	after := server.service.users.Load()
	if after.entries[10].block != before.entries[11].block {
		t.Fatal("cipher of an unchanged user was not reused")
	}

	// The remembered user must resolve to its new index, not the old one.
	echoTCP(t, server, client, 19)
	client, _ = NewClient(ids[30], "auto", 0)
	echoTCP(t, server, client, 29)

	if server.service.Contains(49) || !server.service.Contains(48) {
		t.Fatal("Contains does not follow the user list")
	}
	removed, _ := NewClient(ids[10], "auto", 0)
	conn := removed.DialEarlyConn(server.dial(t), M.ParseSocksaddr("example.com:443"))
	conn.Write([]byte("hello"))
	server.expectError(t, ErrBadRequest)
}

func TestServiceSourceHintsAndScanLimit(t *testing.T) {
	var clock atomic.Int64
	clock.Store(time.Now().UnixNano())
	service := NewService[int](&echoHandler{}, ServiceWithAuthScanLimit(4, 1))
	service.cacheClock = clock.Load
	users, ids, alterIds := testUsers(100)
	if err := service.UpdateUsers(users, ids, alterIds); err != nil {
		t.Fatal(err)
	}
	table := service.users.Load()
	authID := func(user int) []byte {
		buffer := buf.New()
		defer buffer.Release()
		AuthID(Key(uuid.FromStringOrNil(ids[user])), time.Now(), buffer)
		return append([]byte(nil), buffer.Bytes()...)
	}
	junk := func() []byte {
		b := make([]byte, 16)
		rand.Read(b)
		return b
	}
	match := func(source netip.Addr, authID []byte) int {
		entry, _ := service.matchAuthID(table, authID, source, clock.Load())
		if entry == nil {
			return -1
		}
		return entry.user
	}
	sourceA := netip.MustParseAddr("192.0.2.1")
	sourceB := netip.MustParseAddr("192.0.2.2")

	if got := match(sourceA, authID(42)); got != 42 {
		t.Fatalf("got %d, want 42", got)
	}
	for i := 0; i < 4; i++ {
		if got := match(sourceA, junk()); got != -1 {
			t.Fatalf("junk matched user %d", got)
		}
	}
	// Scan budget of A is spent: remembered users still work, others wait.
	if got := match(sourceA, authID(42)); got != 42 {
		t.Fatalf("remembered user rejected, got %d", got)
	}
	if got := match(sourceA, authID(43)); got != -1 {
		t.Fatalf("scan was not limited, got %d", got)
	}
	if got := match(sourceB, authID(43)); got != 43 {
		t.Fatalf("other source affected, got %d", got)
	}
	// IPv4-mapped IPv6 is the same source.
	if got := match(netip.AddrFrom16(sourceA.As16()), authID(44)); got != -1 {
		t.Fatalf("mapped address not unified, got %d", got)
	}
	clock.Add(int64(time.Second))
	if got := match(sourceA, authID(43)); got != 43 {
		t.Fatalf("budget not refilled, got %d", got)
	}
	// Successful scans do not spend budget.
	clock.Add(int64(time.Second))
	for user := 50; user < 60; user++ {
		if got := match(sourceA, authID(user)); got != user {
			t.Fatalf("got %d, want %d", got, user)
		}
	}
	if got := match(netip.Addr{}, authID(99)); got != 99 {
		t.Fatalf("unknown source, got %d", got)
	}
}

func TestSourceCacheBounded(t *testing.T) {
	cache := newSourceCache(4, 1)
	now := time.Now().UnixNano()
	for i := 0; i < sourceCacheShards*sourceShardCapacity*3; i++ {
		addr := netip.AddrFrom4([4]byte{10, byte(i >> 16), byte(i >> 8), byte(i)})
		cache.remember(addr, uint64(i), now)
	}
	for i := range cache.shards {
		if n := len(cache.shards[i].sources); n > sourceShardCapacity {
			t.Fatalf("shard %d holds %d sources", i, n)
		}
	}
}

func TestServiceConcurrentUpdate(t *testing.T) {
	server := newTestServer(t)
	users, ids, alterIds := testUsers(200)
	if err := server.service.UpdateUsers(users, ids, alterIds); err != nil {
		t.Fatal(err)
	}
	done := make(chan struct{})
	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		defer wg.Done()
		for {
			select {
			case <-done:
				return
			default:
				server.service.UpdateUsers(users, ids, alterIds)
			}
		}
	}()
	for i := 0; i < 50; i++ {
		client, _ := NewClient(ids[i*3], "auto", 0)
		echoTCP(t, server, client, i*3)
	}
	close(done)
	wg.Wait()
}

func benchmarkAuth(b *testing.B, hinted bool) {
	service := NewService[int](&echoHandler{})
	users, ids, alterIds := testUsers(5000)
	service.UpdateUsers(users, ids, alterIds)
	table := service.users.Load()
	buffer := buf.New()
	AuthID(Key(uuid.FromStringOrNil(ids[4999])), time.Now(), buffer)
	authID := buffer.Bytes()
	source := netip.MustParseAddr("192.0.2.1")
	if !hinted {
		service.sources = nil
	}
	now := time.Now().UnixNano()
	service.matchAuthID(table, authID, source, now)
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		if entry, _ := service.matchAuthID(table, authID, source, now); entry == nil {
			b.Fatal("no match")
		}
	}
}

func BenchmarkAuth5000UsersFullScan(b *testing.B) { benchmarkAuth(b, false) }
func BenchmarkAuth5000UsersHinted(b *testing.B)   { benchmarkAuth(b, true) }
