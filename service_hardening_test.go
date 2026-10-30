package vmess

import (
	"bytes"
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"hash/crc32"
	"io"
	"net"
	"net/netip"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/sagernet/sing/common"
	"github.com/sagernet/sing/common/buf"
	"github.com/sagernet/sing/common/bufio"
	M "github.com/sagernet/sing/common/metadata"
)

// Deterministically fragment the incoming stream, without relying on how the
// local TCP stack combines writes. The parser still sees real client encoding.
type fragmentedRequestConn struct {
	net.Conn
	data    *bytes.Reader
	maxRead int
}

func (c *fragmentedRequestConn) Close() error { return nil }

func (c *fragmentedRequestConn) Read(p []byte) (int, error) {
	if c.maxRead > 0 && len(p) > c.maxRead {
		p = p[:c.maxRead]
	}
	return c.data.Read(p)
}

func parseTestRequest(service *Service[int], data []byte, maxRead int) (*serverRequest, error) {
	buffer := buf.New()
	defer buffer.Release()
	_, request, err := service.handshake(context.Background(), &fragmentedRequestConn{
		data: bytes.NewReader(data), maxRead: maxRead,
	}, M.ParseSocksaddr("192.0.2.1:12345"), buffer)
	return request, err
}

func TestFragmentedClientHeaders(t *testing.T) {
	for _, alterID := range []int{0, 4} {
		for _, security := range []string{"auto", "none", "zero", "aes-128-cfb", "aes-128-gcm", "chacha20-poly1305"} {
			for _, size := range []int{1, 7, 16, 17, 33, 42, 64, 99, 16384} {
				t.Run(fmt.Sprintf("alterID=%d/%s/read=%d", alterID, security, size), func(t *testing.T) {
					service := NewService[int](&echoHandler{})
					users, ids, alters := testUsers(1)
					alters[0] = alterID
					if err := service.UpdateUsers(users, ids, alters); err != nil {
						t.Fatal(err)
					}
					client, err := NewClient(ids[0], security, alterID, ClientWithGlobalPadding(), ClientWithAuthenticatedLength())
					if err != nil {
						t.Fatal(err)
					}
					payload := bytes.Repeat([]byte("fragmented payload"), 100)
					encoded := clientRequest(t, client, payload)
					request, err := parseTestRequest(service, encoded, size)
					if err != nil {
						t.Fatal(err)
					}
					defer common.Close(request.conn.reader)
					actual := make([]byte, len(payload))
					if _, err := io.ReadFull(request.conn.reader, actual); err != nil || !bytes.Equal(actual, payload) {
						t.Fatalf("body corrupted after fragmented header: %v", err)
					}
				})
			}
		}
	}
}

func TestFragmentedUDPAndMuxHeaders(t *testing.T) {
	for _, command := range []byte{CommandUDP, CommandMux} {
		for _, alterID := range []int{0, 4} {
			t.Run(fmt.Sprintf("command=%d/alterID=%d", command, alterID), func(t *testing.T) {
				service := NewService[int](&echoHandler{})
				users, ids, alters := testUsers(1)
				alters[0] = alterID
				if err := service.UpdateUsers(users, ids, alters); err != nil {
					t.Fatal(err)
				}
				client, _ := NewClient(ids[0], "aes-128-gcm", alterID, ClientWithGlobalPadding(), ClientWithAuthenticatedLength())
				capture := &captureConn{}
				conn := client.dialRaw(capture, command, M.ParseSocksaddr("1.1.1.1:53"))
				payload := []byte("packet or mux frame bytes")
				if err := conn.writeHandshake(payload); err != nil {
					t.Fatal(err)
				}
				request, err := parseTestRequest(service, capture.data.Bytes(), 1)
				if err != nil {
					t.Fatal(err)
				}
				defer common.Close(request.conn.reader)
				if request.command != command {
					t.Fatalf("command %d, want %d", request.command, command)
				}
				actual := make([]byte, len(payload)+MaxRearHeadroom)
				n, err := request.conn.reader.Read(actual)
				if err != nil || !bytes.Equal(actual[:n], payload) {
					t.Fatalf("body corrupted: %v", err)
				}
			})
		}
	}
}

func TestReplayUntilTimestampExpires(t *testing.T) {
	base := time.Unix(1800000000, 0)
	var elapsed atomic.Int64
	clock := func() time.Time { return base.Add(time.Duration(elapsed.Load()) * time.Second) }
	service := NewService[int](&echoHandler{}, ServiceWithTimeFunc(clock))
	users, ids, alters := testUsers(1)
	if err := service.UpdateUsers(users, ids, alters); err != nil {
		t.Fatal(err)
	}
	client, _ := NewClient(ids[0], "auto", 0, ClientWithTimeFunc(func() time.Time { return base.Add(120 * time.Second) }))
	encoded := clientRequest(t, client, []byte("hello"))
	request, err := parseTestRequest(service, encoded, 1)
	if err != nil {
		t.Fatal(err)
	}
	common.Close(request.conn.reader)
	for _, seconds := range []int64{0, 121, 239, 240, 60} {
		// The last step also covers a clock correction while still valid.
		elapsed.Store(seconds)
		if _, err := parseTestRequest(service, encoded, 1); !errors.Is(err, ErrReplay) {
			t.Fatalf("replay at %d seconds: %v", seconds, err)
		}
	}
	elapsed.Store(241)
	if _, err := parseTestRequest(service, encoded, 1); !errors.Is(err, ErrBadTimestamp) {
		t.Fatalf("expired request: %v", err)
	}
}

func TestTamperedHeaderDoesNotConsumeAuthID(t *testing.T) {
	service := NewService[int](&echoHandler{})
	users, ids, alters := testUsers(1)
	if err := service.UpdateUsers(users, ids, alters); err != nil {
		t.Fatal(err)
	}
	client, _ := NewClient(ids[0], "auto", 0)
	encoded := clientRequest(t, client, []byte("hello"))
	for _, index := range []int{16, 34, 42, 60} {
		modified := append([]byte(nil), encoded...)
		modified[index] ^= 0x01
		if _, err := parseTestRequest(service, modified, 1); err == nil {
			t.Fatalf("tampered byte %d accepted", index)
		}
	}
	for _, length := range []int{16, 34, 42, 60} {
		if _, err := parseTestRequest(service, encoded[:length], 1); err == nil {
			t.Fatalf("truncated header of length %d accepted", length)
		}
	}
	request, err := parseTestRequest(service, encoded, 1)
	if err != nil {
		t.Fatalf("genuine request rejected after tampered/truncated attempts: %v", err)
	}
	common.Close(request.conn.reader)
}

func TestLegacyReplayAndFreshConnectionsWithinOneSecond(t *testing.T) {
	now := time.Unix(1800000000, 0)
	clock := func() time.Time { return now }
	service := NewService[int](&echoHandler{}, ServiceWithTimeFunc(clock))
	users, ids, alters := testUsers(1)
	alters[0] = 4
	if err := service.UpdateUsers(users, ids, alters); err != nil {
		t.Fatal(err)
	}
	client, _ := NewClient(ids[0], "auto", 4, ClientWithTimeFunc(clock))
	for i := 0; i < 4; i++ {
		encoded := clientRequest(t, client, []byte("fresh connection"))
		request, err := parseTestRequest(service, encoded, 1)
		if err != nil {
			t.Fatalf("fresh legacy connection %d rejected: %v", i, err)
		}
		common.Close(request.conn.reader)
		if _, err := parseTestRequest(service, encoded, 1); !errors.Is(err, ErrReplay) {
			t.Fatalf("legacy replay %d: %v", i, err)
		}
	}
}

func TestLegacyUsersAddedAfterStartKeepRefreshing(t *testing.T) {
	var seconds atomic.Int64
	seconds.Store(1800000000)
	clock := func() time.Time { return time.Unix(seconds.Load(), 0) }
	service := NewService[int](&echoHandler{}, ServiceWithTimeFunc(clock))
	if err := service.Start(); err != nil {
		t.Fatal(err)
	}
	defer service.Close()
	users, ids, alters := testUsers(1)
	alters[0] = 4
	if err := service.UpdateUsers(users, ids, alters); err != nil {
		t.Fatal(err)
	}
	if service.alterIdUpdateTask == nil {
		t.Fatal("legacy refresh was not started for late-added users")
	}
	service.alterIdUpdateTask.Reset(time.Millisecond)
	seconds.Add(180)
	client, _ := NewClient(ids[0], "auto", 4, ClientWithTimeFunc(clock))
	encoded := clientRequest(t, client, []byte("after timestamp rollover"))
	deadline := time.Now().Add(time.Second)
	for {
		request, err := parseTestRequest(service, encoded, 1)
		if err == nil {
			common.Close(request.conn.reader)
			break
		}
		if time.Now().After(deadline) {
			t.Fatalf("late-added legacy user stopped working after rollover: %v", err)
		}
		time.Sleep(time.Millisecond)
	}
}

func TestReplayClaimsAreAtomic(t *testing.T) {
	service := NewService[int](&echoHandler{})
	users, ids, alters := testUsers(1)
	if err := service.UpdateUsers(users, ids, alters); err != nil {
		t.Fatal(err)
	}
	client, _ := NewClient(ids[0], "auto", 0)
	encoded := clientRequest(t, client, []byte("hello"))
	var accepted atomic.Int32
	var wg sync.WaitGroup
	for i := 0; i < 64; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			request, err := parseTestRequest(service, encoded, 1)
			if err == nil {
				accepted.Add(1)
				common.Close(request.conn.reader)
			} else if !errors.Is(err, ErrReplay) {
				t.Errorf("unexpected rejection: %v", err)
			}
		}()
	}
	wg.Wait()
	if accepted.Load() != 1 {
		t.Fatalf("accepted %d copies, want one", accepted.Load())
	}
}

func TestReplayIDsAreScopedToUsers(t *testing.T) {
	service := NewService[int](&echoHandler{})
	users, ids, alters := testUsers(2)
	if err := service.UpdateUsers(users, ids, alters); err != nil {
		t.Fatal(err)
	}
	now := time.Now().Unix()
	var decoded [16]byte
	binary.BigEndian.PutUint64(decoded[:], uint64(now))
	binary.BigEndian.PutUint32(decoded[8:], 7)
	binary.BigEndian.PutUint32(decoded[12:], crc32.ChecksumIEEE(decoded[:12]))
	for i := range ids {
		var encrypted [16]byte
		service.users.Load().entries[i].block.Encrypt(encrypted[:], decoded[:])
		// Same decoded timestamp/random field, but each user's encrypted ID
		// must get its own replay slot.
		if !service.replayFilter.check(encrypted, now+CacheDurationSeconds, now) {
			t.Fatalf("user %d collided with another user's AuthID", i)
		}
	}
}

func TestConcurrentFailedScansRespectBurst(t *testing.T) {
	cache := newSourceCache(4, 0)
	source := netip.MustParseAddr("192.0.2.1")
	now := time.Now().UnixNano()
	var allowed atomic.Int32
	var wg sync.WaitGroup
	for i := 0; i < 128; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			if cache.allowScan(source, now) {
				allowed.Add(1)
			}
		}()
	}
	wg.Wait()
	if allowed.Load() != 4 {
		t.Fatalf("allowed %d concurrent scans with a burst of 4", allowed.Load())
	}
}

func TestLegacyBodyOwnsPrefetchedBytes(t *testing.T) {
	service := NewService[int](&echoHandler{})
	users, ids, alters := testUsers(1)
	alters[0] = 4
	if err := service.UpdateUsers(users, ids, alters); err != nil {
		t.Fatal(err)
	}
	client, _ := NewClient(ids[0], "aes-128-gcm", 4)
	payload := bytes.Repeat([]byte("owned legacy body"), 100)
	encoded := clientRequest(t, client, payload)
	buffer := buf.New()
	_, request, err := service.handshake(context.Background(), &fragmentedRequestConn{data: bytes.NewReader(encoded)}, M.Socksaddr{}, buffer)
	if err != nil {
		buffer.Release()
		t.Fatal(err)
	}
	defer common.Close(request.conn.reader)
	// Simulate immediate reuse by the buffer pool before the body is read.
	buffer.Resize(0, buffer.Start()+buffer.Len())
	for i := range buffer.Bytes() {
		buffer.Bytes()[i] = 0xff
	}
	buffer.Release()
	actual := make([]byte, len(payload))
	if _, err := io.ReadFull(request.conn.reader, actual); err != nil || !bytes.Equal(actual, payload) {
		t.Fatalf("prefetched legacy body was not owned: %v", err)
	}
}

func TestFragmentedLegacyFailureKeepsRawHeader(t *testing.T) {
	service := NewService[int](&echoHandler{})
	users, ids, alters := testUsers(1)
	alters[0] = 4
	if err := service.UpdateUsers(users, ids, alters); err != nil {
		t.Fatal(err)
	}
	client, _ := NewClient(ids[0], "auto", 4)
	encoded := append([]byte(nil), clientRequest(t, client, nil)...)
	// Corrupt only the encrypted FNV checksum, leaving the parsed fields valid.
	encoded[len(encoded)-1] ^= 1
	buffer := buf.New()
	defer buffer.Release()
	_, _, err := service.handshake(context.Background(), &fragmentedRequestConn{
		data: bytes.NewReader(encoded), maxRead: 1,
	}, M.Socksaddr{}, buffer)
	if !errors.Is(err, ErrInvalidChecksum) {
		t.Fatalf("invalid checksum: %v", err)
	}
	buffer.Resize(0, buffer.Start()+buffer.Len())
	if !bytes.Equal(buffer.Bytes(), encoded) {
		t.Fatalf("fallback transcript lost or changed bytes: got %d, want %d", buffer.Len(), len(encoded))
	}
}

func TestReplayFilterCleanup(t *testing.T) {
	var filter serviceReplayFilter
	first := [16]byte{0, 1}
	second := [16]byte{0, 2} // Same shard.
	if !filter.check(first, 240, 0) || filter.check(first, 240, 240) {
		t.Fatal("last valid second must still be protected")
	}
	if !filter.check(second, 400, 241) {
		t.Fatal("new request rejected")
	}
	shard := filter.shard(first)
	if _, exists := shard.entries[first]; exists {
		t.Fatal("expired entry retained after cleanup")
	}
	if !filter.contains(second, 400) {
		t.Fatal("live entry was removed")
	}
}

type shortWriteSink struct{}

func (shortWriteSink) Write(p []byte) (int, error) { return len(p) / 2, nil }

func TestCoalescedWriterRejectsShortWrite(t *testing.T) {
	writer := &coalescedWriter{upstream: bufio.NewExtendedWriter(shortWriteSink{})}
	writer.hold()
	writer.Write([]byte("header and payload"))
	if err := writer.flush(); !errors.Is(err, io.ErrShortWrite) {
		t.Fatalf("silently truncated an encrypted record: %v", err)
	}
}
