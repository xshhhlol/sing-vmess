package vmess

import (
	"bytes"
	"context"
	"crypto/aes"
	"crypto/hmac"
	"crypto/md5"
	"crypto/sha256"
	"encoding/binary"
	"io"
	"net"
	"sync"
	"sync/atomic"
	"time"
	"unsafe"

	"github.com/sagernet/sing/common"
	"github.com/sagernet/sing/common/auth"
	"github.com/sagernet/sing/common/buf"
	"github.com/sagernet/sing/common/bufio"
	E "github.com/sagernet/sing/common/exceptions"
	M "github.com/sagernet/sing/common/metadata"
	N "github.com/sagernet/sing/common/network"
	"github.com/sagernet/sing/common/replay"
	"github.com/sagernet/sing/common/rw"

	"github.com/gofrs/uuid/v5"
)

type Handler interface {
	N.TCPConnectionHandlerEx
	N.UDPConnectionHandlerEx
}

var (
	ErrBadHeader    = E.New("bad header")
	ErrBadTimestamp = E.New("bad timestamp")
	ErrReplay       = E.New("replayed request")
	ErrBadRequest   = E.New("bad request")
	ErrBadVersion   = E.New("bad version")
)

type Service[U comparable] struct {
	users                atomic.Pointer[userTable[U]]
	sources              *sourceCache
	cacheClock           func() int64
	replayFilter         replay.Filter
	handler              Handler
	time                 func() time.Time
	disableHeaderProtect bool
	handshakeTimeout     time.Duration
	fallbackHandler      N.TCPConnectionHandlerEx
	requireEncryption    bool
	responseShaping      *ResponseShapingOptions
	drainCount           atomic.Int32
	legacyAccess         sync.Mutex
	alterIds             map[U]legacyUser
	alterIdUpdateTime    map[U]int64
	alterIdMap           atomic.Pointer[map[[16]byte]legacyUserEntry[U]]
	alterIdUpdateTask    *time.Ticker
	alterIdUpdateDone    chan struct{}
}

type legacyUser struct {
	cmdKey [16]byte
	ids    [][16]byte
}

type legacyUserEntry[U comparable] struct {
	User   U
	CmdKey [16]byte
	Time   int64
	Index  int
}

const (
	// DefaultHandshakeTimeout bounds reading the request header.
	DefaultHandshakeTimeout = 10 * time.Second
	// DefaultFallbackHandshakeTimeout is the header budget with a web
	// fallback, matching the trojan inbound and the built-in V2bX site.
	DefaultFallbackHandshakeTimeout = 30 * time.Second

	maxDrainingConnections = 4096
)

func NewService[U comparable](handler Handler, options ...ServiceOption) *Service[U] {
	service := &Service[U]{
		replayFilter:     replay.NewSimple(time.Second * 120),
		handler:          handler,
		time:             time.Now,
		handshakeTimeout: -1,
		sources:          newSourceCache(defaultScanFailureBurst, defaultScanFailureRate),
		cacheClock: func() int64 {
			return time.Now().UnixNano()
		},
	}
	anyService := (*Service[string])(unsafe.Pointer(service))
	for _, option := range options {
		option(anyService)
	}
	if service.handshakeTimeout < 0 {
		service.handshakeTimeout = DefaultHandshakeTimeout
		if service.fallbackHandler != nil {
			service.handshakeTimeout = DefaultFallbackHandshakeTimeout
		}
	}
	return service
}

func (s *Service[U]) UpdateUsers(userList []U, userIdList []string, alterIdList []int) error {
	previous := s.users.Load()
	table := &userTable[U]{
		entries: make([]userEntry[U], 0, len(userList)),
		byHint:  make(map[uint64]int, len(userList)),
		byUser:  make(map[U]struct{}, len(userList)),
	}
	userAlterIds := make(map[U]legacyUser)
	for i, user := range userList {
		userId := userIdList[i]
		userUUID, err := uuid.FromString(userId)
		if err != nil {
			userUUID = uuid.NewV5(uuid.Nil, userId)
		}
		userCmdKey := Key(userUUID)
		entry := userEntry[U]{user: user, cmdKey: userCmdKey}
		// Reuse the AuthID cipher of unchanged users, deriving it is the costly part.
		if previous != nil {
			if j, loaded := previous.byHint[keyHint(userCmdKey)]; loaded && previous.entries[j].cmdKey == userCmdKey {
				entry.block = previous.entries[j].block
			}
		}
		if entry.block == nil {
			entry.block, err = aes.NewCipher(KDF(userCmdKey[:], KDFSaltConstAuthIDEncryptionKey)[:16])
			if err != nil {
				return err
			}
		}
		table.byHint[keyHint(userCmdKey)] = len(table.entries)
		table.byUser[user] = struct{}{}
		table.entries = append(table.entries, entry)
		alterId := alterIdList[i]
		if alterId > 0 {
			alterIds := make([][16]byte, 0, alterId)
			currentId := userUUID
			for j := 0; j < alterId; j++ {
				currentId = AlterId(currentId)
				alterIds = append(alterIds, currentId)
			}
			userAlterIds[user] = legacyUser{userCmdKey, alterIds}
		}
	}
	table.legacy = len(userAlterIds) > 0
	s.legacyAccess.Lock()
	s.alterIds = userAlterIds
	s.alterIdUpdateTime = make(map[U]int64)
	s.generateLegacyKeys()
	s.legacyAccess.Unlock()
	s.users.Store(table)
	return nil
}

// Contains reports whether user is in the current user list. A caller that
// closes the connections of deleted users after UpdateUsers can check this
// once a connection is tracked, so none slips through in between.
func (s *Service[U]) Contains(user U) bool {
	table := s.users.Load()
	if table == nil {
		return false
	}
	_, loaded := table.byUser[user]
	return loaded
}

func (s *Service[U]) Start() error {
	const updateInterval = 10 * time.Second
	if table := s.users.Load(); table != nil && table.legacy {
		s.alterIdUpdateTask = time.NewTicker(updateInterval)
		s.alterIdUpdateDone = make(chan struct{})
		go s.loopGenerateLegacyKeys()
	}
	return nil
}

func (s *Service[U]) Close() error {
	if s.alterIdUpdateTask != nil {
		s.alterIdUpdateTask.Stop()
		close(s.alterIdUpdateDone)
	}
	return nil
}

func (s *Service[U]) loopGenerateLegacyKeys() {
	for {
		select {
		case <-s.alterIdUpdateDone:
			return
		case <-s.alterIdUpdateTask.C:
		}
		s.legacyAccess.Lock()
		s.generateLegacyKeys()
		s.legacyAccess.Unlock()
	}
}

// generateLegacyKeys must be called with legacyAccess held.
func (s *Service[U]) generateLegacyKeys() {
	nowSec := s.time().Unix()
	endSec := nowSec + CacheDurationSeconds
	var hashValue [16]byte

	userAlterIdMap := make(map[[16]byte]legacyUserEntry[U])
	userAlterIdUpdateTime := make(map[U]int64)

	for user, legacy := range s.alterIds {
		beginSec := s.alterIdUpdateTime[user]
		if beginSec < nowSec-CacheDurationSeconds {
			beginSec = nowSec - CacheDurationSeconds
		}
		for i, alterId := range legacy.ids {
			idHash := hmac.New(md5.New, alterId[:])
			for ts := beginSec; ts <= endSec; ts++ {
				common.Must(binary.Write(idHash, binary.BigEndian, uint64(ts)))
				idHash.Sum(hashValue[:0])
				idHash.Reset()
				userAlterIdMap[hashValue] = legacyUserEntry[U]{user, legacy.cmdKey, ts, i}
			}
		}
		userAlterIdUpdateTime[user] = nowSec
	}
	s.alterIdUpdateTime = userAlterIdUpdateTime
	s.alterIdMap.Store(&userAlterIdMap)
}

// NewConnection authenticates conn. Every request it cannot serve, for any
// reason, gets the same treatment: the bytes read so far are replayed to the
// fallback handler, or without one the connection is drained until the peer
// closes or the handshake deadline passes. A prober therefore cannot tell bad
// keys, replays, stale timestamps or malformed headers apart, and the reply
// never depends on how many bytes it sent.
func (s *Service[U]) NewConnection(ctx context.Context, conn net.Conn, source M.Socksaddr, onClose N.CloseHandlerFunc) error {
	requestBuffer := buf.New()
	defer requestBuffer.Release()

	deadline := time.Now().Add(s.handshakeTimeout)
	if contextDeadline, loaded := ctx.Deadline(); loaded && contextDeadline.Before(deadline) {
		deadline = contextDeadline
	}
	// A transport that cannot set deadlines keeps working, only unbounded.
	hasDeadline := conn.SetReadDeadline(deadline) == nil

	ctx, request, err := s.handshake(ctx, conn, source, requestBuffer)
	if hasDeadline {
		if clearErr := conn.SetReadDeadline(time.Time{}); clearErr != nil && err == nil {
			err = E.Cause(clearErr, "clear handshake deadline")
		}
	}
	if err != nil {
		requestBuffer.Resize(0, requestBuffer.Start()+requestBuffer.Len())
		return s.reject(ctx, conn, source, requestBuffer, deadline, err, onClose)
	}

	switch request.command {
	case CommandTCP:
		request.conn.shaper = newResponseShaper(s.responseShaping)
		s.handler.NewConnectionEx(ctx, &serverConn{request.conn}, source, request.destination, onClose)
	case CommandUDP:
		s.handler.NewPacketConnectionEx(ctx, &serverPacketConn{request.conn, request.destination}, source, request.destination, onClose)
	case CommandMux:
		return HandleMuxConnection(ctx, &serverConn{request.conn}, source, s.handler)
	}
	return nil
}

type serverRequest struct {
	conn        rawServerConn
	command     byte
	destination M.Socksaddr
}

// handshake reads and checks the request header. Every byte read stays in
// requestBuffer, so on error it can be rewound and replayed.
func (s *Service[U]) handshake(ctx context.Context, conn net.Conn, source M.Socksaddr, requestBuffer *buf.Buffer) (context.Context, *serverRequest, error) {
	const headerLenBufferLen = 2 + CipherOverhead
	const aeadMinHeaderLen = 16 + headerLenBufferLen + 8 + CipherOverhead + 42
	table := s.users.Load()
	minHeaderLen := aeadMinHeaderLen
	if table != nil && table.legacy {
		minHeaderLen = 16 + 38
	}

	if !s.disableHeaderProtect {
		n, err := requestBuffer.ReadOnceFrom(conn)
		if err != nil {
			return ctx, nil, err
		}
		if n < minHeaderLen {
			return ctx, nil, ErrBadHeader
		}
	} else {
		_, err := requestBuffer.ReadAtLeastFrom(conn, minHeaderLen)
		if err != nil {
			return ctx, nil, err
		}
	}

	authId := requestBuffer.To(16)
	var user U
	var cmdKey [16]byte
	var found bool
	if table != nil {
		entry, decodedId := s.matchAuthID(table, authId, source.Addr, s.cacheClock())
		if entry != nil {
			timestamp := int64(binary.BigEndian.Uint64(decodedId[:]))
			if diff := timestamp - s.time().Unix(); diff > 120 || diff < -120 {
				return ctx, nil, ErrBadTimestamp
			}
			if !s.replayFilter.Check(decodedId[:]) {
				return ctx, nil, ErrReplay
			}
			user = entry.user
			cmdKey = entry.cmdKey
			found = true
		}
	}

	var legacyProtocol bool
	var legacyTimestamp uint64
	if !found && table != nil && table.legacy {
		var legacyId [16]byte
		copy(legacyId[:], authId)
		if currUser, loaded := (*s.alterIdMap.Load())[legacyId]; loaded {
			found = true
			legacyProtocol = true
			user = currUser.User
			cmdKey = currUser.CmdKey
			legacyTimestamp = uint64(currUser.Time)
		}
	}
	if !found {
		return ctx, nil, ErrBadRequest
	}

	ctx = auth.ContextWithUser(ctx, user)
	var headerReader io.Reader
	var headerBuffer []byte

	var reader io.Reader
	var err error
	if legacyProtocol {
		requestBuffer.Advance(16)
		reader = io.MultiReader(bytes.NewReader(requestBuffer.Bytes()), conn)

		timeHash := md5.New()
		common.Must(binary.Write(timeHash, binary.BigEndian, legacyTimestamp))
		common.Must(binary.Write(timeHash, binary.BigEndian, legacyTimestamp))
		common.Must(binary.Write(timeHash, binary.BigEndian, legacyTimestamp))
		common.Must(binary.Write(timeHash, binary.BigEndian, legacyTimestamp))
		headerReader = NewStreamReader(reader, cmdKey[:], timeHash.Sum(nil))
		headerBuffer = make([]byte, 38)
		_, err = io.ReadFull(headerReader, headerBuffer)
		if err != nil {
			return ctx, nil, E.Extend(ErrBadHeader, io.ErrShortBuffer)
		}
	} else {
		if requestBuffer.Len() < aeadMinHeaderLen {
			return ctx, nil, ErrBadHeader
		}

		reader = conn

		const nonceIndex = 16 + headerLenBufferLen
		connectionNonce := requestBuffer.Range(nonceIndex, nonceIndex+8)

		lengthKey := KDF(cmdKey[:], KDFSaltConstVMessHeaderPayloadLengthAEADKey, authId, connectionNonce)[:16]
		lengthNonce := KDF(cmdKey[:], KDFSaltConstVMessHeaderPayloadLengthAEADIV, authId, connectionNonce)[:12]
		// Decrypt out of place: on failure the request is replayed unmodified.
		lengthBuffer, err := newAesGcm(lengthKey).Open(nil, lengthNonce, requestBuffer.Range(16, nonceIndex), authId)
		if err != nil {
			return ctx, nil, err
		}

		const headerIndex = nonceIndex + 8
		headerLength := int(binary.BigEndian.Uint16(lengthBuffer))
		needRead := headerLength + headerIndex + CipherOverhead - requestBuffer.Len()
		if needRead > 0 {
			_, err = requestBuffer.ReadFullFrom(conn, needRead)
			if err != nil {
				return ctx, nil, err
			}
		}

		headerKey := KDF(cmdKey[:], KDFSaltConstVMessHeaderPayloadAEADKey, authId, connectionNonce)[:16]
		headerNonce := KDF(cmdKey[:], KDFSaltConstVMessHeaderPayloadAEADIV, authId, connectionNonce)[:12]
		headerBuffer, err = newAesGcm(headerKey).Open(nil, headerNonce, requestBuffer.Range(headerIndex, headerIndex+headerLength+CipherOverhead), authId)
		if err != nil {
			return ctx, nil, err
		}
		// replace with < if support mux
		if len(headerBuffer) <= 38 {
			return ctx, nil, E.Extend(ErrBadHeader, io.ErrShortBuffer)
		}
		requestBuffer.Advance(headerIndex + headerLength + CipherOverhead)
		headerReader = bytes.NewReader(headerBuffer[38:])
	}

	version := headerBuffer[0]
	if version != Version {
		return ctx, nil, E.Extend(ErrBadVersion, version)
	}

	requestBodyKey := make([]byte, 16)
	requestBodyNonce := make([]byte, 16)

	copy(requestBodyKey, headerBuffer[17:33])
	copy(requestBodyNonce, headerBuffer[1:17])

	responseHeader := headerBuffer[33]
	option := headerBuffer[34]
	paddingLen := int(headerBuffer[35] >> 4)
	security := headerBuffer[35] & 0x0F
	switch security {
	case SecurityTypeNone, SecurityTypeLegacy, SecurityTypeAes128Gcm, SecurityTypeChacha20Poly1305:
	default:
		return ctx, nil, E.New("unknown security type: ", security)
	}
	command := headerBuffer[37]
	switch command {
	case CommandTCP, CommandUDP, CommandMux:
	default:
		return ctx, nil, E.New("unknown command: ", command)
	}
	if command == CommandUDP && option == 0 {
		return ctx, nil, E.New("bad packet connection")
	}
	var destination M.Socksaddr
	if command != CommandMux {
		destination, err = AddressSerializer.ReadAddrPort(headerReader)
		if err != nil {
			return ctx, nil, err
		}
	}
	if paddingLen > 0 {
		_, err = io.CopyN(io.Discard, headerReader, int64(paddingLen))
		if err != nil {
			return ctx, nil, E.Extend(ErrBadHeader, "bad padding")
		}
	}
	err = rw.SkipN(headerReader, 4)
	if err != nil {
		return ctx, nil, err
	}
	if !legacyProtocol && requestBuffer.Len() > 0 {
		reader = bufio.NewCachedReader(reader, requestBuffer.ToOwned())
	}
	reader = CreateReader(reader, nil, requestBodyKey, requestBodyNonce, requestBodyKey, requestBodyNonce, security, option)
	if option&RequestOptionChunkStream != 0 && command == CommandTCP || command == CommandMux {
		reader = bufio.NewChunkReader(reader, ReadChunkSize)
	}
	if s.requireEncryption && (security == SecurityTypeNone || security == SecurityTypeLegacy) {
		return ctx, nil, E.New("unauthenticated security type rejected: ", security)
	}
	out := &coalescedWriter{upstream: bufio.NewExtendedWriter(conn)}
	return ctx, &serverRequest{
		conn: rawServerConn{
			Conn:           conn,
			out:            out,
			legacyProtocol: legacyProtocol,
			requestKey:     requestBodyKey,
			requestNonce:   requestBodyNonce,
			responseHeader: responseHeader,
			security:       security,
			option:         option,
			reader:         bufio.NewExtendedReader(reader),
		},
		command:     command,
		destination: destination,
	}, nil
}

func (s *Service[U]) reject(ctx context.Context, conn net.Conn, source M.Socksaddr, request *buf.Buffer, deadline time.Time, err error, onClose N.CloseHandlerFunc) error {
	err = E.Cause(err, "bad request")
	if s.fallbackHandler != nil {
		fallbackConn := conn
		// The header budget is spent: replay the bytes as a finished read so
		// the fallback answers the incomplete request instead of waiting again.
		if E.IsTimeout(err) {
			fallbackConn = &readEndedConn{Conn: conn}
		}
		s.fallbackHandler.NewConnectionEx(ctx, bufio.NewCachedConn(fallbackConn, request), source, M.Socksaddr{}, onClose)
		return nil
	}
	s.drain(conn, deadline)
	return err
}

// drain reads and discards until the peer closes or deadline passes, like a
// server still waiting for a complete request, instead of closing at once.
func (s *Service[U]) drain(conn net.Conn, deadline time.Time) {
	if s.drainCount.Add(1) <= maxDrainingConnections {
		if conn.SetReadDeadline(deadline) == nil {
			io.Copy(io.Discard, conn)
		}
	}
	s.drainCount.Add(-1)
}

// Upstream preserves TLS/ALPN discovery through connection wrappers. Reads are
// intentionally not replaceable: bypassing Read would restart the stalled input.
type readEndedConn struct{ net.Conn }

func (c *readEndedConn) Read([]byte) (int, error) { return 0, io.EOF }
func (c *readEndedConn) Upstream() any            { return c.Conn }
func (c *readEndedConn) ReaderReplaceable() bool  { return false }

var _ N.EarlyWriter = (*rawServerConn)(nil)

type rawServerConn struct {
	net.Conn
	out            *coalescedWriter
	shaper         *responseShaper
	legacyProtocol bool
	requestKey     []byte
	requestNonce   []byte
	responseHeader byte
	security       byte
	option         byte
	reader         N.ExtendedReader
	writer         N.ExtendedWriter
}

func (c *rawServerConn) writeResponse() error {
	if c.legacyProtocol {
		responseKey := md5.Sum(c.requestKey)
		responseNonce := md5.Sum(c.requestNonce)
		c.out.hold()
		headerWriter := NewStreamWriter(c.out, responseKey[:], responseNonce[:])
		_, err := headerWriter.Write([]byte{c.responseHeader, c.option, 0, 0})
		if err != nil {
			return E.Cause(err, "write response")
		}
		c.writer = bufio.NewExtendedWriter(CreateWriter(c.out, headerWriter, c.requestKey, c.requestNonce, responseKey[:], responseNonce[:], c.security, c.option))
	} else {
		responseBuffer := buf.NewSize(2 + CipherOverhead + 4 + CipherOverhead)
		defer responseBuffer.Release()

		_responseKey := sha256.Sum256(c.requestKey[:])
		responseKey := _responseKey[:16]
		_responseNonce := sha256.Sum256(c.requestNonce[:])
		responseNonce := _responseNonce[:16]

		headerLenKey := KDF(responseKey, KDFSaltConstAEADRespHeaderLenKey)[:16]
		headerLenNonce := KDF(responseNonce, KDFSaltConstAEADRespHeaderLenIV)[:12]
		headerLenCipher := newAesGcm(headerLenKey)
		binary.BigEndian.PutUint16(responseBuffer.Extend(2), 4)
		headerLenCipher.Seal(responseBuffer.Index(0), headerLenNonce, responseBuffer.Bytes(), nil)
		responseBuffer.Extend(CipherOverhead)

		headerKey := KDF(responseKey, KDFSaltConstAEADRespHeaderPayloadKey)[:16]
		headerNonce := KDF(responseNonce, KDFSaltConstAEADRespHeaderPayloadIV)[:12]
		headerCipher := newAesGcm(headerKey)
		common.Must(
			responseBuffer.WriteByte(c.responseHeader),
			responseBuffer.WriteByte(c.option),
			responseBuffer.WriteZeroN(2),
		)
		const headerIndex = 2 + CipherOverhead
		headerCipher.Seal(responseBuffer.Index(headerIndex), headerNonce, responseBuffer.From(headerIndex), nil)
		responseBuffer.Extend(CipherOverhead)

		// Held until the first data, so it never travels as a fixed-size write.
		c.out.hold()
		common.Must1(c.out.Write(responseBuffer.Bytes()))

		c.writer = bufio.NewExtendedWriter(CreateWriter(c.out, nil, c.requestKey, c.requestNonce, responseKey, responseNonce, c.security, c.option))
	}
	return nil
}

func (c *rawServerConn) Close() error {
	return common.Close(
		c.Conn,
		c.reader,
	)
}

func (c *rawServerConn) FrontHeadroom() int {
	return MaxFrontHeadroom
}

func (c *rawServerConn) RearHeadroom() int {
	return MaxRearHeadroom
}

func (c *rawServerConn) ReaderOverhead() int {
	return ReaderOverhead(c.security, c.option)
}

func (c *rawServerConn) NeedHandshakeForWrite() bool {
	return c.writer == nil
}

func (c *rawServerConn) NeedAdditionalReadDeadline() bool {
	return true
}

func (c *rawServerConn) Upstream() any {
	return c.Conn
}

type serverConn struct {
	rawServerConn
}

func (c *serverConn) Read(b []byte) (n int, err error) {
	return c.reader.Read(b)
}

func (c *serverConn) ReadBuffer(buffer *buf.Buffer) error {
	return c.reader.ReadBuffer(buffer)
}

func (c *serverConn) WriteTo(w io.Writer) (n int64, err error) {
	return bufio.Copy(w, c.reader)
}

var _ PacketConn = (*serverPacketConn)(nil)

type serverPacketConn struct {
	rawServerConn
	destination M.Socksaddr
}

func (c *serverPacketConn) ReadFrom(p []byte) (n int, addr net.Addr, err error) {
	n, err = c.reader.Read(p)
	if err != nil {
		return
	}
	addr = c.destination.UDPAddr()
	return
}

func (c *serverPacketConn) ReadPacket(buffer *buf.Buffer) (destination M.Socksaddr, err error) {
	err = c.reader.ReadBuffer(buffer)
	if err != nil {
		return
	}
	destination = c.destination
	return
}
