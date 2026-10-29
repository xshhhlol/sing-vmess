package vmess

import (
	"io"
	"math/rand"
	"net"

	"github.com/sagernet/sing/common/buf"
	"github.com/sagernet/sing/common/bufio"
	M "github.com/sagernet/sing/common/metadata"
	N "github.com/sagernet/sing/common/network"
)

// The chunk writers emit a chunk as several small writes (length, payload,
// padding), and the AEAD response header used to be a write of its own. Over
// TLS or with TCP_NODELAY each write can become its own record or segment, so
// the first downlink record always had the same length and every chunk could
// leak a 2-byte record. coalescedWriter gathers what one application write
// produces, including the pending response header, into a single write. The
// byte stream is unchanged.

const coalesceLimit = 32 * 1024

type coalescedWriter struct {
	upstream N.ExtendedWriter
	pending  []byte
	holding  bool
}

func (w *coalescedWriter) hold() {
	w.holding = true
}

func (w *coalescedWriter) Write(p []byte) (int, error) {
	if !w.holding {
		return w.upstream.Write(p)
	}
	if len(w.pending) >= coalesceLimit {
		if err := w.writePending(); err != nil {
			return 0, err
		}
	}
	w.pending = append(w.pending, p...)
	return len(p), nil
}

func (w *coalescedWriter) WriteBuffer(buffer *buf.Buffer) error {
	if !w.holding {
		return w.upstream.WriteBuffer(buffer)
	}
	defer buffer.Release()
	_, err := w.Write(buffer.Bytes())
	return err
}

func (w *coalescedWriter) flush() error {
	w.holding = false
	return w.writePending()
}

func (w *coalescedWriter) writePending() error {
	if len(w.pending) == 0 {
		return nil
	}
	_, err := w.upstream.Write(w.pending)
	if cap(w.pending) > coalesceLimit*2 {
		w.pending = nil
	} else {
		w.pending = w.pending[:0]
	}
	return err
}

// ResponseShapingOptions splits the first downlink data of a TCP request into
// records of random size, so the nested TLS handshake of the proxied
// connection does not show its usual record lengths. Only the server changes;
// clients read the same byte stream. Each extra record costs one chunk header
// and tag. Uplink and the total size of a burst are not changed.
type ResponseShapingOptions struct {
	MinRecordSize int // Default: 256 payload bytes.
	MaxRecordSize int // Default: 1400; maximum: WriteChunkSize.
	MinRecords    int // Default: 8 shaped records per connection.
	MaxRecords    int // Default: 16; maximum: 256.
}

func normalizeResponseShaping(options ResponseShapingOptions) *ResponseShapingOptions {
	if options.MinRecordSize <= 0 {
		options.MinRecordSize = 256
	}
	if options.MaxRecordSize <= 0 {
		options.MaxRecordSize = 1400
	}
	options.MaxRecordSize = minInt(options.MaxRecordSize, WriteChunkSize)
	options.MinRecordSize = minInt(options.MinRecordSize, options.MaxRecordSize)
	if options.MinRecords <= 0 {
		options.MinRecords = 8
	}
	if options.MaxRecords <= 0 {
		options.MaxRecords = 16
	}
	options.MaxRecords = minInt(options.MaxRecords, 256)
	options.MinRecords = minInt(options.MinRecords, options.MaxRecords)
	return &options
}

func minInt(a, b int) int {
	if a < b {
		return a
	}
	return b
}

func randomBetween(low, high int) int {
	return low + rand.Intn(high-low+1)
}

type responseShaper struct {
	minSize   int
	maxSize   int
	remaining int
}

func newResponseShaper(options *ResponseShapingOptions) *responseShaper {
	if options == nil {
		return nil
	}
	return &responseShaper{
		minSize:   options.MinRecordSize,
		maxSize:   options.MaxRecordSize,
		remaining: randomBetween(options.MinRecords, options.MaxRecords),
	}
}

func (s *responseShaper) active() bool {
	return s != nil && s.remaining > 0
}

// next returns how much of n bytes the next record carries.
func (s *responseShaper) next(n int) int {
	s.remaining--
	return minInt(n, randomBetween(s.minSize, s.maxSize))
}

func (c *rawServerConn) prepareWrite() error {
	if c.writer == nil {
		return c.writeResponse()
	}
	return nil
}

// write sends p as one coalesced write, or as shaped records while the
// shaping window lasts.
func (c *rawServerConn) write(p []byte) (n int, err error) {
	if err = c.prepareWrite(); err != nil {
		return
	}
	if len(p) == 0 {
		// Sends a pending response header, as an empty write always did.
		return 0, c.out.flush()
	}
	for len(p) > 0 {
		size := len(p)
		if c.shaper.active() {
			size = c.shaper.next(size)
		}
		c.out.hold()
		_, err = c.writer.Write(p[:size])
		if flushErr := c.out.flush(); err == nil {
			err = flushErr
		}
		if err != nil {
			return
		}
		n += size
		p = p[size:]
	}
	return
}

func (c *rawServerConn) writeBuffer(buffer *buf.Buffer) error {
	if err := c.prepareWrite(); err != nil {
		buffer.Release()
		return err
	}
	if c.shaper.active() {
		defer buffer.Release()
		_, err := c.write(buffer.Bytes())
		return err
	}
	// The buffer path already writes each chunk at once; only the response
	// header may still be pending.
	if len(c.out.pending) == 0 {
		return c.writer.WriteBuffer(buffer)
	}
	c.out.hold()
	err := c.writer.WriteBuffer(buffer)
	if flushErr := c.out.flush(); err == nil {
		err = flushErr
	}
	return err
}

func (c *serverConn) Write(b []byte) (n int, err error) {
	return c.write(b)
}

func (c *serverConn) WriteBuffer(buffer *buf.Buffer) error {
	return c.writeBuffer(buffer)
}

func (c *serverConn) ReadFrom(r io.Reader) (n int64, err error) {
	if err = c.prepareWrite(); err != nil {
		return
	}
	return bufio.Copy(&serverConnWriter{&c.rawServerConn}, r)
}

// serverConnWriter keeps bufio.Copy on the coalesced and shaped write path.
// It deliberately has no Upstream, so the copy cannot unwrap it to the
// connection and bypass the chunk writer.
type serverConnWriter struct {
	conn *rawServerConn
}

func (w *serverConnWriter) Write(p []byte) (int, error) {
	return w.conn.write(p)
}

func (w *serverConnWriter) WriteBuffer(buffer *buf.Buffer) error {
	return w.conn.writeBuffer(buffer)
}

func (w *serverConnWriter) FrontHeadroom() int {
	return w.conn.FrontHeadroom()
}

func (w *serverConnWriter) RearHeadroom() int {
	return w.conn.RearHeadroom()
}

func (c *serverPacketConn) WriteTo(p []byte, _ net.Addr) (n int, err error) {
	return c.write(p)
}

func (c *serverPacketConn) WritePacket(buffer *buf.Buffer, _ M.Socksaddr) error {
	return c.writeBuffer(buffer)
}
