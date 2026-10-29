package vmess

import (
	"crypto/cipher"
	"encoding/binary"
	"hash/crc32"
	"net/netip"
	"sync"
	"time"
)

// AuthID lookup has to try every user's key, so a connection that matches no
// user costs O(users). Two things keep that off the hot path without changing
// the wire format:
//   - each source address remembers the users that recently authenticated from
//     it, and those are tried first;
//   - full scans that end without a match are rate limited per source, so junk
//     connections and clients with deleted users cannot saturate the CPU.
// Remembered users of a source are always tried, even when its limit is spent.

const (
	sourceHintSlots     = 8
	sourceCacheShards   = 64
	sourceShardCapacity = 1024
	sourceIdleTimeout   = 10 * time.Minute

	defaultScanFailureBurst = 256
	defaultScanFailureRate  = 16 // per second
)

type userEntry[U comparable] struct {
	user   U
	cmdKey [16]byte
	block  cipher.Block
}

// decodeAuthID reports whether authID was encrypted with this user's key.
func (e *userEntry[U]) decodeAuthID(dst *[16]byte, authID []byte) bool {
	e.block.Decrypt(dst[:], authID)
	return crc32.ChecksumIEEE(dst[:12]) == binary.BigEndian.Uint32(dst[12:])
}

// userTable is immutable once published, so connections never see a
// half-updated user list.
type userTable[U comparable] struct {
	entries []userEntry[U]
	byHint  map[uint64]int
	byUser  map[U]struct{}
	legacy  bool
}

func keyHint(cmdKey [16]byte) uint64 {
	return binary.BigEndian.Uint64(cmdKey[:8])
}

type sourceState struct {
	hints    [sourceHintSlots]uint64
	hintN    int
	lastSeen int64
	tokens   float64
	refillAt int64
}

type sourceShard struct {
	access  sync.Mutex
	sources map[netip.Addr]*sourceState
}

type sourceCache struct {
	burst  float64
	rate   float64
	shards [sourceCacheShards]sourceShard
}

func newSourceCache(burst int, rate float64) *sourceCache {
	c := &sourceCache{burst: float64(burst), rate: rate}
	for i := range c.shards {
		c.shards[i].sources = make(map[netip.Addr]*sourceState)
	}
	return c
}

func (c *sourceCache) shard(addr netip.Addr) *sourceShard {
	b := addr.As16()
	return &c.shards[(binary.BigEndian.Uint64(b[:8])^binary.BigEndian.Uint64(b[8:]))%sourceCacheShards]
}

// get returns the state of addr, creating it if needed. The shard lock must be held.
func (c *sourceCache) get(shard *sourceShard, addr netip.Addr, now int64) *sourceState {
	state := shard.sources[addr]
	if state == nil {
		if len(shard.sources) >= sourceShardCapacity {
			shard.evict(now)
		}
		state = &sourceState{tokens: c.burst, refillAt: now}
		shard.sources[addr] = state
	}
	state.lastSeen = now
	return state
}

func (s *sourceShard) evict(now int64) {
	for addr, state := range s.sources {
		if now-state.lastSeen > int64(sourceIdleTimeout) {
			delete(s.sources, addr)
		}
	}
	// Map iteration order is random, so this drops an arbitrary half.
	for addr := range s.sources {
		if len(s.sources) < sourceShardCapacity/2 {
			break
		}
		delete(s.sources, addr)
	}
}

func (c *sourceCache) hints(addr netip.Addr, now int64) (hints [sourceHintSlots]uint64, n int) {
	shard := c.shard(addr)
	shard.access.Lock()
	defer shard.access.Unlock()
	if state := shard.sources[addr]; state != nil {
		state.lastSeen = now
		return state.hints, state.hintN
	}
	return
}

func (c *sourceCache) remember(addr netip.Addr, hint uint64, now int64) {
	shard := c.shard(addr)
	shard.access.Lock()
	defer shard.access.Unlock()
	state := c.get(shard, addr, now)
	i := 0
	for i < state.hintN && state.hints[i] != hint {
		i++
	}
	if i == state.hintN {
		if state.hintN < sourceHintSlots {
			state.hintN++
		} else {
			i = sourceHintSlots - 1
		}
	}
	copy(state.hints[1:i+1], state.hints[:i])
	state.hints[0] = hint
}

// allowScan reports whether addr still has budget for failed full scans.
func (c *sourceCache) allowScan(addr netip.Addr, now int64) bool {
	if c.burst <= 0 {
		return true
	}
	shard := c.shard(addr)
	shard.access.Lock()
	defer shard.access.Unlock()
	state := c.get(shard, addr, now)
	state.tokens += float64(now-state.refillAt) / float64(time.Second) * c.rate
	if state.tokens > c.burst {
		state.tokens = c.burst
	}
	state.refillAt = now
	return state.tokens >= 1
}

func (c *sourceCache) scanFailed(addr netip.Addr, now int64) {
	if c.burst <= 0 {
		return
	}
	shard := c.shard(addr)
	shard.access.Lock()
	defer shard.access.Unlock()
	c.get(shard, addr, now).tokens--
}

func sourceAddr(addr netip.Addr) (netip.Addr, bool) {
	if !addr.IsValid() {
		return addr, false
	}
	return addr.Unmap(), true
}

// matchAuthID finds the user whose key decrypts authID.
func (s *Service[U]) matchAuthID(table *userTable[U], authID []byte, source netip.Addr, now int64) (entry *userEntry[U], decoded [16]byte) {
	addr, cached := sourceAddr(source)
	cached = cached && s.sources != nil
	if cached {
		hints, n := s.sources.hints(addr, now)
		for _, hint := range hints[:n] {
			if i, loaded := table.byHint[hint]; loaded && table.entries[i].decodeAuthID(&decoded, authID) {
				return &table.entries[i], decoded
			}
		}
		if !s.sources.allowScan(addr, now) {
			return nil, decoded
		}
	}
	for i := range table.entries {
		if table.entries[i].decodeAuthID(&decoded, authID) {
			if cached {
				s.sources.remember(addr, keyHint(table.entries[i].cmdKey), now)
			}
			return &table.entries[i], decoded
		}
	}
	if cached {
		s.sources.scanFailed(addr, now)
	}
	return nil, decoded
}
