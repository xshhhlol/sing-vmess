package vmess

import "sync"

const replayShards = 64

// Keep an AuthID until its timestamp is no longer acceptable, including the
// last valid second. Key by the encrypted AuthID: the decoded timestamp and
// 32-bit random field can collide between different users.
type serviceReplayFilter struct {
	shards [replayShards]serviceReplayShard
}

type serviceReplayShard struct {
	access    sync.Mutex
	entries   map[[16]byte]int64
	lastClean int64
}

func (f *serviceReplayFilter) shard(id [16]byte) *serviceReplayShard {
	return &f.shards[id[0]%replayShards]
}

func (f *serviceReplayFilter) contains(id [16]byte, now int64) bool {
	s := f.shard(id)
	s.access.Lock()
	defer s.access.Unlock()
	expires, found := s.entries[id]
	return found && expires >= now
}

// check atomically claims an authenticated request. Call only after the full
// header has been verified; a modified or truncated header must not consume
// the genuine request's AuthID.
func (f *serviceReplayFilter) check(id [16]byte, expires, now int64) bool {
	s := f.shard(id)
	s.access.Lock()
	defer s.access.Unlock()
	if until, found := s.entries[id]; found && until >= now {
		return false
	}
	if s.entries == nil {
		s.entries = make(map[[16]byte]int64)
	}
	if now-s.lastClean >= 30 {
		for oldID, until := range s.entries {
			if until < now {
				delete(s.entries, oldID)
			}
		}
		s.lastClean = now
	}
	s.entries[id] = expires
	return true
}
