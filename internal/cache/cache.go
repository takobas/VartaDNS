// Package cache is a sharded, TTL-aware cache of raw DNS responses.
package cache

import (
	"hash/maphash"
	"sync"
	"sync/atomic"
	"time"

	"github.com/takobas/vartadns/internal/dnsmsg"
)

const shardCount = 64

type entry struct {
	msg        []byte // response as received from upstream (never mutated)
	ttlOffsets []int
	stored     time.Time
	expires    time.Time
}

type shard struct {
	mu sync.RWMutex
	m  map[string]*entry
}

// Cache stores responses keyed by question (name/type/class/flags).
type Cache struct {
	shards   [shardCount]shard
	seed     maphash.Seed
	perShard int
	minTTL   uint32
	maxTTL   uint32
	negTTL   uint32

	hits, misses atomic.Uint64
}

// New creates a cache holding up to size entries.
func New(size int, minTTL, maxTTL, negTTL uint32) *Cache {
	if size < shardCount {
		size = shardCount
	}
	c := &Cache{seed: maphash.MakeSeed(), perShard: size / shardCount,
		minTTL: minTTL, maxTTL: maxTTL, negTTL: negTTL}
	for i := range c.shards {
		c.shards[i].m = make(map[string]*entry)
	}
	return c
}

// Key builds a cache key for a query.
func Key(q dnsmsg.Query) string {
	flags := byte('0')
	if q.DO {
		flags |= 1
	}
	if q.CD {
		flags |= 2
	}
	b := make([]byte, 0, len(q.Name)+8)
	b = append(b, q.Name...)
	b = append(b, '|', byte(q.Type>>8), byte(q.Type), byte(q.Class>>8), byte(q.Class), flags)
	return string(b)
}

func (c *Cache) shardFor(key string) *shard {
	return &c.shards[maphash.String(c.seed, key)%shardCount]
}

// Get returns a fresh copy of the cached response with the client's ID and
// aged TTLs, or nil on a miss.
func (c *Cache) Get(key string, id uint16) []byte {
	s := c.shardFor(key)
	s.mu.RLock()
	e := s.m[key]
	s.mu.RUnlock()
	now := time.Now()
	if e == nil || now.After(e.expires) {
		c.misses.Add(1)
		return nil
	}
	c.hits.Add(1)
	out := make([]byte, len(e.msg))
	copy(out, e.msg)
	dnsmsg.SetID(out, id)
	elapsed := uint32(now.Sub(e.stored) / time.Second)
	dnsmsg.AgeTTLs(out, e.ttlOffsets, elapsed, 1)
	return out
}

// Put stores a response. Only NOERROR and NXDOMAIN, non-truncated answers
// are cached.
func (c *Cache) Put(key string, msg []byte, info dnsmsg.RRInfo) {
	if dnsmsg.Truncated(msg) {
		return
	}
	rc := dnsmsg.Rcode(msg)
	if rc != dnsmsg.RcodeSuccess && rc != dnsmsg.RcodeNXDomain {
		return
	}
	ttl := c.negTTL
	if info.HasTTL {
		ttl = info.MinTTL
	}
	if ttl < c.minTTL {
		ttl = c.minTTL
	}
	if c.maxTTL > 0 && ttl > c.maxTTL {
		ttl = c.maxTTL
	}
	if ttl == 0 {
		return
	}
	now := time.Now()
	e := &entry{msg: append([]byte(nil), msg...), ttlOffsets: info.TTLOffsets,
		stored: now, expires: now.Add(time.Duration(ttl) * time.Second)}

	s := c.shardFor(key)
	s.mu.Lock()
	if len(s.m) >= c.perShard {
		c.evictLocked(s, now)
	}
	s.m[key] = e
	s.mu.Unlock()
}

// evictLocked removes expired entries; if none expired it drops a few
// arbitrary ones (Go map iteration order is random).
func (c *Cache) evictLocked(s *shard, now time.Time) {
	removed := 0
	for k, e := range s.m {
		if now.After(e.expires) {
			delete(s.m, k)
			removed++
		}
	}
	if removed > 0 {
		return
	}
	n := c.perShard/16 + 1
	for k := range s.m {
		delete(s.m, k)
		n--
		if n == 0 {
			return
		}
	}
}

// Len returns the number of cached entries.
func (c *Cache) Len() int {
	n := 0
	for i := range c.shards {
		c.shards[i].mu.RLock()
		n += len(c.shards[i].m)
		c.shards[i].mu.RUnlock()
	}
	return n
}

// Flush empties the cache.
func (c *Cache) Flush() {
	for i := range c.shards {
		c.shards[i].mu.Lock()
		c.shards[i].m = make(map[string]*entry)
		c.shards[i].mu.Unlock()
	}
}

// Stats returns hit/miss counters.
func (c *Cache) Stats() (hits, misses uint64) { return c.hits.Load(), c.misses.Load() }

// Janitor periodically removes expired entries until stop is closed.
func (c *Cache) Janitor(every time.Duration, stop <-chan struct{}) {
	t := time.NewTicker(every)
	defer t.Stop()
	for {
		select {
		case <-stop:
			return
		case now := <-t.C:
			for i := range c.shards {
				s := &c.shards[i]
				s.mu.Lock()
				for k, e := range s.m {
					if now.After(e.expires) {
						delete(s.m, k)
					}
				}
				s.mu.Unlock()
			}
		}
	}
}
