package server

import (
	"hash/maphash"
	"net/netip"
	"sync"
	"time"
)

// limiter is a sharded per-client token bucket.
type limiter struct {
	rate   float64 // tokens per second
	burst  float64
	seed   maphash.Seed
	shards [32]limShard
}

type limShard struct {
	mu sync.Mutex
	m  map[netip.Addr]*bucket
}

type bucket struct {
	tokens float64
	last   time.Time
}

func newLimiter(qps, burst int) *limiter {
	if qps <= 0 {
		return nil
	}
	if burst < qps {
		burst = qps
	}
	l := &limiter{rate: float64(qps), burst: float64(burst), seed: maphash.MakeSeed()}
	for i := range l.shards {
		l.shards[i].m = map[netip.Addr]*bucket{}
	}
	return l
}

// allow reports whether the client may send one more query.
func (l *limiter) allow(ip netip.Addr, now time.Time) bool {
	if l == nil {
		return true
	}
	b16 := ip.As16()
	sh := &l.shards[maphash.Bytes(l.seed, b16[:])%uint64(len(l.shards))]
	sh.mu.Lock()
	defer sh.mu.Unlock()
	b := sh.m[ip]
	if b == nil {
		sh.m[ip] = &bucket{tokens: l.burst - 1, last: now}
		return true
	}
	b.tokens += now.Sub(b.last).Seconds() * l.rate
	if b.tokens > l.burst {
		b.tokens = l.burst
	}
	b.last = now
	if b.tokens < 1 {
		return false
	}
	b.tokens--
	return true
}

// gc drops idle buckets.
func (l *limiter) gc(now time.Time) {
	if l == nil {
		return
	}
	for i := range l.shards {
		sh := &l.shards[i]
		sh.mu.Lock()
		for k, b := range sh.m {
			if now.Sub(b.last) > time.Minute {
				delete(sh.m, k)
			}
		}
		sh.mu.Unlock()
	}
}
