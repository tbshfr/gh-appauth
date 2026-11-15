package main

import (
	"net/netip"
	"sync"
	"time"
)

// limitKey is the bucket key for a source address. IPv6 is keyed by /64
// because a single host usually controls that whole range.
func limitKey(ip netip.Addr) string {
	if ip.Is6() {
		if p, err := ip.Prefix(64); err == nil {
			return p.String()
		}
	}
	return ip.String()
}

// limiter is a set of token buckets keyed by string (client name or IP).
type limiter struct {
	mu      sync.Mutex
	perSec  float64
	burst   float64
	buckets map[string]*bucket
}

type bucket struct {
	tokens float64
	last   time.Time
}

func newLimiter(perMinute int) *limiter {
	return &limiter{perSec: float64(perMinute) / 60, burst: float64(perMinute), buckets: map[string]*bucket{}}
}

func (l *limiter) get(key string, now time.Time) *bucket {
	b := l.buckets[key]
	if b == nil {
		if len(l.buckets) > 10000 {
			l.gc(now)
		}
		b = &bucket{tokens: l.burst, last: now}
		l.buckets[key] = b
		return b
	}
	b.tokens += now.Sub(b.last).Seconds() * l.perSec
	if b.tokens > l.burst {
		b.tokens = l.burst
	}
	b.last = now
	return b
}

// gc drops buckets that have refilled completely; they carry no state.
func (l *limiter) gc(now time.Time) {
	for k, b := range l.buckets {
		if b.tokens+now.Sub(b.last).Seconds()*l.perSec >= l.burst {
			delete(l.buckets, k)
		}
	}
}

// allow takes one token and reports whether one was available.
func (l *limiter) allow(key string, now time.Time) bool {
	l.mu.Lock()
	defer l.mu.Unlock()
	b := l.get(key, now)
	if b.tokens < 1 {
		return false
	}
	b.tokens--
	return true
}

// refund returns a token taken with allow. Failure limits take a token
// before checking a credential and refund it on success, so concurrent
// attempts can't all slip past a check made before any of them is counted.
func (l *limiter) refund(key string, now time.Time) {
	l.mu.Lock()
	defer l.mu.Unlock()
	if b := l.get(key, now); b.tokens < l.burst {
		b.tokens++
	}
}
