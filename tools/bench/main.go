// Command bench is a simple UDP DNS load generator.
//
//	go run ./tools/bench -server 127.0.0.1:53 -c 64 -d 10s -names 20000
package main

import (
	"flag"
	"fmt"
	"log"
	"net"
	"sort"
	"sync"
	"sync/atomic"
	"time"

	"github.com/takobas/vartadns/internal/dnsmsg"
)

func main() {
	server := flag.String("server", "127.0.0.1:53", "DNS server address")
	conc := flag.Int("c", 64, "concurrent workers")
	dur := flag.Duration("d", 10*time.Second, "test duration")
	names := flag.Int("names", 20000, "distinct names (lower = more cache hits)")
	blockedPct := flag.Int("blocked", 20, "percent of queries for a blocked domain (ads.<n>.test-block.com)")
	flag.Parse()

	var ok, timeouts atomic.Int64
	var mu sync.Mutex
	var lat []time.Duration
	deadline := time.Now().Add(*dur)
	var wg sync.WaitGroup
	for w := 0; w < *conc; w++ {
		wg.Add(1)
		go func(w int) {
			defer wg.Done()
			conn, err := net.Dial("udp", *server)
			if err != nil {
				log.Fatal(err)
			}
			defer conn.Close()
			buf := make([]byte, 4096)
			local := make([]time.Duration, 0, 1<<16)
			for i := 0; time.Now().Before(deadline); i++ {
				n := (w*7919 + i*104729) % *names
				name := fmt.Sprintf("host%d.example%d.org", n, n%97)
				if (i % 100) < *blockedPct {
					name = fmt.Sprintf("ads%d.test-block.com", n)
				}
				id := uint16(i)
				q := dnsmsg.BuildQuery(id, name, dnsmsg.TypeA)
				start := time.Now()
				_ = conn.SetDeadline(start.Add(2 * time.Second))
				if _, err := conn.Write(q); err != nil {
					continue
				}
				for {
					m, err := conn.Read(buf)
					if err != nil {
						timeouts.Add(1)
						break
					}
					if m >= 12 && dnsmsg.ID(buf[:m]) == id {
						ok.Add(1)
						local = append(local, time.Since(start))
						break
					}
				}
			}
			mu.Lock()
			lat = append(lat, local...)
			mu.Unlock()
		}(w)
	}
	wg.Wait()
	sort.Slice(lat, func(i, j int) bool { return lat[i] < lat[j] })
	p := func(q float64) time.Duration {
		if len(lat) == 0 {
			return 0
		}
		return lat[int(float64(len(lat)-1)*q)]
	}
	fmt.Printf("answers: %d  timeouts: %d  qps: %.0f\n", ok.Load(), timeouts.Load(), float64(ok.Load())/dur.Seconds())
	fmt.Printf("latency p50=%v p95=%v p99=%v max=%v\n", p(.5), p(.95), p(.99), p(1))
}
