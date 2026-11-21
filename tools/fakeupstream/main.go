// Command fakeupstream is a test-only DNS server that answers every A query
// with 1.2.3.4 and everything else with NODATA. Used for load testing.
package main

import (
	"encoding/binary"
	"flag"
	"log"
	"net"
	"runtime"

	"github.com/takobas/vartadns/internal/dnsmsg"
)

func main() {
	addr := flag.String("listen", "127.0.0.1:5300", "listen address")
	flag.Parse()
	pc, err := net.ListenPacket("udp", *addr)
	if err != nil {
		log.Fatal(err)
	}
	log.Printf("fake upstream on %s", *addr)
	for i := 0; i < runtime.NumCPU(); i++ {
		go serve(pc)
	}
	select {}
}

func serve(pc net.PacketConn) {
	buf := make([]byte, 4096)
	for {
		n, a, err := pc.ReadFrom(buf)
		if err != nil {
			return
		}
		q, err := dnsmsg.ParseQuery(buf[:n])
		if err != nil {
			continue
		}
		r := append([]byte(nil), buf[:q.QEnd]...)
		r[2] |= 0x80
		r[3] = 0x80
		binary.BigEndian.PutUint16(r[8:12], 0)
		binary.BigEndian.PutUint16(r[10:12], 0)
		if q.Type == dnsmsg.TypeA {
			binary.BigEndian.PutUint16(r[6:8], 1)
			r = append(r, 0xC0, 12, 0, 1, 0, 1, 0, 0, 1, 44, 0, 4, 1, 2, 3, 4)
		} else {
			binary.BigEndian.PutUint16(r[6:8], 0)
		}
		_, _ = pc.WriteTo(r, a)
	}
}
