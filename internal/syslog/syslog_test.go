package syslog

import (
	"bufio"
	"context"
	"net"
	"strings"
	"testing"
	"time"

	"github.com/takobas/vartadns/internal/stats"
)

func TestUDPAndTCP(t *testing.T) {
	pc, _ := net.ListenPacket("udp", "127.0.0.1:0")
	defer pc.Close()
	ln, _ := net.Listen("tcp", "127.0.0.1:0")
	defer ln.Close()

	s := New(Settings{Enabled: true, Address: pc.LocalAddr().String(), Protocol: "udp", Mode: "threats"})
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go s.Run(ctx)
	s.Query(&stats.Entry{Time: time.Now(), Client: "10.0.0.1", Name: "ads.example", Status: "blocked", Kind: "ads"})
	s.Query(&stats.Entry{Time: time.Now(), Client: "10.0.0.1", Name: "evil.example", Status: "blocked", Kind: "malware"})
	buf := make([]byte, 9000)
	pc.SetReadDeadline(time.Now().Add(2 * time.Second))
	n, _, err := pc.ReadFrom(buf)
	if err != nil {
		t.Fatal(err)
	}
	msg := string(buf[:n])
	if !strings.HasPrefix(msg, "<132>1 ") || !strings.Contains(msg, `"name":"evil.example"`) || !strings.Contains(msg, " QUERY - {") {
		t.Fatalf("udp message: %s", msg)
	}

	set := Settings{Enabled: true, Address: ln.Addr().String(), Protocol: "tcp", Mode: "all", Audit: true}
	if err := set.Validate(); err != nil {
		t.Fatal(err)
	}
	s.SetSettings(set)
	s.Audit(map[string]string{"user": "admin", "action": "login"})
	c, err := ln.Accept()
	if err != nil {
		t.Fatal(err)
	}
	c.SetReadDeadline(time.Now().Add(3 * time.Second))
	line, err := bufio.NewReader(c).ReadString('}')
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(line, " AUDIT - ") || !strings.Contains(line, "<133>1") {
		t.Fatalf("tcp message: %s", line)
	}
	if !strings.Contains(strings.SplitN(line, " ", 2)[0], "") {
		t.Fatal("octet count")
	}
	bad := Settings{Enabled: true, Address: "nope", Protocol: "udp"}
	if bad.Validate() == nil {
		t.Fatal("bad address must fail")
	}
}
