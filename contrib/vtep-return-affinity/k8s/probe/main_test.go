// This file was not reviewed by a human before submission
// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium
package main

import (
	"bufio"
	"net"
	"testing"
	"time"
)

func TestExplicitSourceReachesServer(t *testing.T) {
	l, err := net.ListenTCP("tcp4", &net.TCPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatal(err)
	}
	defer l.Close()
	_ = l.SetDeadline(time.Now().Add(3 * time.Second))
	reservation, err := net.ListenTCP("tcp4", &net.TCPAddr{IP: net.IPv4(127, 0, 0, 2)})
	if err != nil {
		t.Fatal(err)
	}
	source := reservation.Addr().String()
	reservation.Close()
	seen := make(chan string, 1)
	go func() {
		c, err := l.Accept()
		if err != nil {
			seen <- ""
			return
		}
		defer c.Close()
		_ = c.SetDeadline(time.Now().Add(3 * time.Second))
		line, _ := bufio.NewReader(c).ReadString('\n')
		if line != "PING\n" {
			seen <- ""
			return
		}
		_, _ = c.Write([]byte("PONG fixture\n"))
		seen <- c.RemoteAddr().String()
	}()
	if err := run("request", l.Addr().String(), "", 2*time.Second, source); err != nil {
		t.Fatal(err)
	}
	if got := <-seen; got != source {
		t.Fatalf("source changed: %s", got)
	}
}

func TestExplicitSourceCannotCreateFalsePolicyDenial(t *testing.T) {
	for _, source := range []string{"0.0.0.0:12345", "127.0.0.1:0", "localhost:12345", "[::1]:12345"} {
		err := run("request", "127.0.0.1:1", "", time.Second, source)
		if err == nil || err.Error() != "invalid explicit IPv4 client address" {
			t.Fatalf("invalid source became a policy result: %v", err)
		}
	}
	l, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer l.Close()
	err = run("request", "127.0.0.1:1", "", time.Second, l.Addr().String())
	if err == nil || err.Error() != "TCP client setup failed" {
		t.Fatalf("occupied source port became a policy denial: %v", err)
	}
}
