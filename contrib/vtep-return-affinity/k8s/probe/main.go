// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

// A dependency-free lab workload. A hold session never reconnects: every
// response must carry the same server-side connection identity.
package main

import (
	"bufio"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"flag"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"strings"
	"time"
)

type progress struct {
	Connection string `json:"connection"`
	Requests   int    `json:"requests"`
	Error      string `json:"error,omitempty"`
}

func writeProgress(path string, p progress) error {
	b, err := json.Marshal(p)
	if err != nil {
		return err
	}
	tmp := filepath.Clean(path) + ".tmp"
	if err := os.WriteFile(tmp, b, 0600); err != nil {
		return err
	}
	return os.Rename(tmp, path)
}

func main() {
	mode := flag.String("mode", "serve", "serve, request, hold, or read-state")
	target := flag.String("target", ":8080", "TCP address")
	state := flag.String("state", "/tmp/session.json", "hold progress file")
	timeout := flag.Duration("timeout", 2*time.Second, "per-request timeout")
	flag.Parse()
	if err := run(*mode, *target, *state, *timeout); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}

func run(mode, target, state string, timeout time.Duration) error {
	if mode == "read-state" {
		b, err := os.ReadFile(state)
		if err == nil {
			_, err = os.Stdout.Write(b)
		}
		return err
	}
	if mode == "serve" {
		l, err := net.Listen("tcp4", target)
		if err != nil {
			return err
		}
		defer l.Close()
		for {
			c, err := l.Accept()
			if err != nil {
				return err
			}
			go func() {
				defer c.Close()
				var token [16]byte
				if _, err := rand.Read(token[:]); err != nil {
					return
				}
				id := hex.EncodeToString(token[:])
				r := bufio.NewReader(c)
				for {
					line, err := r.ReadString('\n')
					if err != nil || line != "PING\n" {
						return
					}
					if _, err := fmt.Fprintln(c, "PONG "+id); err != nil {
						return
					}
				}
			}()
		}
	}
	if mode != "request" && mode != "hold" {
		return fmt.Errorf("unknown mode")
	}
	c, err := net.DialTimeout("tcp4", target, timeout)
	if err != nil {
		return fmt.Errorf("TCP connection failed")
	}
	defer c.Close()
	r := bufio.NewReader(c)
	p := progress{}
	for {
		c.SetDeadline(time.Now().Add(timeout))
		if _, err = fmt.Fprintln(c, "PING"); err == nil {
			var line string
			line, err = r.ReadString('\n')
			if err == nil {
				fields := strings.Fields(line)
				if len(fields) != 2 || fields[0] != "PONG" {
					err = fmt.Errorf("invalid reply")
				} else if p.Connection != "" && p.Connection != fields[1] {
					err = fmt.Errorf("connection changed")
				} else {
					p.Connection = fields[1]
					p.Requests++
				}
			}
		}
		if err != nil {
			p.Error = "persistent TCP session failed"
			if mode == "hold" {
				_ = writeProgress(state, p)
			}
			return fmt.Errorf("persistent TCP session failed")
		}
		if mode == "request" {
			fmt.Println("PASS")
			return nil
		}
		if err := writeProgress(state, p); err != nil {
			return err
		}
		time.Sleep(100 * time.Millisecond)
	}
}
