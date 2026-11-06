// A synthetic TCP boundary canary. This is NOT a browser or an untrusted-site runner.
package main

import (
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"strconv"
	"time"
)

type outcome struct {
	GuestFixture string `json:"guest_fixture"`
	HostGateway  string `json:"host_gateway"`
	OffGuest     string `json:"off_guest"`
}

func fixture() error {
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		return err
	}
	defer l.Close()
	server := &http.Server{Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet || r.URL.Path != "/fixture" {
			http.Error(w, "refused", http.StatusForbidden)
			return
		}
		w.Header().Set("Content-Type", "text/plain")
		_, _ = io.WriteString(w, "LDW_SYNTHETIC_LOCAL_FIXTURE")
	})}
	go func() { _ = server.Serve(l) }()
	defer server.Close()
	client := &http.Client{Timeout: 2 * time.Second, Transport: &http.Transport{Proxy: nil}}
	res, err := client.Get("http://" + l.Addr().String() + "/fixture")
	if err != nil {
		return err
	}
	defer res.Body.Close()
	data, err := io.ReadAll(io.LimitReader(res.Body, 64))
	if err != nil || res.StatusCode != http.StatusOK || string(data) != "LDW_SYNTHETIC_LOCAL_FIXTURE" {
		return fmt.Errorf("invalid local fixture")
	}
	return nil
}

func unreachable(addr string) bool {
	conn, err := net.DialTimeout("tcp", addr, 1300*time.Millisecond)
	if err != nil {
		return true
	}
	_ = conn.Close()
	return false
}

func main() {
	if len(os.Args) == 2 && os.Args[1] == "--local-fixture-only" {
		if err := fixture(); err != nil {
			os.Exit(2)
		}
		fmt.Println("LDW_LOCAL_FIXTURE=PASS")
		return
	}
	if len(os.Args) != 4 || os.Args[1] != "--probe" {
		os.Exit(2)
	}
	ip := net.ParseIP(os.Args[2])
	port, err := strconv.Atoi(os.Args[3])
	if ip == nil || ip.To4() == nil || ip.IsLoopback() || ip.IsUnspecified() ||
		ip.IsMulticast() || err != nil || port < 1 || port > 65535 {
		os.Exit(2)
	}
	result := outcome{GuestFixture: "FAIL", HostGateway: "FAIL", OffGuest: "FAIL"}
	if fixture() == nil {
		result.GuestFixture = "PASS"
	}
	// Host-gateway port is a short-lived synthetic listener on Docker's bridge
	// interface, NOT a credential-bearing service or a production endpoint.
	if unreachable(net.JoinHostPort(ip.String(), strconv.Itoa(port))) {
		result.HostGateway = "BLOCKED"
	}
	// TEST-NET address outside the guest, not a real external provider endpoint.
	if unreachable("192.0.2.1:443") {
		result.OffGuest = "BLOCKED"
	}
	_ = json.NewEncoder(os.Stdout).Encode(result)
	if result.GuestFixture != "PASS" || result.HostGateway != "BLOCKED" || result.OffGuest != "BLOCKED" {
		os.Exit(1)
	}
}
