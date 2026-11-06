package host

import (
	"bufio"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math/rand/v2"
	"net"
	"net/http"
	"net/netip"
	"os"
	"strconv"
	"strings"
	"syscall"
	"time"
)

func jsonUnmarshal(b []byte, v any) error { return json.Unmarshal(b, v) }

// FreePort returns a random UDP port in the dynamic range that nothing uses now.
func (r *Real) FreePort(ctx context.Context) (int, error) {
	for i := 0; i < 50; i++ {
		p := 49152 + rand.IntN(65535-49152)
		pc, err := net.ListenPacket("udp", ":"+strconv.Itoa(p))
		if err == nil {
			pc.Close()
			return p, nil
		}
	}
	return 0, errors.New("no free UDP port found")
}

// WarmSource sends three small UDP packets from src to dst:51820. WireGuard drops them as invalid.
// The packets make the network learn the new source address before the first handshake.
func (r *Real) WarmSource(ctx context.Context, src, dst netip.Addr) error {
	return r.WarmSources(ctx, []WarmPair{{src, dst}})
}

// WarmSources warms several sources at once. It sends one packet for every pair, waits 300 ms,
// and repeats this three times. So the time does not grow with the number of pairs.
func (r *Real) WarmSources(ctx context.Context, pairs []WarmPair) error {
	var conns []net.Conn
	defer func() {
		for _, c := range conns {
			c.Close()
		}
	}()
	var first error
	for _, p := range pairs {
		d := net.Dialer{LocalAddr: &net.UDPAddr{IP: p.Src.AsSlice()}, Timeout: 2 * time.Second}
		c, err := d.DialContext(ctx, "udp6", net.JoinHostPort(p.Dst.String(), "51820"))
		if err != nil {
			if first == nil {
				first = err
			}
			continue
		}
		conns = append(conns, c)
	}
	for i := 0; i < 3 && len(conns) > 0; i++ {
		for _, c := range conns {
			if _, err := c.Write([]byte{0xff, byte(i)}); err != nil && first == nil {
				first = err
			}
		}
		if err := r.Clock.Sleep(ctx, 300*time.Millisecond); err != nil {
			return err
		}
	}
	return first
}

// Probe sends HTTPS requests that can leave only through the interface.
//
// A socket bound to the interface (SO_BINDTODEVICE) matches a temporary IPv4 rule
// "oif <iface> lookup <table>" that has one default route through the interface.
// Host traffic and other tunnels never match this rule, so another tunnel cannot pass the check.
// The IPv4 tables are separate from the IPv6 tables that the fwmark rule uses.
func (r *Real) Probe(ctx context.Context, iface string, table, prio int) (string, error) {
	if err := r.probeSetup(ctx, iface, table, prio); err != nil {
		_ = r.ProbeCleanup(context.WithoutCancel(ctx), iface, table, prio)
		return "", err
	}
	defer r.ProbeCleanup(context.WithoutCancel(ctx), iface, table, prio)

	dialer := &net.Dialer{
		Timeout: 8 * time.Second,
		Control: func(network, address string, c syscall.RawConn) error {
			var serr error
			if err := c.Control(func(fd uintptr) {
				serr = syscall.SetsockoptString(int(fd), syscall.SOL_SOCKET, syscall.SO_BINDTODEVICE, iface)
			}); err != nil {
				return err
			}
			return serr
		},
	}
	tr := &http.Transport{
		Proxy: nil,
		DialContext: func(ctx context.Context, network, addr string) (net.Conn, error) {
			return dialer.DialContext(ctx, "tcp4", addr)
		},
		DisableKeepAlives:   true,
		TLSHandshakeTimeout: 8 * time.Second,
	}
	defer tr.CloseIdleConnections()
	client := &http.Client{Transport: tr, Timeout: 10 * time.Second}

	var errs []string
	for _, target := range r.ProbeTargets {
		ip, err := traceIP(ctx, client, target)
		if err == nil {
			return ip, nil
		}
		errs = append(errs, err.Error())
		if ctx.Err() != nil {
			break
		}
	}
	msg := "traffic probe through " + iface + " failed: " + strings.Join(errs, "; ")
	if rp := strictRPFilter(iface); rp != "" {
		msg += " (" + rp + ")"
	}
	return "", errors.New(msg)
}

func traceIP(ctx context.Context, c *http.Client, url string) (string, error) {
	req, err := http.NewRequestWithContext(ctx, "GET", url, nil)
	if err != nil {
		return "", err
	}
	resp, err := c.Do(req)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()
	if resp.StatusCode != 200 {
		return "", fmt.Errorf("%s: http %d", url, resp.StatusCode)
	}
	sc := bufio.NewScanner(io.LimitReader(resp.Body, 64<<10))
	for sc.Scan() {
		if v, ok := strings.CutPrefix(sc.Text(), "ip="); ok && v != "" {
			return strings.TrimSpace(v), nil
		}
	}
	return "", fmt.Errorf("%s: no ip= line in answer", url)
}

func strictRPFilter(iface string) string {
	for _, n := range []string{"all", iface} {
		b, err := os.ReadFile("/proc/sys/net/ipv4/conf/" + n + "/rp_filter")
		if err == nil && strings.TrimSpace(string(b)) == "1" {
			return "net.ipv4.conf." + n + ".rp_filter=1 is strict and can drop tunnel replies; use 2"
		}
	}
	return ""
}

func (r *Real) probeSetup(ctx context.Context, iface string, table, prio int) error {
	t, p := strconv.Itoa(table), strconv.Itoa(prio)
	_ = r.ProbeCleanup(ctx, iface, table, prio) // remove leftovers of an earlier crash
	if _, err := r.Run.Run(ctx, nil, "ip", "-4", "route", "add", "default", "dev", iface, "table", t); err != nil {
		return fmt.Errorf("probe route: %w", err)
	}
	if _, err := r.Run.Run(ctx, nil, "ip", "-4", "rule", "add", "priority", p, "oif", iface, "lookup", t); err != nil {
		return fmt.Errorf("probe rule: %w", err)
	}
	return nil
}

// ProbeCleanup removes the temporary probe rule and route. It is safe to call at any time.
func (r *Real) ProbeCleanup(ctx context.Context, iface string, table, prio int) error {
	t, p := strconv.Itoa(table), strconv.Itoa(prio)
	var last error
	for i := 0; i < 5; i++ { // a crash may have left more than one copy
		if _, err := r.Run.Run(ctx, nil, "ip", "-4", "rule", "del", "priority", p, "oif", iface, "lookup", t); err != nil {
			last = err
			break
		}
	}
	_, _ = r.Run.Run(ctx, nil, "ip", "-4", "route", "flush", "table", t)
	// "No such file or directory" on the last delete means nothing is left. That is the goal.
	_ = last
	return nil
}
