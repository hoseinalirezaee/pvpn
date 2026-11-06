package host

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"pvpn/internal/render"
)

// fakeRunner answers commands by their joined text.
type fakeRunner struct {
	handlers []func(cmd string, stdin []byte) ([]byte, error, bool)
	calls    []string
}

func (f *fakeRunner) Run(ctx context.Context, stdin []byte, name string, args ...string) ([]byte, error) {
	cmd := strings.Join(append([]string{name}, args...), " ")
	f.calls = append(f.calls, cmd)
	if ctx.Err() != nil {
		return nil, ctx.Err()
	}
	for i := len(f.handlers) - 1; i >= 0; i-- {
		if out, err, ok := f.handlers[i](cmd, stdin); ok {
			return out, err
		}
	}
	return nil, &CmdError{Cmd: cmd, Code: 127, Stderr: "no handler"}
}

func (f *fakeRunner) on(prefix string, fn func(cmd string) ([]byte, error)) {
	f.handlers = append(f.handlers, func(cmd string, _ []byte) ([]byte, error, bool) {
		if strings.HasPrefix(cmd, prefix) {
			out, err := fn(cmd)
			return out, err, true
		}
		return nil, nil, false
	})
}

func (f *fakeRunner) called(prefix string) int {
	n := 0
	for _, c := range f.calls {
		if strings.HasPrefix(c, prefix) {
			n++
		}
	}
	return n
}

func fail(cmd string, code int, msg string) error {
	return &CmdError{Cmd: cmd, Code: code, Stderr: msg}
}

type fakeClock struct{ now time.Time }

func (c *fakeClock) Now() time.Time { return c.now }
func (c *fakeClock) Sleep(ctx context.Context, d time.Duration) error {
	c.now = c.now.Add(d)
	return ctx.Err()
}

func addrJSON(ip string, flags ...string) string {
	extra := ""
	for _, f := range flags {
		extra += fmt.Sprintf(`,"%s":true`, f)
	}
	return fmt.Sprintf(`[{"ifindex":2,"ifname":"eth0","addr_info":[{"family":"inet6","local":"fe80::1","prefixlen":64},{"family":"inet6","local":"%s","prefixlen":128,"scope":"global"%s}]}]`, ip, extra)
}

func newReal(t *testing.T, fr *fakeRunner) *Real {
	t.Helper()
	d := t.TempDir()
	r := &Real{
		Run: fr, Clock: &fakeClock{now: time.Unix(1000, 0)},
		NetplanDir: filepath.Join(d, "etc/netplan"), WGDir: filepath.Join(d, "etc/wireguard"), UnitDir: filepath.Join(d, "units"),
		BackupDir: filepath.Join(d, "backup"), ApplyTimeout: time.Second, PollEvery: 250 * time.Millisecond,
	}
	for _, p := range []string{r.NetplanDir, r.WGDir, r.UnitDir} {
		if err := os.MkdirAll(p, 0o755); err != nil {
			t.Fatal(err)
		}
	}
	return r
}

var src = netip.MustParseAddr("2a01:4f8:1c1b:a31:1:2:3:4")

func TestEnsureAddrSuccessAfterTentative(t *testing.T) {
	fr := &fakeRunner{}
	n := 0
	fr.on("ip -j -6 addr show", func(string) ([]byte, error) {
		n++
		if n < 3 { // twice tentative, then fine
			return []byte(addrJSON(src.String(), "tentative", "deprecated", "noprefixroute")), nil
		}
		return []byte(addrJSON(src.String(), "deprecated", "noprefixroute")), nil
	})
	r := newReal(t, fr)
	if err := r.EnsureAddr(context.Background(), "eth0", src, 10*time.Second); err != nil {
		t.Fatal(err)
	}
	if fr.called("ip -6 addr change") != 0 {
		t.Fatal("flags were already right; no change command expected")
	}
}

func TestEnsureAddrSetsFlags(t *testing.T) {
	fr := &fakeRunner{}
	changed := false
	fr.on("ip -j -6 addr show", func(string) ([]byte, error) {
		if changed {
			return []byte(addrJSON(src.String(), "deprecated", "noprefixroute")), nil
		}
		return []byte(addrJSON(src.String())), nil
	})
	fr.on("ip -6 addr change", func(cmd string) ([]byte, error) {
		if cmd != "ip -6 addr change 2a01:4f8:1c1b:a31:1:2:3:4/128 dev eth0 noprefixroute preferred_lft 0" {
			t.Errorf("bad command: %s", cmd)
		}
		changed = true
		return nil, nil
	})
	if err := newReal(t, fr).EnsureAddr(context.Background(), "eth0", src, 10*time.Second); err != nil {
		t.Fatal(err)
	}
	if fr.called("ip -6 addr change") != 1 {
		t.Fatal("expected one change command")
	}
}

func TestEnsureAddrDuplicateDetected(t *testing.T) {
	fr := &fakeRunner{}
	fr.on("ip -j -6 addr show", func(string) ([]byte, error) {
		return []byte(addrJSON(src.String(), "tentative", "dadfailed", "deprecated", "noprefixroute")), nil
	})
	err := newReal(t, fr).EnsureAddr(context.Background(), "eth0", src, 10*time.Second)
	if !errors.Is(err, ErrDADFailed) {
		t.Fatalf("want ErrDADFailed, got %v", err)
	}
}

func TestEnsureAddrMissingTimesOut(t *testing.T) {
	fr := &fakeRunner{}
	fr.on("ip -j -6 addr show", func(string) ([]byte, error) { return []byte(addrJSON("2001:db8::99")), nil })
	r := newReal(t, fr)
	start := r.Clock.Now()
	err := r.EnsureAddr(context.Background(), "eth0", src, 10*time.Second)
	if !errors.Is(err, ErrAddrMissing) {
		t.Fatalf("want ErrAddrMissing, got %v", err)
	}
	if el := r.Clock.Now().Sub(start); el < 10*time.Second || el > 11*time.Second {
		t.Fatalf("waited %v, want about 10s", el)
	}
}

func TestEnsureAddrTentativeTimesOut(t *testing.T) {
	fr := &fakeRunner{}
	fr.on("ip -j -6 addr show", func(string) ([]byte, error) {
		return []byte(addrJSON(src.String(), "tentative", "deprecated", "noprefixroute")), nil
	})
	err := newReal(t, fr).EnsureAddr(context.Background(), "eth0", src, 10*time.Second)
	if !errors.Is(err, ErrAddrTentative) {
		t.Fatalf("want ErrAddrTentative, got %v", err)
	}
}

func TestDelAddrToleratesGone(t *testing.T) {
	fr := &fakeRunner{}
	fr.on("ip -6 addr del", func(cmd string) ([]byte, error) { return nil, fail(cmd, 2, "Cannot assign requested address") })
	fr.on("ip -j -6 addr show", func(string) ([]byte, error) { return []byte(addrJSON("2001:db8::99")), nil })
	if err := newReal(t, fr).DelAddr(context.Background(), "eth0", src); err != nil {
		t.Fatalf("already gone must not fail: %v", err)
	}
	fr2 := &fakeRunner{}
	fr2.on("ip -6 addr del", func(cmd string) ([]byte, error) { return nil, fail(cmd, 2, "boom") })
	fr2.on("ip -j -6 addr show", func(string) ([]byte, error) { return []byte(addrJSON(src.String())), nil })
	if err := newReal(t, fr2).DelAddr(context.Background(), "eth0", src); err == nil {
		t.Fatal("a real failure must be reported")
	}
}

func member() render.Member {
	return render.Member{Iface: "pvpn-de1", Table: 5751, Mark: 0x5751, Priority: 101, Addrs: []netip.Addr{src}, From: src, Gateway: netip.MustParseAddr("fe80::1")}
}

func TestCheckResources(t *testing.T) {
	good := &fakeRunner{}
	good.on("ip -j -6 route show table 5751", func(string) ([]byte, error) {
		return []byte(`[{"dst":"default","gateway":"fe80::1","dev":"eth0","protocol":"static","prefsrc":"2a01:4f8:1c1b:a31:1:2:3:4","flags":["onlink"]}]`), nil
	})
	good.on("ip -j -6 rule show", func(string) ([]byte, error) {
		return []byte(`[{"priority":0,"src":"all","table":"local"},{"priority":101,"src":"all","fwmark":"0x5751","table":"5751"}]`), nil
	})
	if err := newReal(t, good).CheckResources(context.Background(), "eth0", member()); err != nil {
		t.Fatal(err)
	}
	// Wrong source in the route.
	badRoute := &fakeRunner{}
	badRoute.on("ip -j -6 route show table 5751", func(string) ([]byte, error) {
		return []byte(`[{"dst":"default","gateway":"fe80::1","dev":"eth0","prefsrc":"2001:db8::1"}]`), nil
	})
	badRoute.on("ip -j -6 rule show", func(string) ([]byte, error) { return []byte(`[]`), nil })
	if err := newReal(t, badRoute).CheckResources(context.Background(), "eth0", member()); err == nil || !strings.Contains(err.Error(), "no default route") {
		t.Fatalf("want route error, got %v", err)
	}
	// Route fine, rule missing.
	noRule := &fakeRunner{}
	noRule.on("ip -j -6 route show table 5751", func(string) ([]byte, error) {
		return []byte(`[{"dst":"default","gateway":"fe80::1","dev":"eth0","prefsrc":"2a01:4f8:1c1b:a31:1:2:3:4"}]`), nil
	})
	noRule.on("ip -j -6 rule show", func(string) ([]byte, error) {
		return []byte(`[{"priority":101,"src":"all","fwmark":"0x9999","table":"5751"}]`), nil
	})
	if err := newReal(t, noRule).CheckResources(context.Background(), "eth0", member()); err == nil || !strings.Contains(err.Error(), "no ip rule") {
		t.Fatalf("want rule error, got %v", err)
	}
}

func TestFindDevice(t *testing.T) {
	doc := []byte(`
network:
  version: 2
  ethernets:
    nic0:
      match: {macaddress: "aa:bb"}
      set-name: eth0
    eth1: {dhcp4: true}
  vlans:
    vlan5: {id: 5, link: eth1}
`)
	if d, err := findDevice(doc, "eth0"); err != nil || d != (DeviceRef{"ethernets", "nic0"}) {
		t.Fatalf("set-name match: %+v %v", d, err)
	}
	if d, err := findDevice(doc, "eth1"); err != nil || d.ID != "eth1" {
		t.Fatalf("id match: %+v %v", d, err)
	}
	if d, err := findDevice(doc, "vlan5"); err != nil || d.Section != "vlans" {
		t.Fatalf("vlan: %+v %v", d, err)
	}
	if _, err := findDevice(doc, "eth9"); err == nil || !strings.Contains(err.Error(), "no netplan definition") {
		t.Fatalf("missing device: %v", err)
	}
	nm := []byte("network:\n  version: 2\n  renderer: NetworkManager\n  ethernets:\n    eth0: {}\n")
	if _, err := findDevice(nm, "eth0"); err == nil || !strings.Contains(err.Error(), "needs networkd") {
		t.Fatalf("renderer check: %v", err)
	}
	perDev := []byte("network:\n  version: 2\n  ethernets:\n    eth0: {renderer: networkd}\n")
	if _, err := findDevice(perDev, "eth0"); err != nil {
		t.Fatalf("networkd renderer must pass: %v", err)
	}
}

func TestParseWGDump(t *testing.T) {
	dump := "PRIV\tOWNPUB\t51111\t0x5751\nPEERPUB\t(none)\t[2001:db8::1]:51820\t0.0.0.0/0,::/0\t1700000000\t1234\t5678\t25\n"
	st, err := parseWGDump(dump)
	if err != nil || !st.Exists || st.PublicKey != "OWNPUB" || st.ListenPort != 51111 || st.FwMark != 0x5751 ||
		st.PeerKey != "PEERPUB" || st.Endpoint != "[2001:db8::1]:51820" || st.Handshake.Unix() != 1700000000 || st.RxBytes != 1234 || st.TxBytes != 5678 {
		t.Fatalf("status: %+v %v", st, err)
	}
	st, _ = parseWGDump("PRIV\tPUB\t0\toff\nP\t(none)\t(none)\t0.0.0.0/0\t0\t0\t0\toff\n")
	if !st.Handshake.IsZero() || st.FwMark != 0 {
		t.Fatalf("no handshake: %+v", st)
	}
	if _, err := parseWGDump("junk"); err == nil {
		t.Fatal("junk must fail")
	}
}

func TestWGStatusMissingInterface(t *testing.T) {
	fr := &fakeRunner{}
	fr.on("wg show", func(cmd string) ([]byte, error) {
		return nil, fail(cmd, 1, "Unable to access interface: No such device")
	})
	st, err := newReal(t, fr).WGStatus(context.Background(), "nope")
	if err != nil || st.Exists {
		t.Fatalf("%+v %v", st, err)
	}
}

func TestWGSetKeyUsesStdinAndRedacts(t *testing.T) {
	fr := &fakeRunner{}
	var gotStdin []byte
	fr.handlers = append(fr.handlers, func(cmd string, stdin []byte) ([]byte, error, bool) {
		if strings.HasPrefix(cmd, "wg set") {
			gotStdin = stdin
			return nil, fail(cmd, 1, "bad key SECRETKEY here"), true
		}
		return nil, nil, false
	})
	err := newReal(t, fr).WGSetKey(context.Background(), "pvpn-de1", "SECRETKEY", 51999)
	if err == nil || strings.Contains(err.Error(), "SECRETKEY") {
		t.Fatalf("error must hide the key: %v", err)
	}
	if string(gotStdin) != "SECRETKEY\n" {
		t.Fatalf("stdin: %q", gotStdin)
	}
	if fr.calls[0] != "wg set pvpn-de1 listen-port 51999 private-key /dev/stdin" {
		t.Fatalf("command: %s", fr.calls[0])
	}
}

func TestUnitStates(t *testing.T) {
	fr := &fakeRunner{}
	fr.on("systemctl is-active", func(cmd string) ([]byte, error) {
		if strings.Contains(cmd, "up") {
			return nil, nil
		}
		return nil, fail(cmd, 3, "")
	})
	fr.on("systemctl is-enabled", func(cmd string) ([]byte, error) { return nil, fail(cmd, 1, "") })
	r := newReal(t, fr)
	if a, err := r.UnitActive(context.Background(), "up"); !a || err != nil {
		t.Fatalf("active: %v %v", a, err)
	}
	if a, err := r.UnitActive(context.Background(), "down"); a || err != nil {
		t.Fatalf("inactive: %v %v", a, err)
	}
	if e, err := r.UnitEnabled(context.Background(), "x"); e || err != nil {
		t.Fatalf("disabled: %v %v", e, err)
	}
}

func TestDropInRoundTrip(t *testing.T) {
	fr := &fakeRunner{}
	fr.on("systemctl daemon-reload", func(string) ([]byte, error) { return nil, nil })
	r := newReal(t, fr)
	if r.HasDropIn("a") {
		t.Fatal("no drop-in yet")
	}
	if err := r.WriteDropIn(context.Background(), "a"); err != nil {
		t.Fatal(err)
	}
	if !r.HasDropIn("a") || fr.called("systemctl daemon-reload") != 1 {
		t.Fatal("drop-in not written or no daemon-reload")
	}
	// Do not remove a drop-in that pvpn does not own.
	p := r.dropInPath("b")
	_ = os.MkdirAll(filepath.Dir(p), 0o755)
	_ = os.WriteFile(p, []byte("[Unit]\nAfter=x\n"), 0o644)
	if err := r.RemoveDropIn(context.Background(), "b"); err == nil {
		t.Fatal("must refuse to remove a foreign drop-in")
	}
	if err := r.RemoveDropIn(context.Background(), "a"); err != nil || r.HasDropIn("a") {
		t.Fatalf("remove: %v", err)
	}
	if _, err := os.Stat(filepath.Dir(r.dropInPath("a"))); err == nil {
		t.Fatal("empty drop-in directory should be removed")
	}
}

func TestWGFiles(t *testing.T) {
	r := newReal(t, &fakeRunner{})
	if err := r.WriteWG("pvpn-de1", "hello"); err != nil {
		t.Fatal(err)
	}
	fi, _ := os.Stat(filepath.Join(r.WGDir, "pvpn-de1.conf"))
	if fi.Mode().Perm() != 0o600 {
		t.Fatalf("mode %o", fi.Mode().Perm())
	}
	_ = os.WriteFile(filepath.Join(r.WGDir, "other.conf"), nil, 0o600)
	_ = os.WriteFile(filepath.Join(r.WGDir, "private.key"), nil, 0o600)
	names, _ := r.ListWG()
	if strings.Join(names, ",") != "other,pvpn-de1" {
		t.Fatalf("list: %v", names)
	}
	if err := r.RemoveWG("pvpn-de1"); err != nil {
		t.Fatal(err)
	}
	if err := r.RemoveWG("pvpn-de1"); err != nil {
		t.Fatalf("second remove: %v", err)
	}
	if _, err := r.ReadWG("pvpn-de1"); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("read: %v", err)
	}
}

func TestProbeSetupAndCleanup(t *testing.T) {
	fr := &fakeRunner{}
	fr.on("ip -4", func(string) ([]byte, error) { return nil, nil })
	r := newReal(t, fr)
	r.ProbeTargets = nil // no targets: the probe fails after setup, and must clean up
	_, err := r.Probe(context.Background(), "pvpn-de1", 5751, 101)
	if err == nil {
		t.Fatal("no targets must fail")
	}
	want := []string{
		"ip -4 route add default dev pvpn-de1 table 5751",
		"ip -4 rule add priority 101 oif pvpn-de1 lookup 5751",
	}
	var added []string
	for _, c := range fr.calls {
		if strings.Contains(c, " add ") {
			added = append(added, c)
		}
	}
	if strings.Join(added, "|") != strings.Join(want, "|") {
		t.Fatalf("setup commands: %v", added)
	}
	last := fr.calls[len(fr.calls)-1]
	if last != "ip -4 route flush table 5751" || fr.called("ip -4 rule del priority 101 oif pvpn-de1 lookup 5751") == 0 {
		t.Fatalf("cleanup missing: %v", fr.calls)
	}
}

func TestWarmSourcesSendsThreeRoundsToEveryPair(t *testing.T) {
	pc, err := net.ListenPacket("udp6", "[::1]:51820")
	if err != nil {
		t.Skipf("cannot listen on [::1]:51820: %v", err)
	}
	defer pc.Close()
	r := newReal(t, &fakeRunner{})
	lo := netip.MustParseAddr("::1")
	if err := r.WarmSources(context.Background(), []WarmPair{{lo, lo}, {lo, lo}}); err != nil {
		t.Fatal(err)
	}
	got := 0
	buf := make([]byte, 16)
	for {
		_ = pc.SetReadDeadline(time.Now().Add(200 * time.Millisecond))
		if _, _, err := pc.ReadFrom(buf); err != nil {
			break
		}
		got++
	}
	if got != 6 { // 2 pairs x 3 rounds
		t.Fatalf("packets: %d, want 6", got)
	}
	// An empty list is not an error and sends nothing.
	if err := r.WarmSources(context.Background(), nil); err != nil {
		t.Fatal(err)
	}
}

func TestWGSetPeerEndpointCommand(t *testing.T) {
	fr := &fakeRunner{}
	fr.on("wg set", func(string) ([]byte, error) { return nil, nil })
	r := newReal(t, fr)
	ep := netip.AddrPortFrom(netip.MustParseAddr("2001:db8::1"), 51820)
	if err := r.WGSetPeerEndpoint(context.Background(), "pvpn-de1", "PEERKEY=", ep); err != nil {
		t.Fatal(err)
	}
	if len(fr.calls) != 1 || fr.calls[0] != "wg set pvpn-de1 peer PEERKEY= endpoint [2001:db8::1]:51820" {
		t.Errorf("calls: %q", fr.calls)
	}
}
