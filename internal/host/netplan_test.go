package host

import (
	"context"
	"errors"
	"fmt"
	"net/netip"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"pvpn/internal/render"
)

func devsOne() []render.Device {
	return []render.Device{{Section: "ethernets", ID: "eth0", Members: []render.Member{member()}}}
}

// networkdFor is what netplan 0.107+ renders for the members.
func networkdFor(devs []render.Device) string {
	var b strings.Builder
	b.WriteString("[Match]\nName=eth0\n\n[Network]\nDHCP=ipv4\n")
	for _, d := range devs {
		for _, m := range d.Members {
			fmt.Fprintf(&b, "\n[Route]\nDestination=::/0\nGateway=%s\nPreferredSource=%s\nGatewayOnLink=true\nTable=%d\n", m.Gateway, m.From, m.Table)
			fmt.Fprintf(&b, "\n[RoutingPolicyRule]\nTo=::/0\nTable=%d\nPriority=%d\nFirewallMark=%d\n", m.Table, m.Priority, m.Mark)
			for _, a := range m.Addrs {
				fmt.Fprintf(&b, "\n[Address]\nAddress=%s/128\nPreferredLifetime=0\n", a)
			}
		}
	}
	return b.String()
}

type npEnv struct {
	r         *Real
	fr        *fakeRunner
	rootsSeen []string
	applyErr  error
	genErr    error
	omit      bool // generate output omits the members
	devs      []render.Device
}

func newNP(t *testing.T) *npEnv {
	t.Helper()
	e := &npEnv{fr: &fakeRunner{}, devs: devsOne()}
	e.r = newReal(t, e.fr)
	_ = os.WriteFile(filepath.Join(e.r.NetplanDir, "50-cloud-init.yaml"), []byte("network:\n  version: 2\n"), 0o600)
	e.fr.on("netplan generate --root-dir ", func(cmd string) ([]byte, error) {
		root := strings.TrimPrefix(cmd, "netplan generate --root-dir ")
		e.rootsSeen = append(e.rootsSeen, root)
		if e.genErr != nil {
			return nil, e.genErr
		}
		dir := filepath.Join(root, "run/systemd/network")
		_ = os.MkdirAll(dir, 0o755)
		text := networkdFor(e.devs)
		if e.omit {
			text = networkdFor(nil)
		}
		// The managed file must reach the temp root only as the candidate.
		if _, err := os.Stat(filepath.Join(root, "etc/netplan/50-cloud-init.yaml")); err != nil {
			return nil, fail(cmd, 1, "temp root lacks the existing netplan file")
		}
		return nil, os.WriteFile(filepath.Join(dir, "10-netplan-eth0.network"), []byte(text), 0o644)
	})
	applies := 0
	e.fr.on("netplan apply", func(string) ([]byte, error) {
		applies++
		if applies == 1 { // only the first apply fails; the restore apply works
			return nil, e.applyErr
		}
		return nil, nil
	})
	return e
}

func (e *npEnv) managed() string {
	b, _ := e.r.NetplanManaged()
	return string(b)
}

func TestNetplanApplyInstalls(t *testing.T) {
	e := newNP(t)
	content := render.Netplan(e.devs)
	if err := e.r.NetplanApply(context.Background(), content, e.devs); err != nil {
		t.Fatal(err)
	}
	if e.managed() != string(content) {
		t.Fatal("managed file not installed")
	}
	fi, _ := os.Stat(filepath.Join(e.r.NetplanDir, ManagedName))
	if fi.Mode().Perm() != 0o600 {
		t.Fatalf("mode %o", fi.Mode().Perm())
	}
	if e.fr.called("netplan apply") != 1 || len(e.rootsSeen) != 1 {
		t.Fatalf("calls: %v", e.fr.calls)
	}
	if _, err := os.Stat(e.rootsSeen[0]); err == nil {
		t.Fatal("temp root was not removed")
	}
	// Order: validate before apply.
	if !strings.HasPrefix(e.fr.calls[0], "netplan generate") {
		t.Fatalf("validation must come first: %v", e.fr.calls)
	}
}

func TestNetplanApplyKeepsPreviousFile(t *testing.T) {
	e := newNP(t)
	old := []byte("# managed-by: pvpn\nnetwork:\n  version: 2\n")
	_ = os.WriteFile(filepath.Join(e.r.NetplanDir, ManagedName), old, 0o600)
	if err := e.r.NetplanApply(context.Background(), render.Netplan(e.devs), e.devs); err != nil {
		t.Fatal(err)
	}
	prev, err := os.ReadFile(filepath.Join(e.r.BackupDir, ManagedName+".prev"))
	if err != nil || string(prev) != string(old) {
		t.Fatalf("previous file not saved: %v", err)
	}
}

func TestNetplanApplyRejectedByGenerate(t *testing.T) {
	e := newNP(t)
	e.genErr = fail("netplan generate", 1, "Error in network definition: unknown key 'lifetim'")
	err := e.r.NetplanApply(context.Background(), render.Netplan(e.devs), e.devs)
	if err == nil || !strings.Contains(err.Error(), "rejected") {
		t.Fatalf("got %v", err)
	}
	if e.managed() != "" || e.fr.called("netplan apply") != 0 {
		t.Fatal("a rejected file must not be installed or applied")
	}
}

func TestNetplanApplyToleratesSystemdNoise(t *testing.T) {
	e := newNP(t)
	e.genErr = fail("netplan generate", 1, "Failed to send reload request: No such file or directory\nSystem has not been booted with systemd as init system (PID 1). Can't operate.\nFailed to connect to bus: Host is down\nCommand '['systemctl', 'daemon-reload', '--no-ask-password']' returned non-zero exit status 1.")
	// The generator still writes output: simulate that by clearing the error after writing.
	e.fr.handlers = append(e.fr.handlers, func(cmd string, _ []byte) ([]byte, error, bool) {
		if strings.HasPrefix(cmd, "netplan generate --root-dir ") {
			root := strings.TrimPrefix(cmd, "netplan generate --root-dir ")
			dir := filepath.Join(root, "run/systemd/network")
			_ = os.MkdirAll(dir, 0o755)
			_ = os.WriteFile(filepath.Join(dir, "10.network"), []byte(networkdFor(e.devs)), 0o644)
			return nil, e.genErr, true
		}
		return nil, nil, false
	})
	if err := e.r.NetplanApply(context.Background(), render.Netplan(e.devs), e.devs); err != nil {
		t.Fatalf("systemd-only noise must be tolerated: %v", err)
	}
}

func TestNetplanApplyDetectsMissingNetworkdEntries(t *testing.T) {
	e := newNP(t)
	e.omit = true
	err := e.r.NetplanApply(context.Background(), render.Netplan(e.devs), e.devs)
	if err == nil || !strings.Contains(err.Error(), "no networkd entry") {
		t.Fatalf("got %v", err)
	}
	if e.managed() != "" {
		t.Fatal("file installed despite failed validation")
	}
}

func TestNetplanApplyFailureRestoresOldFile(t *testing.T) {
	e := newNP(t)
	old := []byte("# managed-by: pvpn\nnetwork:\n  version: 2\n")
	_ = os.WriteFile(filepath.Join(e.r.NetplanDir, ManagedName), old, 0o600)
	e.applyErr = fail("netplan apply", 1, "networkd did not restart")
	err := e.r.NetplanApply(context.Background(), render.Netplan(e.devs), e.devs)
	if err == nil || !strings.Contains(err.Error(), "old file restored") {
		t.Fatalf("got %v", err)
	}
	if e.managed() != string(old) {
		t.Fatalf("old file not restored: %q", e.managed())
	}
	if e.fr.called("netplan apply") != 2 {
		t.Fatalf("expected a second apply to return to the old state: %v", e.fr.calls)
	}
}

func TestNetplanApplyTimeout(t *testing.T) {
	e := newNP(t)
	e.r.ApplyTimeout = 30 * time.Millisecond
	n := 0
	e.fr.handlers = append(e.fr.handlers, func(cmd string, _ []byte) ([]byte, error, bool) {
		if cmd != "netplan apply" {
			return nil, nil, false
		}
		n++
		if n == 1 { // the first apply hangs until the deadline
			return nil, errors.New("netplan: " + context.DeadlineExceeded.Error()), true
		}
		return nil, nil, true
	})
	err := e.r.NetplanApply(context.Background(), render.Netplan(e.devs), e.devs)
	if err == nil || !strings.Contains(err.Error(), "netplan apply failed") || e.managed() != "" {
		t.Fatalf("timeout must fail and restore: err=%v managed=%q", err, e.managed())
	}
}

func TestNetplanApplyRemovesFile(t *testing.T) {
	e := newNP(t)
	_ = os.WriteFile(filepath.Join(e.r.NetplanDir, ManagedName), []byte("x"), 0o600)
	e.devs = nil
	if err := e.r.NetplanApply(context.Background(), nil, nil); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(filepath.Join(e.r.NetplanDir, ManagedName)); err == nil {
		t.Fatal("managed file must be removed when there are no members")
	}
	if e.fr.called("netplan apply") != 1 {
		t.Fatal("apply must run after removal")
	}
}

func TestBuildRootExcludesManagedFile(t *testing.T) {
	e := newNP(t)
	_ = os.WriteFile(filepath.Join(e.r.NetplanDir, ManagedName), []byte("old"), 0o600)
	_ = os.WriteFile(filepath.Join(e.r.NetplanDir, "60-ipv6.yaml"), []byte("network:\n  version: 2\n"), 0o600)
	root, err := e.r.buildRoot(nil)
	if err != nil {
		t.Fatal(err)
	}
	defer os.RemoveAll(root)
	for name, want := range map[string]bool{"50-cloud-init.yaml": true, "60-ipv6.yaml": true, ManagedName: false} {
		_, err := os.Stat(filepath.Join(root, "etc/netplan", name))
		if (err == nil) != want {
			t.Errorf("%s present=%v want %v", name, err == nil, want)
		}
	}
	root2, _ := e.r.buildRoot([]byte("candidate"))
	defer os.RemoveAll(root2)
	b, _ := os.ReadFile(filepath.Join(root2, "etc/netplan", ManagedName))
	if string(b) != "candidate" {
		t.Fatalf("candidate not placed: %q", b)
	}
}

func TestCheckGeneratedMultipleMembers(t *testing.T) {
	m2 := member()
	m2.Iface, m2.Table, m2.Mark, m2.Priority = "pvpn-de2", 5752, 0x5752, 102
	m2.Addrs = []netip.Addr{netip.MustParseAddr("2001:db8::2"), netip.MustParseAddr("2001:db8::3")}
	m2.From = m2.Addrs[0]
	devs := []render.Device{{Section: "ethernets", ID: "eth0", Members: []render.Member{member(), m2}}}
	if err := checkGenerated(networkdFor(devs), devs); err != nil {
		t.Fatal(err)
	}
	// Missing PreferredLifetime=0 must fail.
	text := strings.ReplaceAll(networkdFor(devs), "PreferredLifetime=0", "PreferredLifetime=forever")
	if err := checkGenerated(text, devs); err == nil || !strings.Contains(err.Error(), "PreferredLifetime=0") {
		t.Fatalf("got %v", err)
	}
}

func TestUsedIDs(t *testing.T) {
	fr := &fakeRunner{}
	fr.on("ip -j -4 rule show", func(string) ([]byte, error) {
		return []byte(`[{"priority":0,"table":"local"},{"priority":100,"fwmark":"0xca6c","table":"51820"}]`), nil
	})
	fr.on("ip -j -6 rule show", func(string) ([]byte, error) {
		return []byte(`[{"priority":0,"table":"local"},{"priority":32766,"table":"main"}]`), nil
	})
	fr.on("ip -j -4 route show table all", func(string) ([]byte, error) {
		return []byte(`[{"dst":"10.0.0.0/8","table":"7000"},{"dst":"1.1.1.1","dev":"eth0"}]`), nil
	})
	fr.on("ip -j -6 route show table all", func(string) ([]byte, error) { return []byte(`[{"dst":"::1","table":"local"}]`), nil })
	fr.on("netplan get all --root-dir", func(string) ([]byte, error) {
		return []byte("network:\n  ethernets:\n    eth1:\n      routes:\n      - table: 8000\n        to: x\n      routing-policy:\n      - table: 8000\n        mark: 4242\n        priority: 555\n"), nil
	})
	fr.on("wg show all fwmark", func(string) ([]byte, error) { return []byte("warp\t0x1234\nother\toff\n"), nil })
	r := newReal(t, fr)
	_ = os.WriteFile(filepath.Join(r.WGDir, "warp.conf"), []byte("[Interface]\nFwMark = 0x9999\nTable = 9000\n"), 0o600)
	u, err := r.UsedIDs(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	for _, c := range []struct {
		set  map[int]bool
		v    int
		name string
	}{
		{u.Priorities, 100, "prio 100"}, {u.Priorities, 555, "prio 555"}, {u.Marks, 0xca6c, "mark ca6c"}, {u.Marks, 4242, "mark 4242"},
		{u.Marks, 0x9999, "wg file mark"}, {u.Marks, 0x1234, "live wg mark"}, {u.Tables, 51820, "table 51820"}, {u.Tables, 7000, "route table"},
		{u.Tables, 8000, "netplan table"}, {u.Tables, 9000, "wg file table"},
	} {
		if !c.set[c.v] {
			t.Errorf("%s not found", c.name)
		}
	}
}
