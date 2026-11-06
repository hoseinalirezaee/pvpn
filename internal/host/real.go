package host

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/netip"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"pvpn/internal/render"
	"pvpn/internal/state"
)

// Fixed system paths. Only tests change them.
const (
	NetplanDir  = "/etc/netplan"
	ManagedName = "90-pvpn.yaml"
	WGDir       = "/etc/wireguard"
	UnitDir     = "/etc/systemd/system"
)

// Real is the System implementation for a Linux host.
type Real struct {
	Run          Runner
	Clock        Clock
	NetplanDir   string
	NetplanExtra []string // more directories netplan reads: /lib/netplan, /run/netplan
	WGDir        string
	UnitDir      string
	BackupDir    string
	ApplyTimeout time.Duration
	PollEvery    time.Duration
	// ProbeTargets are HTTPS URLs that print "ip=<address>" lines.
	ProbeTargets []string
}

// NewReal returns the production System. backupDir is under the state directory.
func NewReal(backupDir string) *Real {
	return &Real{
		Run: ExecRunner{}, Clock: RealClock{},
		NetplanDir: NetplanDir, NetplanExtra: []string{"/lib/netplan", "/run/netplan"},
		WGDir: WGDir, UnitDir: UnitDir, BackupDir: backupDir,
		ApplyTimeout: 90 * time.Second, PollEvery: 250 * time.Millisecond,
		ProbeTargets: []string{"https://1.1.1.1/cdn-cgi/trace", "https://1.0.0.1/cdn-cgi/trace"},
	}
}

func (r *Real) managedPath() string { return filepath.Join(r.NetplanDir, ManagedName) }

// ---- addresses, routes, rules ----

type jsonAddr struct {
	IfName   string `json:"ifname"`
	AddrInfo []struct {
		Family        string `json:"family"`
		Local         string `json:"local"`
		PrefixLen     int    `json:"prefixlen"`
		Tentative     bool   `json:"tentative"`
		DADFailed     bool   `json:"dadfailed"`
		Deprecated    bool   `json:"deprecated"`
		NoPrefixRoute bool   `json:"noprefixroute"`
	} `json:"addr_info"`
}

func (r *Real) ListAddrs(ctx context.Context, dev string) ([]AddrInfo, error) {
	out, err := r.Run.Run(ctx, nil, "ip", "-j", "-6", "addr", "show", "dev", dev)
	if err != nil {
		return nil, err
	}
	var list []jsonAddr
	if err := json.Unmarshal(out, &list); err != nil {
		return nil, fmt.Errorf("ip addr show: bad JSON: %w", err)
	}
	var res []AddrInfo
	for _, d := range list {
		for _, a := range d.AddrInfo {
			ip, err := netip.ParseAddr(a.Local)
			if err != nil || a.Family != "inet6" {
				continue
			}
			res = append(res, AddrInfo{ip, a.PrefixLen, a.Tentative, a.DADFailed, a.Deprecated, a.NoPrefixRoute})
		}
	}
	return res, nil
}

func findAddr(list []AddrInfo, ip netip.Addr) (AddrInfo, bool) {
	for _, a := range list {
		if a.Addr == ip {
			return a, true
		}
	}
	return AddrInfo{}, false
}

// EnsureAddr applies noprefixroute and preferred_lft 0, then polls the address.
// One bounded loop covers a slow networkd, DAD, and a duplicate.
func (r *Real) EnsureAddr(ctx context.Context, dev string, ip netip.Addr, wait time.Duration) error {
	deadline := r.Clock.Now().Add(wait)
	last := ErrAddrMissing
	for {
		list, err := r.ListAddrs(ctx, dev)
		if err != nil {
			return err
		}
		a, ok := findAddr(list, ip)
		switch {
		case !ok:
			last = ErrAddrMissing
		case a.DADFailed:
			return fmt.Errorf("%w: %s on %s", ErrDADFailed, ip, dev)
		default:
			if !a.NoPrefixRoute || !a.Deprecated {
				if _, err := r.Run.Run(ctx, nil, "ip", "-6", "addr", "change", ip.String()+"/128", "dev", dev, "noprefixroute", "preferred_lft", "0"); err != nil {
					return fmt.Errorf("set address flags: %w", err)
				}
				last = ErrAddrTentative
				break // read the flags again
			}
			if a.Tentative {
				last = ErrAddrTentative
				break
			}
			return nil
		}
		if !r.Clock.Now().Before(deadline) {
			return fmt.Errorf("%w: %s on %s after %s", last, ip, dev, wait)
		}
		if err := r.Clock.Sleep(ctx, r.PollEvery); err != nil {
			return err
		}
	}
}

func (r *Real) DelAddr(ctx context.Context, dev string, ip netip.Addr) error {
	_, err := r.Run.Run(ctx, nil, "ip", "-6", "addr", "del", ip.String()+"/128", "dev", dev)
	if err == nil {
		return nil
	}
	list, lerr := r.ListAddrs(ctx, dev)
	if lerr == nil {
		if _, ok := findAddr(list, ip); !ok {
			return nil // already gone
		}
	}
	return err
}

type jsonRoute struct {
	Dst     string `json:"dst"`
	Gateway string `json:"gateway"`
	Dev     string `json:"dev"`
	PrefSrc string `json:"prefsrc"`
	Table   string `json:"table"`
}

type jsonRule struct {
	Priority int    `json:"priority"`
	Src      string `json:"src"`
	Dst      string `json:"dst"`
	Fwmark   string `json:"fwmark"`
	Table    string `json:"table"`
	Oif      string `json:"oif"`
}

func parseMark(s string) (int, bool) {
	s = strings.TrimSpace(s)
	if s == "" || s == "off" {
		return 0, false
	}
	if i := strings.IndexByte(s, '/'); i >= 0 { // mark/mask
		s = s[:i]
	}
	v, err := strconv.ParseInt(s, 0, 64)
	if err != nil {
		return 0, false
	}
	return int(v), true
}

func (r *Real) rules(ctx context.Context, fam string) ([]jsonRule, error) {
	out, err := r.Run.Run(ctx, nil, "ip", "-j", fam, "rule", "show")
	if err != nil {
		return nil, err
	}
	var rs []jsonRule
	if err := json.Unmarshal(out, &rs); err != nil {
		return nil, fmt.Errorf("ip rule show: bad JSON: %w", err)
	}
	return rs, nil
}

// CheckResources checks that the route in the member table and the fwmark rule exist.
func (r *Real) CheckResources(ctx context.Context, dev string, m render.Member) error {
	out, err := r.Run.Run(ctx, nil, "ip", "-j", "-6", "route", "show", "table", strconv.Itoa(m.Table))
	if err != nil {
		return err
	}
	var routes []jsonRoute
	if err := json.Unmarshal(out, &routes); err != nil {
		return fmt.Errorf("ip route show: bad JSON: %w", err)
	}
	found := false
	for _, rt := range routes {
		if (rt.Dst == "default" || rt.Dst == "::/0") && rt.Dev == dev && rt.Gateway == m.Gateway.String() && rt.PrefSrc == m.From.String() {
			found = true
		}
	}
	if !found {
		return fmt.Errorf("table %d has no default route via %s dev %s src %s", m.Table, m.Gateway, dev, m.From)
	}
	rs, err := r.rules(ctx, "-6")
	if err != nil {
		return err
	}
	for _, ru := range rs {
		mark, ok := parseMark(ru.Fwmark)
		if ru.Priority == m.Priority && ok && mark == m.Mark && ru.Table == strconv.Itoa(m.Table) {
			return nil
		}
	}
	return fmt.Errorf("no ip rule: priority %d fwmark 0x%x lookup %d", m.Priority, m.Mark, m.Table)
}

// ---- files ----

func (r *Real) wgPath(name string) string { return filepath.Join(r.WGDir, name+".conf") }

func (r *Real) ReadWG(name string) (string, error) {
	b, err := os.ReadFile(r.wgPath(name))
	return string(b), err
}

func (r *Real) WriteWG(name, content string) error {
	return state.WriteFileAtomic(r.wgPath(name), []byte(content), 0o600)
}

func (r *Real) RemoveWG(name string) error {
	if err := os.Remove(r.wgPath(name)); err != nil && !errors.Is(err, os.ErrNotExist) {
		return err
	}
	return nil
}

func (r *Real) ListWG() ([]string, error) {
	ents, err := os.ReadDir(r.WGDir)
	if errors.Is(err, os.ErrNotExist) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	var names []string
	for _, e := range ents {
		if n, ok := strings.CutSuffix(e.Name(), ".conf"); ok && !e.IsDir() {
			names = append(names, n)
		}
	}
	return names, nil
}

// ---- systemd ----

func unit(iface string) string { return "wg-quick@" + iface + ".service" }

func (r *Real) LinkExists(ctx context.Context, name string) (bool, error) {
	_, err := r.Run.Run(ctx, nil, "ip", "link", "show", "dev", name)
	if err == nil {
		return true, nil
	}
	if exitCode(err) == 1 || exitCode(err) == 255 {
		return false, nil
	}
	return false, err
}

func (r *Real) UnitActive(ctx context.Context, iface string) (bool, error) {
	_, err := r.Run.Run(ctx, nil, "systemctl", "is-active", "--quiet", unit(iface))
	switch exitCode(err) {
	case 0:
		return true, nil
	case 3, 4: // inactive, unknown
		return false, nil
	}
	return false, err
}

func (r *Real) UnitEnabled(ctx context.Context, iface string) (bool, error) {
	_, err := r.Run.Run(ctx, nil, "systemctl", "is-enabled", "--quiet", unit(iface))
	switch exitCode(err) {
	case 0:
		return true, nil
	case 1: // disabled or not found
		return false, nil
	}
	return false, err
}

func (r *Real) UnitStart(ctx context.Context, iface string) error {
	_, err := r.Run.Run(ctx, nil, "systemctl", "start", unit(iface))
	return err
}

func (r *Real) UnitStop(ctx context.Context, iface string) error {
	_, err := r.Run.Run(ctx, nil, "systemctl", "stop", unit(iface))
	return err
}

func (r *Real) UnitEnable(ctx context.Context, iface string) error {
	_, err := r.Run.Run(ctx, nil, "systemctl", "enable", unit(iface))
	return err
}

func (r *Real) UnitDisable(ctx context.Context, iface string) error {
	_, err := r.Run.Run(ctx, nil, "systemctl", "disable", unit(iface))
	return err
}

func (r *Real) dropInPath(iface string) string {
	return filepath.Join(r.UnitDir, unit(iface)+".d", "pvpn.conf")
}

func (r *Real) HasDropIn(iface string) bool {
	b, err := os.ReadFile(r.dropInPath(iface))
	return err == nil && string(b) == render.DropIn()
}

func (r *Real) WriteDropIn(ctx context.Context, iface string) error {
	p := r.dropInPath(iface)
	if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
		return err
	}
	if err := state.WriteFileAtomic(p, []byte(render.DropIn()), 0o644); err != nil {
		return err
	}
	_, err := r.Run.Run(ctx, nil, "systemctl", "daemon-reload")
	return err
}

func (r *Real) RemoveDropIn(ctx context.Context, iface string) error {
	p := r.dropInPath(iface)
	if b, err := os.ReadFile(p); err == nil && !strings.HasPrefix(string(b), "# managed-by = pvpn") {
		return fmt.Errorf("%s is not managed by pvpn; not removed", p)
	}
	if err := os.Remove(p); err != nil && !errors.Is(err, os.ErrNotExist) {
		return err
	}
	_ = os.Remove(filepath.Dir(p)) // only succeeds when empty
	_, err := r.Run.Run(ctx, nil, "systemctl", "daemon-reload")
	return err
}

// ---- WireGuard ----

func (r *Real) WGStatus(ctx context.Context, iface string) (WGStatus, error) {
	out, err := r.Run.Run(ctx, nil, "wg", "show", iface, "dump")
	if err != nil {
		var ce *CmdError
		if errors.As(err, &ce) && (strings.Contains(ce.Stderr, "No such device") || strings.Contains(ce.Stderr, "Unable to access interface")) {
			return WGStatus{}, nil
		}
		return WGStatus{}, err
	}
	return parseWGDump(string(out))
}

// parseWGDump reads `wg show <if> dump`. Line 1: private-key public-key listen-port fwmark.
// Next lines (one per peer): public-key psk endpoint allowed-ips latest-handshake rx tx keepalive.
func parseWGDump(s string) (WGStatus, error) {
	lines := strings.Split(strings.TrimSpace(s), "\n")
	f := strings.Split(lines[0], "\t")
	if len(f) < 4 {
		return WGStatus{}, fmt.Errorf("wg dump: unexpected first line")
	}
	st := WGStatus{Exists: true, PublicKey: f[1]}
	st.ListenPort, _ = strconv.Atoi(f[2])
	st.FwMark, _ = parseMark(f[3])
	if len(lines) > 1 {
		p := strings.Split(lines[1], "\t")
		if len(p) >= 8 {
			st.PeerKey, st.Endpoint = p[0], p[2]
			if ts, _ := strconv.ParseInt(p[4], 10, 64); ts > 0 {
				st.Handshake = time.Unix(ts, 0)
			}
			st.RxBytes, _ = strconv.ParseInt(p[5], 10, 64)
			st.TxBytes, _ = strconv.ParseInt(p[6], 10, 64)
		}
	}
	return st, nil
}

// WGSetKey changes the private key and the listen port of a running interface.
// A new listen port makes WireGuard open a new UDP socket, so it uses the new source address.
func (r *Real) WGSetKey(ctx context.Context, iface, privateKey string, listenPort int) error {
	args := []string{"set", iface}
	if listenPort > 0 {
		args = append(args, "listen-port", strconv.Itoa(listenPort))
	}
	args = append(args, "private-key", "/dev/stdin")
	_, err := r.Run.Run(ctx, []byte(privateKey+"\n"), "wg", args...)
	if err != nil {
		return fmt.Errorf("wg set %s: %w", iface, errors.New(redactKey(err.Error(), privateKey)))
	}
	return nil
}

// WGSetListenPort opens a new UDP socket on another port. WireGuard then picks the source address again.
func (r *Real) WGSetListenPort(ctx context.Context, iface string, port int) error {
	_, err := r.Run.Run(ctx, nil, "wg", "set", iface, "listen-port", strconv.Itoa(port))
	return err
}

func redactKey(s, key string) string {
	if key == "" {
		return s
	}
	return strings.ReplaceAll(s, key, "<key>")
}
