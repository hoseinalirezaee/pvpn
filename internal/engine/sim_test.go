package engine

import (
	"context"
	"encoding/base64"
	"errors"
	"fmt"
	"net/netip"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"testing"
	"time"

	"pvpn/internal/alloc"
	"pvpn/internal/config"
	"pvpn/internal/host"
	"pvpn/internal/proton"
	"pvpn/internal/render"
	"pvpn/internal/state"
)

var rePreUp = regexp.MustCompile(`PreUp = ip -6 addr change (\S+)/128`)

// crashSignal is the panic value that models a process death.
type crashSignal struct{ at string }

type simClock struct{ now time.Time }

func (c *simClock) Now() time.Time { return c.now }
func (c *simClock) Sleep(ctx context.Context, d time.Duration) error {
	c.now = c.now.Add(d)
	return ctx.Err()
}

type simCert struct {
	Serial, DeviceName, WGPub string
	Label, Peer               string
	Expires                   int64
}

type simAddr struct {
	dev           string
	tentativeTill time.Time
	noPrefixRoute bool
	deprecated    bool
	fromNetplan   bool
}

type simLink struct {
	priv, pub string
	port      int
	handshake time.Time
	needHS    bool
	attempts  int
	keyTime   time.Time
	endpoint  string
}

type simUnit struct{ active, enabled bool }

// sim is a fake host and a fake Proton API. It keeps its state across engine "restarts".
type sim struct {
	t     *testing.T
	clock *simClock

	// API
	logicals []proton.Logical
	maxTier  int
	certs    map[string]*simCert
	certSeq  int
	edToWG   map[string]string
	certTTL  time.Duration

	// host
	managed  []byte
	addrs    map[netip.Addr]*simAddr
	routes   map[int]netip.Addr // table -> prefsrc
	rules    map[int][2]int     // priority -> {mark, table}
	wg       map[string]string  // /etc/wireguard files
	units    map[string]*simUnit
	dropins  map[string]bool
	links    map[string]*simLink
	netlinks map[string]bool // other links, for name conflicts
	ports    int

	// fault injection
	steps      int
	crashAt    int
	failures   map[string]int
	failErr    map[string]error
	dadFail    map[netip.Addr]bool
	dadFn      func(netip.Addr) bool
	extraUsed  *alloc.Used
	stickyAddr bool                                 // netplan does not remove addresses; only DelAddr does
	hsPolicy   func(iface string, attempt int) bool // does a handshake come?
	probeFail  map[string]error                     // per interface
	slowTentat time.Duration                        // how long a new address stays tentative

	calls []string
}

func newSim(t *testing.T) *sim {
	s := &sim{
		t: t, clock: &simClock{now: time.Date(2026, 6, 1, 12, 0, 0, 0, time.UTC)}, maxTier: 2,
		certs: map[string]*simCert{}, edToWG: map[string]string{}, certTTL: 365 * 24 * time.Hour,
		addrs: map[netip.Addr]*simAddr{}, routes: map[int]netip.Addr{}, rules: map[int][2]int{},
		wg: map[string]string{}, units: map[string]*simUnit{}, dropins: map[string]bool{}, links: map[string]*simLink{},
		netlinks: map[string]bool{"lo": true, "eth0": true}, failures: map[string]int{}, failErr: map[string]error{},
		dadFail: map[netip.Addr]bool{}, probeFail: map[string]error{}, ports: 50000, slowTentat: 2 * time.Second,
	}
	s.addrs[netip.MustParseAddr("2a01:4f8:1c1b:a31::1")] = &simAddr{dev: "eth0"}
	return s
}

// ---- fault injection ----

func (s *sim) tick(name string) {
	s.steps++
	if s.crashAt > 0 && s.steps == s.crashAt {
		panic(crashSignal{name})
	}
}

// mut wraps a mutating call: a crash can come just before or just after the effect.
func (s *sim) mut(name string, fn func() error) error {
	s.calls = append(s.calls, name)
	s.tick(name + ":before")
	if n := s.failures[name]; n > 0 {
		s.failures[name]--
		if err := s.failErr[name]; err != nil {
			return err
		}
		return fmt.Errorf("injected failure of %s", name)
	}
	err := fn()
	s.tick(name + ":after")
	return err
}

func (s *sim) count(prefix string) int {
	n := 0
	for _, c := range s.calls {
		if strings.HasPrefix(c, prefix) {
			n++
		}
	}
	return n
}

func (s *sim) index(prefix string) int {
	for i, c := range s.calls {
		if strings.HasPrefix(c, prefix) {
			return i
		}
	}
	return -1
}

func (s *sim) lastIndex(prefix string) int {
	for i := len(s.calls) - 1; i >= 0; i-- {
		if strings.HasPrefix(s.calls[i], prefix) {
			return i
		}
	}
	return -1
}

var mutating = []string{"CreateCert", "DeleteCert", "NetplanApply", "EnsureAddr", "DelAddr", "WGSetKey", "WGSetListenPort",
	"WriteWG", "RemoveWG", "UnitStart", "UnitStop", "UnitEnable", "UnitDisable", "WriteDropIn", "RemoveDropIn"}

func (s *sim) mutations() int {
	n := 0
	for _, m := range mutating {
		n += s.count(m)
	}
	return n
}

// ---- API ----

func (s *sim) newCred() (*proton.Credential, error) {
	c, err := proton.NewCredential()
	if err != nil {
		return nil, err
	}
	s.edToWG[string(c.EdPublic)] = c.WGPublic
	return c, nil
}

func (s *sim) Info(ctx context.Context) (proton.VPNInfo, error) {
	if err := s.failErr["Info"]; err != nil {
		return proton.VPNInfo{}, err
	}
	return proton.VPNInfo{PlanName: "vpn2024", MaxTier: s.maxTier, MaxConnect: 11, Status: 1}, nil
}

func (s *sim) Logicals(ctx context.Context) ([]proton.Logical, error) {
	if err := s.failErr["Logicals"]; err != nil {
		return nil, err
	}
	out := make([]proton.Logical, len(s.logicals))
	copy(out, s.logicals)
	for i := range out {
		out[i].Servers = append([]proton.Physical(nil), s.logicals[i].Servers...)
	}
	return out, nil
}

func (s *sim) CreateCert(ctx context.Context, rq proton.CertRequest) (*proton.Cert, error) {
	var cert *proton.Cert
	err := s.mut("CreateCert", func() error {
		s.certSeq++
		serial := fmt.Sprintf("SN%03d", s.certSeq)
		wgPub := s.edToWG[string(rq.EdPubKey)]
		exp := s.clock.Now().Add(s.certTTL).Unix()
		s.certs[serial] = &simCert{Serial: serial, DeviceName: rq.DeviceName, WGPub: wgPub, Label: rq.Label, Peer: rq.PeerName, Expires: exp}
		cert = &proton.Cert{Serial: serial, Expiration: exp, Refresh: exp - 90*24*3600}
		return nil
	})
	return cert, err
}

func (s *sim) DeleteCert(ctx context.Context, serial string) error {
	return s.mut("DeleteCert", func() error {
		delete(s.certs, serial)
		return nil
	})
}

func (s *sim) ListCerts(ctx context.Context) ([]proton.CertInfo, error) {
	if s.failures["ListCerts"] > 0 {
		s.failures["ListCerts"]--
		return nil, errors.New("injected failure of ListCerts")
	}
	var out []proton.CertInfo
	for _, c := range s.certs {
		out = append(out, proton.CertInfo{Serial: c.Serial, DeviceName: c.DeviceName, Mode: "persistent", Expiration: c.Expires})
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Serial < out[j].Serial })
	return out, nil
}

// ---- host: netplan ----

func (s *sim) NetplanDevice(ctx context.Context, dev string) (host.DeviceRef, error) {
	if dev != "eth0" {
		return host.DeviceRef{}, fmt.Errorf("device %q has no netplan definition", dev)
	}
	return host.DeviceRef{Section: "ethernets", ID: "eth0"}, nil
}

func (s *sim) NetplanManaged() ([]byte, error) { return s.managed, nil }

func (s *sim) NetplanApply(ctx context.Context, content []byte, devs []render.Device) error {
	return s.mut("NetplanApply", func() error {
		s.managed = content
		want := map[netip.Addr]bool{}
		routes := map[int]netip.Addr{}
		rules := map[int][2]int{}
		for _, d := range devs {
			for _, m := range d.Members {
				for _, a := range m.Addrs {
					want[a] = true
				}
				routes[m.Table] = m.From
				rules[m.Priority] = [2]int{m.Mark, m.Table}
			}
		}
		for a := range want {
			if x, ok := s.addrs[a]; ok {
				x.noPrefixRoute = false // networkd writes the address again and drops noprefixroute
			}
			if _, ok := s.addrs[a]; !ok {
				s.addrs[a] = &simAddr{dev: "eth0", tentativeTill: s.clock.Now().Add(s.slowTentat), fromNetplan: true}
			}
		}
		if !s.stickyAddr {
			for a, x := range s.addrs {
				if x.fromNetplan && !want[a] {
					delete(s.addrs, a)
				}
			}
		}
		s.routes, s.rules = routes, rules
		return nil
	})
}

func (s *sim) UsedIDs(ctx context.Context) (*alloc.Used, error) {
	u := alloc.NewUsed()
	u.Priorities[0], u.Priorities[32766], u.Priorities[32767] = true, true, true
	u.Merge(s.extraUsed)
	return u, nil
}

func (s *sim) ListAddrs(ctx context.Context, dev string) ([]host.AddrInfo, error) {
	var out []host.AddrInfo
	for a, x := range s.addrs {
		if x.dev != dev {
			continue
		}
		out = append(out, host.AddrInfo{Addr: a, PrefixLen: 128, Tentative: x.tentativeTill.After(s.clock.Now()), DADFailed: s.dadFail[a],
			Deprecated: x.deprecated, NoPrefixRoute: x.noPrefixRoute})
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Addr.Less(out[j].Addr) })
	return out, nil
}

func (s *sim) EnsureAddr(ctx context.Context, dev string, ip netip.Addr, wait time.Duration) error {
	s.calls = append(s.calls, "EnsureAddr")
	s.tick("EnsureAddr:before")
	deadline := s.clock.Now().Add(wait)
	for {
		x, ok := s.addrs[ip]
		switch {
		case !ok:
		case s.dadFail[ip] || (s.dadFn != nil && s.dadFn(ip)):
			return fmt.Errorf("%w: %s", host.ErrDADFailed, ip)
		default:
			x.noPrefixRoute, x.deprecated = true, true
			if !x.tentativeTill.After(s.clock.Now()) {
				return nil
			}
		}
		if !s.clock.Now().Before(deadline) {
			if !ok {
				return fmt.Errorf("%w: %s", host.ErrAddrMissing, ip)
			}
			return fmt.Errorf("%w: %s", host.ErrAddrTentative, ip)
		}
		_ = s.clock.Sleep(ctx, 250*time.Millisecond)
	}
}

func (s *sim) DelAddr(ctx context.Context, dev string, ip netip.Addr) error {
	return s.mut("DelAddr", func() error {
		if x, ok := s.addrs[ip]; ok && x.dev == dev {
			delete(s.addrs, ip)
		}
		return nil
	})
}

func (s *sim) CheckResources(ctx context.Context, dev string, m render.Member) error {
	if src, ok := s.routes[m.Table]; !ok || src != m.From {
		return fmt.Errorf("table %d has no route via %s src %s", m.Table, m.Gateway, m.From)
	}
	if r, ok := s.rules[m.Priority]; !ok || r != [2]int{m.Mark, m.Table} {
		return fmt.Errorf("no rule for priority %d", m.Priority)
	}
	return nil
}

// ---- host: WireGuard ----

func (s *sim) WGStatus(ctx context.Context, iface string) (host.WGStatus, error) {
	l, ok := s.links[iface]
	if !ok {
		return host.WGStatus{}, nil
	}
	if l.needHS && (s.hsPolicy == nil || s.hsPolicy(iface, l.attempts)) {
		l.handshake, l.needHS = s.clock.Now(), false
	}
	return host.WGStatus{Exists: true, PublicKey: l.pub, ListenPort: l.port, Handshake: l.handshake, Endpoint: l.endpoint}, nil
}

func (s *sim) WGSetKey(ctx context.Context, iface, privateKey string, listenPort int) error {
	return s.mut("WGSetKey", func() error {
		l, ok := s.links[iface]
		if !ok {
			return host.ErrLinkMissing
		}
		pub, err := proton.PublicFromPrivate(privateKey)
		if err != nil {
			return err
		}
		l.priv, l.pub, l.port = privateKey, pub, listenPort
		l.needHS, l.attempts, l.handshake, l.keyTime = true, 0, time.Time{}, s.clock.Now()
		return nil
	})
}

func (s *sim) WGSetListenPort(ctx context.Context, iface string, port int) error {
	return s.mut("WGSetListenPort", func() error {
		l, ok := s.links[iface]
		if !ok {
			return host.ErrLinkMissing
		}
		l.port, l.needHS = port, true
		l.attempts++
		return nil
	})
}

func (s *sim) WarmSource(ctx context.Context, src, dst netip.Addr) error {
	s.calls = append(s.calls, "WarmSource")
	return nil
}

func (s *sim) WarmSources(ctx context.Context, pairs []host.WarmPair) error {
	s.calls = append(s.calls, "WarmSources")
	return nil
}

func (s *sim) FreePort(ctx context.Context) (int, error) {
	s.ports++
	return s.ports, nil
}

// Probe succeeds only if this interface has a fresh handshake and its key belongs to a live certificate.
// Another healthy interface cannot satisfy it.
func (s *sim) Probe(ctx context.Context, iface string, table, prio int) (string, error) {
	s.calls = append(s.calls, "Probe:"+iface)
	if err := s.probeFail[iface]; err != nil {
		return "", err
	}
	l, ok := s.links[iface]
	if !ok || l.handshake.IsZero() {
		return "", fmt.Errorf("probe through %s: no route", iface)
	}
	for _, c := range s.certs {
		if c.WGPub == l.pub {
			return "198.51.100.7", nil
		}
	}
	return "", fmt.Errorf("probe through %s: server drops traffic (no live certificate for this key)", iface)
}

func (s *sim) ProbeCleanup(ctx context.Context, iface string, table, prio int) error {
	s.calls = append(s.calls, "ProbeCleanup")
	return nil
}

// ---- host: files and units ----

func (s *sim) ReadWG(name string) (string, error) {
	t, ok := s.wg[name]
	if !ok {
		return "", os.ErrNotExist
	}
	return t, nil
}

func (s *sim) WriteWG(name, content string) error {
	return s.mut("WriteWG", func() error { s.wg[name] = content; return nil })
}

func (s *sim) RemoveWG(name string) error {
	return s.mut("RemoveWG", func() error { delete(s.wg, name); return nil })
}

func (s *sim) ListWG() ([]string, error) {
	var out []string
	for n := range s.wg {
		out = append(out, n)
	}
	sort.Strings(out)
	return out, nil
}

func (s *sim) LinkExists(ctx context.Context, name string) (bool, error) {
	_, ok := s.links[name]
	return ok || s.netlinks[name], nil
}

func (s *sim) unit(i string) *simUnit {
	u := s.units[i]
	if u == nil {
		u = &simUnit{}
		s.units[i] = u
	}
	return u
}

func (s *sim) UnitActive(ctx context.Context, iface string) (bool, error) {
	return s.unit(iface).active, nil
}
func (s *sim) UnitEnabled(ctx context.Context, iface string) (bool, error) {
	return s.unit(iface).enabled, nil
}

func (s *sim) UnitStart(ctx context.Context, iface string) error {
	return s.mut("UnitStart", func() error {
		conf, ok := s.wg[iface]
		if !ok {
			return fmt.Errorf("wg-quick: /etc/wireguard/%s.conf does not exist", iface)
		}
		meta := render.ParseWG(conf)
		pub, err := proton.PublicFromPrivate(meta.PrivateKey)
		if err != nil {
			return err
		}
		// wg-quick runs PreUp ("ip -6 addr change <src>/128 ..."). It fails when the address does not exist.
		if m := rePreUp.FindStringSubmatch(conf); m != nil {
			a, err := netip.ParseAddr(m[1])
			if err != nil || s.addrs[a] == nil {
				return fmt.Errorf("wg-quick: PreUp failed: Cannot assign requested address %s", m[1])
			}
			s.addrs[a].noPrefixRoute, s.addrs[a].deprecated = true, true
		}
		s.links[iface] = &simLink{priv: meta.PrivateKey, pub: pub, needHS: true, keyTime: s.clock.Now(), endpoint: meta.Endpoint, port: 40000}
		s.unit(iface).active = true
		return nil
	})
}

func (s *sim) UnitStop(ctx context.Context, iface string) error {
	return s.mut("UnitStop", func() error {
		delete(s.links, iface)
		s.unit(iface).active = false
		return nil
	})
}

func (s *sim) UnitEnable(ctx context.Context, iface string) error {
	return s.mut("UnitEnable", func() error { s.unit(iface).enabled = true; return nil })
}

func (s *sim) UnitDisable(ctx context.Context, iface string) error {
	return s.mut("UnitDisable", func() error { s.unit(iface).enabled = false; return nil })
}

func (s *sim) WriteDropIn(ctx context.Context, iface string) error {
	return s.mut("WriteDropIn", func() error { s.dropins[iface] = true; return nil })
}

func (s *sim) RemoveDropIn(ctx context.Context, iface string) error {
	return s.mut("RemoveDropIn", func() error { delete(s.dropins, iface); return nil })
}

func (s *sim) HasDropIn(iface string) bool { return s.dropins[iface] }

var _ host.System = (*sim)(nil)
var _ API = (*sim)(nil)

// ---- world builders ----

const testYAML = `
version: 1
paths:
  state_dir: STATE
reconcile:
  prune: true
defaults:
  source:
    device: eth0
    gateway: fe80::1
    subnets:
      - "2a01:4f8:1c1b:a31::/64"
groups:
  germany:
    server:
      country: DE
      city: Frankfurt
      exclude: ["DE#53-TOR", "node-de-16.protonvpn.net"]
      max_load: 70
      require_features: [p2p]
      exclude_features: [tor, secure_core]
      select: least_load
    interfaces: [pvpn-de1, pvpn-de2]
  netherlands:
    server:
      country: NL
      select: least_load
    interfaces: [pvpn-nl1, pvpn-nl2]
`

var key32 = base64.StdEncoding.EncodeToString([]byte("0123456789abcdef0123456789abcdef"))

func keyN(n int) string {
	b := []byte("0123456789abcdef0123456789abcdef")
	b[0] = byte('A' + n)
	return base64.StdEncoding.EncodeToString(b)
}

func lg(name, cc, city string, load int, feats int, machines ...string) proton.Logical {
	l := proton.Logical{ID: name, Name: name, EntryCountry: cc, ExitCountry: cc, City: city, Tier: 2, Features: feats, Status: 1, Load: load}
	for i, m := range machines {
		l.Servers = append(l.Servers, proton.Physical{ID: m, Domain: m, EntryIP: fmt.Sprintf("203.0.113.%d", 10+i), EntryIPv6: fmt.Sprintf("2001:db8:%x::%d", len(m), 10+i),
			ExitIP: "203.0.113.1", Label: fmt.Sprint(i), X25519PublicKey: keyN(len(name) + i), Status: 1})
	}
	return l
}

func defaultLogicals() []proton.Logical {
	return []proton.Logical{
		lg("DE#1", "DE", "Frankfurt", 30, 4|16, "node-de-1.protonvpn.net"),
		lg("DE#2", "DE", "Frankfurt", 55, 4|16, "node-de-2.protonvpn.net"),
		lg("DE#3", "DE", "Berlin", 5, 4|16, "node-de-3.protonvpn.net"),
		lg("DE#4", "DE", "Frankfurt", 90, 4|16, "node-de-4.protonvpn.net"), // above max_load
		lg("NL#1", "NL", "Amsterdam", 20, 4|16, "node-nl-1.protonvpn.net"),
		lg("NL#2", "NL", "Amsterdam", 40, 4|16, "node-nl-2.protonvpn.net"),
	}
}

type world struct {
	t   *testing.T
	s   *sim
	cfg *config.Config
	dir string
}

func newWorld(t *testing.T) *world {
	t.Helper()
	dir := filepath.Join(t.TempDir(), "state")
	s := newSim(t)
	s.logicals = defaultLogicals()
	w := &world{t: t, s: s, dir: dir}
	w.setConfig(testYAML)
	return w
}

func (w *world) setConfig(y string) {
	w.t.Helper()
	cfg, err := config.Parse([]byte(strings.ReplaceAll(y, "STATE", w.dir)))
	if err != nil {
		w.t.Fatal(err)
	}
	w.cfg = cfg
}

// engine returns a fresh engine, as a new process would.
func (w *world) engine() *Engine {
	w.t.Helper()
	store, err := state.Open(w.dir, true)
	if err != nil {
		w.t.Fatal(err)
	}
	e := New(w.cfg, store, w.s, w.s)
	e.Clock = w.s.clock
	e.NewCred = w.s.newCred
	e.Rand = func(n int) int { return 0 }
	if err := e.Load(); err != nil {
		w.t.Fatal(err)
	}
	return e
}

func (w *world) reconcile() (*Plan, error) {
	e := w.engine()
	return e.Reconcile(context.Background(), false)
}

func (w *world) mustReconcile() *Plan {
	w.t.Helper()
	p, err := w.reconcile()
	if err != nil {
		w.t.Fatalf("reconcile: %v", err)
	}
	return p
}

func (w *world) loadState() *state.State {
	w.t.Helper()
	store, _ := state.Open(w.dir, false)
	st, err := store.Load()
	if err != nil {
		w.t.Fatal(err)
	}
	return st
}

// crashRun runs fn and reports whether the simulated process died.
func crashRun(fn func()) (crashed bool) {
	defer func() {
		if r := recover(); r != nil {
			if _, ok := r.(crashSignal); ok {
				crashed = true
				return
			}
			panic(r)
		}
	}()
	fn()
	return false
}
