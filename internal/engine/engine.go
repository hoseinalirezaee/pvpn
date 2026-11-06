// Package engine plans and runs reconcile and rotate. It keeps state and the journal consistent.
package engine

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"net/netip"
	"sort"
	"time"

	"pvpn/internal/alloc"
	"pvpn/internal/config"
	"pvpn/internal/host"
	"pvpn/internal/proton"
	"pvpn/internal/render"
	"pvpn/internal/selector"
	"pvpn/internal/state"
)

// API is the part of the Proton client the engine uses. *proton.Client implements it.
type API interface {
	Info(ctx context.Context) (proton.VPNInfo, error)
	Logicals(ctx context.Context) ([]proton.Logical, error)
	CreateCert(ctx context.Context, rq proton.CertRequest) (*proton.Cert, error)
	DeleteCert(ctx context.Context, serial string) error
	ListCerts(ctx context.Context) ([]proton.CertInfo, error)
}

// Engine holds everything a command needs. Create it with New, then call Load.
type Engine struct {
	Cfg   *config.Config
	Store *state.Store
	API   API
	Sys   host.System
	Clock host.Clock

	Rand    selector.Rand
	Entropy io.Reader
	NewCred func() (*proton.Credential, error)
	Logf    func(format string, args ...any)

	AddrWait  time.Duration // bounded address check
	Validate  time.Duration // deadline for handshake and traffic probe
	PortRetry time.Duration // set a new listen port when no handshake came in this time

	st     *state.State
	dev    host.DeviceRef
	devSet bool
	keys   map[string]string // private keys that are not in a WireGuard file yet
	used   *alloc.Used
}

// New returns an engine with production defaults.
func New(cfg *config.Config, store *state.Store, api API, sys host.System) *Engine {
	return &Engine{
		Cfg: cfg, Store: store, API: api, Sys: sys, Clock: host.RealClock{},
		NewCred: proton.NewCredential, Logf: func(string, ...any) {},
		AddrWait: 10 * time.Second, Validate: 30 * time.Second, PortRetry: 4 * time.Second,
		keys: map[string]string{},
	}
}

// Load reads the state file.
func (e *Engine) Load() error {
	st, err := e.Store.Load()
	if err != nil {
		return err
	}
	e.st = st
	return nil
}

// State returns the loaded state (read-only use).
func (e *Engine) State() *state.State { return e.st }

func (e *Engine) save() error { return e.Store.Save(e.st) }

func (e *Engine) logf(format string, args ...any) {
	if e.Logf != nil {
		e.Logf(format, args...)
	}
}

// srcDevice is the source device of the config. With no groups in the config (a full prune)
// it is the device that the saved interfaces use.
func (e *Engine) srcDevice() string {
	if d := e.Cfg.Defaults.Source.Device; d != "" {
		return d
	}
	if e.st != nil {
		for _, n := range e.st.InterfaceNames() {
			if d := e.st.Interfaces[n].Device; d != "" {
				return d
			}
		}
	}
	return ""
}

func (e *Engine) deviceRef(ctx context.Context) (host.DeviceRef, error) {
	if e.devSet {
		return e.dev, nil
	}
	ref, err := e.Sys.NetplanDevice(ctx, e.srcDevice())
	if err != nil {
		return host.DeviceRef{}, err
	}
	e.dev, e.devSet = ref, true
	return ref, nil
}

func (e *Engine) member(name string, it *state.Interface) (render.Member, error) {
	src, err := netip.ParseAddr(it.SourceIP)
	if err != nil {
		return render.Member{}, fmt.Errorf("interface %s: bad saved source address %q", name, it.SourceIP)
	}
	gw := e.Cfg.Gateway
	if !gw.IsValid() {
		gw, err = netip.ParseAddr(it.Gateway)
		if err != nil {
			return render.Member{}, fmt.Errorf("interface %s: no gateway in the config or the state", name)
		}
	}
	return render.Member{Iface: name, Table: it.Table, Mark: it.Mark, Priority: it.Priority,
		Addrs: []netip.Addr{src}, From: src, Gateway: gw}, nil
}

type override struct {
	addrs []netip.Addr
	from  netip.Addr
}

// devices builds the netplan view of the state. ov changes single members during a rotation.
func (e *Engine) devices(ctx context.Context, ov map[string]override) ([]render.Device, error) {
	var ms []render.Member
	for _, n := range e.st.InterfaceNames() {
		m, err := e.member(n, e.st.Interfaces[n])
		if err != nil {
			return nil, err
		}
		if o, ok := ov[n]; ok {
			m.Addrs, m.From = o.addrs, o.from
		}
		ms = append(ms, m)
	}
	if len(ms) == 0 {
		return nil, nil
	}
	ref, err := e.deviceRef(ctx)
	if err != nil {
		return nil, err
	}
	return []render.Device{{Section: ref.Section, ID: ref.ID, Members: ms}}, nil
}

// syncNetplan renders the managed netplan file from the state and applies it when it differs.
// With force it applies even when the file is the same (to restore live resources).
func (e *Engine) syncNetplan(ctx context.Context, ov map[string]override, force bool) error {
	devs, err := e.devices(ctx, ov)
	if err != nil {
		return err
	}
	content := render.Netplan(devs)
	cur, err := e.Sys.NetplanManaged()
	if err != nil {
		return err
	}
	if !force && bytes.Equal(cur, content) {
		return nil
	}
	if content == nil && cur == nil {
		return nil
	}
	e.logf("netplan: applying %d member(s)", countMembers(devs))
	if err := e.Sys.NetplanApply(ctx, content, devs); err != nil {
		return err
	}
	e.restoreFlags(ctx, devs)
	return nil
}

// restoreFlags sets noprefixroute and preferred_lft 0 on every managed address again.
// A netplan apply makes networkd write the addresses again, and netplan cannot set noprefixroute.
// Errors are not final here: the per-member check that follows reports them.
func (e *Engine) restoreFlags(ctx context.Context, devs []render.Device) {
	for _, d := range devs {
		for _, m := range d.Members {
			for _, a := range m.Addrs {
				if err := e.Sys.EnsureAddr(ctx, e.srcDevice(), a, e.AddrWait); err != nil {
					e.logf("warning: %s: address %s: %v", m.Iface, a, err)
				}
			}
		}
	}
}

// warm sends a few packets from the source address to the group server before a handshake.
func (e *Engine) warm(ctx context.Context, src string, g *state.Group) {
	s, err1 := netip.ParseAddr(src)
	d, err2 := netip.ParseAddr(g.EntryIPv6)
	if err1 != nil || err2 != nil {
		return
	}
	if err := e.Sys.WarmSource(ctx, s, d); err != nil {
		e.logf("warning: warm-up from %s failed: %v", s, err)
	}
}

func countMembers(devs []render.Device) int {
	n := 0
	for _, d := range devs {
		n += len(d.Members)
	}
	return n
}

// checkMember waits for the member addresses and then checks route and rule.
func (e *Engine) checkMember(ctx context.Context, name string, addrs []netip.Addr, m render.Member) error {
	for _, a := range addrs {
		if err := e.Sys.EnsureAddr(ctx, e.srcDevice(), a, e.AddrWait); err != nil {
			return fmt.Errorf("%s: %w", name, err)
		}
	}
	if err := e.Sys.CheckResources(ctx, e.srcDevice(), m); err != nil {
		return fmt.Errorf("%s: %w", name, err)
	}
	return nil
}

// ---- journal helpers ----

type issued struct {
	cred *proton.Credential
	cert *proton.Cert
	name string
	op   *state.Op
}

// issueCert makes a certificate for the interface on the group server.
// The journal gets an intent before the API call, so a crash cannot leak a certificate.
func (e *Engine) issueCert(ctx context.Context, iface string, g *state.Group) (*issued, error) {
	cred, err := e.NewCred()
	if err != nil {
		return nil, err
	}
	name := "pvpn-" + iface + "-" + state.NewID()
	op := e.st.AddOp(&state.Op{Kind: state.OpCertIssue, Iface: iface, DeviceName: name})
	if err := e.save(); err != nil {
		return nil, err
	}
	cert, err := e.API.CreateCert(ctx, proton.CertRequest{
		DeviceName: name, Label: g.Label, PeerName: g.Logical, PeerIP: g.EntryIPv4,
		PeerPubKey: g.PublicKey, EdPubKey: cred.EdPublic,
	})
	if err != nil {
		e.cleanupIssue(context.WithoutCancel(ctx), op)
		return nil, fmt.Errorf("create certificate for %s: %w", iface, err)
	}
	op.Serial = cert.Serial
	if err := e.save(); err != nil {
		_ = e.DeleteOwnedCert(context.WithoutCancel(ctx), cert.Serial)
		return nil, err
	}
	return &issued{cred, cert, name, op}, nil
}

// cleanupIssue looks for a certificate that an interrupted issue may have created. It revokes it
// only when its device name matches the journal entry.
func (e *Engine) cleanupIssue(ctx context.Context, op *state.Op) {
	if op.Serial == "" {
		list, err := e.API.ListCerts(ctx)
		if err != nil {
			return // keep the op; the next modifying command tries again
		}
		for _, c := range list {
			if c.DeviceName == op.DeviceName {
				op.Serial = c.Serial
			}
		}
	}
	if op.Serial != "" {
		if err := e.API.DeleteCert(ctx, op.Serial); err != nil {
			return
		}
	}
	e.st.RemoveOp(op.ID)
	_ = e.save()
}

// DeleteOwnedCert revokes a certificate through a journal entry.
func (e *Engine) DeleteOwnedCert(ctx context.Context, serial string) error {
	if serial == "" {
		return nil
	}
	op := e.st.AddOp(&state.Op{Kind: state.OpCertRevoke, Serial: serial})
	if err := e.save(); err != nil {
		return err
	}
	return e.runRevoke(ctx, op)
}

func (e *Engine) runRevoke(ctx context.Context, op *state.Op) error {
	if err := e.API.DeleteCert(ctx, op.Serial); err != nil {
		e.logf("warning: cannot revoke certificate %s now; pvpn retries on the next command: %v", op.Serial, err)
		return err
	}
	e.st.RemoveOp(op.ID)
	return e.save()
}

// ensureAddrGone removes an address that no longer belongs to any interface.
// The journal entry makes the removal survive a crash.
func (e *Engine) ensureAddrGone(ctx context.Context, ip netip.Addr) error {
	if e.addrInState(ip) {
		return nil
	}
	op := e.st.AddOp(&state.Op{Kind: state.OpAddrRemove, Dev: e.srcDevice(), Addr: ip.String()})
	if err := e.save(); err != nil {
		return err
	}
	return e.runAddrRemove(ctx, op)
}

func (e *Engine) runAddrRemove(ctx context.Context, op *state.Op) error {
	ip, err := netip.ParseAddr(op.Addr)
	if err != nil {
		e.st.RemoveOp(op.ID)
		return e.save()
	}
	if !e.addrInState(ip) {
		list, err := e.Sys.ListAddrs(ctx, op.Dev)
		if err != nil {
			return err
		}
		for _, a := range list {
			if a.Addr == ip {
				if err := e.Sys.DelAddr(ctx, op.Dev, ip); err != nil {
					return err
				}
			}
		}
	}
	e.st.RemoveOp(op.ID)
	return e.save()
}

func (e *Engine) addrInState(ip netip.Addr) bool {
	for _, it := range e.st.Interfaces {
		if it.SourceIP == ip.String() {
			return true
		}
	}
	for _, op := range e.st.Pending {
		if op.Txn != nil {
			for _, m := range op.Txn.Members {
				if m.Old.SourceIP == ip.String() || m.New.SourceIP == ip.String() {
					// During a transaction both addresses are live. Cleanup logic decides.
					if op.Txn.Phase != state.TxnCommitted && op.Txn.Phase != state.TxnPrepared {
						return true
					}
				}
			}
		}
	}
	return false
}

// ---- allocation ----

func (e *Engine) usedIDs(ctx context.Context) (*alloc.Used, error) {
	if e.used != nil {
		return e.used, nil
	}
	u, err := e.Sys.UsedIDs(ctx)
	if err != nil {
		return nil, err
	}
	for _, it := range e.st.Interfaces {
		u.Tables[it.Table], u.Marks[it.Mark], u.Priorities[it.Priority] = true, true, true
	}
	e.used = u
	return u, nil
}

// newSource picks a random source address that nothing uses.
func (e *Engine) newSource(ctx context.Context, extra ...netip.Addr) (netip.Addr, error) {
	taken := map[netip.Addr]bool{}
	if e.Cfg.Gateway.IsValid() {
		taken[e.Cfg.Gateway] = true
	}
	for _, a := range extra {
		taken[a] = true
	}
	for _, it := range e.st.Interfaces {
		if a, err := netip.ParseAddr(it.SourceIP); err == nil {
			taken[a] = true
		}
	}
	for _, op := range e.st.Pending {
		if op.Txn != nil {
			for _, m := range op.Txn.Members {
				for _, s := range []string{m.Old.SourceIP, m.New.SourceIP} {
					if a, err := netip.ParseAddr(s); err == nil {
						taken[a] = true
					}
				}
			}
		}
	}
	list, err := e.Sys.ListAddrs(ctx, e.srcDevice())
	if err != nil {
		return netip.Addr{}, err
	}
	for _, a := range list {
		taken[a.Addr] = true
	}
	return alloc.RandomAddr(e.Cfg.Subnets, e.Entropy, func(a netip.Addr) bool { return taken[a] })
}

func (e *Engine) rnd() selector.Rand {
	if e.Rand != nil {
		return e.Rand
	}
	return selector.CryptoRand
}

// orderedInterfaces returns the configured interfaces that exist in the state, in config order.
func (e *Engine) orderedInterfaces() []string {
	var out []string
	for _, n := range e.Cfg.AllInterfaces() {
		if _, ok := e.st.Interfaces[n]; ok {
			out = append(out, n)
		}
	}
	return out
}

func sortedKeys[V any](m map[string]V) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}

// ErrNeedsLogin wraps proton.ErrLoginRequired for callers.
var ErrNeedsLogin = proton.ErrLoginRequired

func isLogin(err error) bool { return errors.Is(err, proton.ErrLoginRequired) }
