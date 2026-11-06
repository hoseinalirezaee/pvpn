package engine

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"net/netip"
	"os"
	"strings"
	"time"

	"pvpn/internal/proton"
	"pvpn/internal/render"
	"pvpn/internal/selector"
	"pvpn/internal/state"
)

// Action is one line of a plan.
type Action struct {
	Kind   string // select, replace-server, create, renew, repair, prune
	Group  string
	Iface  string
	Detail string
}

func (a Action) String() string {
	s := a.Kind
	if a.Group != "" {
		s += " group " + a.Group
	}
	if a.Iface != "" {
		s += " " + a.Iface
	}
	if a.Detail != "" {
		s += ": " + a.Detail
	}
	return s
}

// Plan is what reconcile would do.
type Plan struct {
	Actions  []Action
	Warnings []string

	groups []*groupPlan
	prune  []string
	drift  bool // the managed netplan file differs from the state
}

// Empty reports whether nothing needs to change.
func (p *Plan) Empty() bool { return len(p.Actions) == 0 }

func (p *Plan) String() string {
	var b strings.Builder
	for _, a := range p.Actions {
		b.WriteString("  " + a.String() + "\n")
	}
	for _, w := range p.Warnings {
		b.WriteString("  warning: " + w + "\n")
	}
	if p.Empty() {
		b.WriteString("  nothing to do: the host matches the config\n")
	}
	return b.String()
}

const (
	modeKeep    = "keep"
	modeNew     = "new"
	modeReplace = "replace"
)

type groupPlan struct {
	name    string
	sel     selector.Candidate
	mode    string
	members []string // existing members, in config order
	create  []string
	renew   map[string]string // iface -> reason
	repair  []*facts
}

// facts describes one existing interface.
type facts struct {
	name         string
	it           *state.Interface
	priv         string
	credBad      string // not empty: the credential must be replaced
	reasons      []string
	netplan      bool // netplan must be applied again
	confDiffers  bool
	needStart    bool
	needEnable   bool
	needDropIn   bool
	needValidate bool
}

func (f *facts) needsRepair() bool {
	return f.netplan || f.confDiffers || f.needStart || f.needEnable || f.needDropIn || f.needValidate || len(f.reasons) > 0
}

// plan reads the account, the servers, and the host. It changes nothing.
func (e *Engine) plan(ctx context.Context, logicals []proton.Logical, maxTier int) (*Plan, error) {
	p := &Plan{}
	var errs []error
	now := e.Clock.Now()

	if len(e.st.Pending) > 0 {
		p.Warnings = append(p.Warnings, fmt.Sprintf("%d pending journal operation(s); the next modifying command finishes them", len(e.st.Pending)))
	}
	if len(e.Cfg.Groups) > 0 {
		if _, err := e.deviceRef(ctx); err != nil {
			errs = append(errs, err)
		}
	}
	drift, derr := e.netplanDrift(ctx)
	if derr != nil {
		errs = append(errs, derr)
	}
	p.drift = drift

	for _, gname := range e.Cfg.GroupNames() {
		gc := e.Cfg.Groups[gname]
		gp := &groupPlan{name: gname, renew: map[string]string{}}
		f := selector.FromConfig(gc.Server, maxTier)
		saved := e.st.Groups[gname]
		cands, funnel := selector.Match(logicals, f, false)

		for _, in := range gc.Interfaces {
			if it, ok := e.st.Interfaces[in]; ok {
				if it.Group != gname {
					errs = append(errs, fmt.Errorf("interface %s belongs to group %q in the state, not %q; remove it from the config first and prune it", in, it.Group, gname))
					continue
				}
				gp.members = append(gp.members, in)
			}
		}
		fresh, valid := selector.Candidate{}, false
		if saved != nil {
			fresh, valid = selector.Revalidate(saved, logicals, f)
		}
		switch {
		case saved != nil && valid && selector.SameEndpoint(saved, fresh):
			gp.mode, gp.sel = modeKeep, fresh
		case saved != nil && valid:
			gp.mode, gp.sel = modeReplace, fresh // same server, changed address or key
		default:
			if len(cands) == 0 {
				errs = append(errs, fmt.Errorf("group %s: %w", gname, &selector.NoCandidatesError{Funnel: funnel}))
				continue
			}
			c, err := selector.Choose(cands, gc.Server.Select, e.rnd())
			if err != nil {
				errs = append(errs, err)
				continue
			}
			gp.sel = c
			gp.mode = modeNew
			if saved != nil && len(gp.members) > 0 {
				gp.mode = modeReplace
			}
		}
		if gp.mode == modeReplace && len(gp.members) == 0 {
			gp.mode = modeNew
		}

		detail := fmt.Sprintf("%s on %s (load %d)", gp.sel.Logical.Name, gp.sel.Server.Domain, gp.sel.Logical.Load)
		switch gp.mode {
		case modeNew:
			p.Actions = append(p.Actions, Action{"select", gname, "", detail})
		case modeReplace:
			from := "?"
			if saved != nil {
				from = saved.Logical + " on " + saved.Domain
			}
			p.Actions = append(p.Actions, Action{"replace-server", gname, "", fmt.Sprintf("%s -> %s; new keys and certificates for %s", from, detail, strings.Join(gp.members, ", "))})
		}

		for _, in := range gc.Interfaces {
			it, exists := e.st.Interfaces[in]
			if !exists {
				if err := e.checkNewName(ctx, in); err != nil {
					errs = append(errs, err)
					continue
				}
				gp.create = append(gp.create, in)
				p.Actions = append(p.Actions, Action{"create", gname, in, "new key, certificate, and random source address"})
				continue
			}
			if it.Group != gname {
				continue // reported above
			}
			if gp.mode == modeReplace {
				continue // replaced together with the group
			}
			g := e.st.Groups[gname]
			ft, err := e.inspect(ctx, in, it, g, now, drift)
			if err != nil {
				errs = append(errs, err)
				continue
			}
			switch {
			case ft.credBad != "":
				gp.renew[in] = ft.credBad
				p.Actions = append(p.Actions, Action{"renew", gname, in, ft.credBad + "; new key and certificate, same source address and server"})
			case ft.needsRepair():
				gp.repair = append(gp.repair, ft)
				p.Actions = append(p.Actions, Action{"repair", gname, in, strings.Join(ft.reasons, ", ")})
			}
		}
		p.groups = append(p.groups, gp)
	}

	// Interfaces that the config no longer lists.
	for _, n := range e.st.InterfaceNames() {
		if _, ok := e.Cfg.GroupOf(n); ok {
			continue
		}
		if e.Cfg.Reconcile.Prune {
			p.prune = append(p.prune, n)
			p.Actions = append(p.Actions, Action{"prune", e.st.Interfaces[n].Group, n, "stop, disable, remove files and netplan entry, revoke certificate"})
		} else {
			p.Warnings = append(p.Warnings, fmt.Sprintf("%s is not in the config; left running because reconcile.prune is false", n))
		}
	}
	if len(e.st.Interfaces) == 0 && len(e.st.Pending) == 0 {
		if cur, err := e.Sys.NetplanManaged(); err == nil && cur != nil {
			errs = append(errs, errors.New("the managed netplan file exists but the state is empty; restore the state directory or remove /etc/netplan/90-pvpn.yaml"))
		}
	}
	if len(errs) > 0 {
		return p, joinErrs(errs)
	}
	return p, nil
}

// checkNewName refuses a name that an unmanaged file or link already uses.
func (e *Engine) checkNewName(ctx context.Context, name string) error {
	if text, err := e.Sys.ReadWG(name); err == nil {
		if render.ParseWG(text).Managed {
			return fmt.Errorf("/etc/wireguard/%s.conf is a pvpn file but the state has no such interface; remove the file or restore the state", name)
		}
		return fmt.Errorf("/etc/wireguard/%s.conf exists and is not managed by pvpn; pvpn does not overwrite it", name)
	} else if !errors.Is(err, os.ErrNotExist) {
		return err
	}
	if ok, err := e.Sys.LinkExists(ctx, name); err != nil {
		return err
	} else if ok {
		return fmt.Errorf("a network interface named %s already exists and is not managed by pvpn", name)
	}
	return nil
}

// netplanDrift reports whether the managed netplan file differs from the file the state calls for.
func (e *Engine) netplanDrift(ctx context.Context) (bool, error) {
	if len(e.st.Interfaces) == 0 {
		return false, nil
	}
	devs, err := e.devices(ctx, nil)
	if err != nil {
		return false, err
	}
	cur, err := e.Sys.NetplanManaged()
	if err != nil {
		return false, err
	}
	return !bytes.Equal(cur, render.Netplan(devs)), nil
}

// inspect gathers the facts of one existing interface.
func (e *Engine) inspect(ctx context.Context, name string, it *state.Interface, g *state.Group, now time.Time, drift bool) (*facts, error) {
	f := &facts{name: name, it: it}
	if g == nil {
		return nil, fmt.Errorf("%s: its group has no saved server", name)
	}
	conf, err := e.Sys.ReadWG(name)
	switch {
	case errors.Is(err, os.ErrNotExist):
		f.credBad = "WireGuard file is missing"
	case err != nil:
		return nil, err
	default:
		meta := render.ParseWG(conf)
		if !meta.Managed {
			return nil, fmt.Errorf("/etc/wireguard/%s.conf is not managed by pvpn; pvpn does not overwrite it", name)
		}
		f.priv = meta.PrivateKey
		if pub, err := proton.PublicFromPrivate(meta.PrivateKey); meta.PrivateKey == "" || err != nil || pub != it.WGPublicKey {
			f.credBad = "private key does not match the saved certificate"
		} else if want, werr := e.wgText(name, it, g, meta.PrivateKey); werr != nil {
			return nil, werr
		} else if conf != want {
			f.confDiffers = true
			f.reasons = append(f.reasons, "WireGuard file differs from the config")
		}
	}
	if f.credBad == "" && it.CertExpires > 0 && now.Unix() >= it.CertExpires {
		f.credBad = "certificate expired"
	}
	if f.credBad != "" {
		return f, nil
	}

	src, err := netip.ParseAddr(it.SourceIP)
	if err != nil {
		return nil, fmt.Errorf("%s: bad saved source address", name)
	}
	list, err := e.Sys.ListAddrs(ctx, e.srcDevice())
	if err != nil {
		return nil, err
	}
	found := false
	for _, a := range list {
		if a.Addr == src {
			found = true
			if !a.NoPrefixRoute || !a.Deprecated {
				f.reasons = append(f.reasons, "address flags (noprefixroute, preferred_lft 0) are missing")
			}
		}
	}
	if !found {
		f.netplan = true
		f.reasons = append(f.reasons, "source address is missing")
	}
	if m, err := e.member(name, it); err == nil {
		if err := e.Sys.CheckResources(ctx, e.srcDevice(), m); err != nil {
			f.netplan = true
			f.reasons = append(f.reasons, "route or rule is missing")
		}
	}
	if drift {
		f.netplan = true
		f.reasons = append(f.reasons, "managed netplan file differs from the state")
	}
	if ok, err := e.Sys.UnitActive(ctx, name); err != nil {
		return nil, err
	} else if !ok {
		f.needStart = true
		f.reasons = append(f.reasons, "unit is not running")
	}
	if ok, err := e.Sys.UnitEnabled(ctx, name); err != nil {
		return nil, err
	} else if !ok {
		f.needEnable = true
		f.reasons = append(f.reasons, "unit is not enabled")
	}
	if !e.Sys.HasDropIn(name) {
		f.needDropIn = true
		f.reasons = append(f.reasons, "boot ordering drop-in is missing")
	}
	if it.Phase != state.PhaseReady || it.ValidatedAt.IsZero() {
		f.needValidate = true
		f.reasons = append(f.reasons, "tunnel was never validated")
	}
	f.reasons = dedupe(f.reasons)
	return f, nil
}

func dedupe(in []string) []string {
	seen := map[string]bool{}
	var out []string
	for _, s := range in {
		if !seen[s] {
			seen[s] = true
			out = append(out, s)
		}
	}
	return out
}
