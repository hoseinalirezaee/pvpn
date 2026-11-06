package engine

import (
	"context"
	"errors"
	"fmt"
	"net/netip"
	"time"

	"pvpn/internal/alloc"
	"pvpn/internal/render"
	"pvpn/internal/state"
)

// wgText renders the WireGuard file of an interface for the saved group server.
func (e *Engine) wgText(name string, it *state.Interface, g *state.Group, priv string) (string, error) {
	src, err := netip.ParseAddr(it.SourceIP)
	if err != nil {
		return "", fmt.Errorf("interface %s: bad source address %q", name, it.SourceIP)
	}
	ep, err := netip.ParseAddr(g.EntryIPv6)
	if err != nil {
		return "", fmt.Errorf("group %s: bad server address %q", it.Group, g.EntryIPv6)
	}
	return render.WireGuard(render.WG{
		Iface: name, Group: it.Group, Server: g.Logical, PrivateKey: priv, Mark: it.Mark, Device: it.Device,
		SourceIP: src, PeerPublicKey: g.PublicKey, Endpoint: ep,
	}), nil
}

// validateTunnel waits for a handshake that is newer than t0 and then sends a traffic probe
// that is bound to this interface. If no handshake comes, it sets a new listen port every PortRetry.
// A fresh source address often needs a second try, and a new port gives a new socket.
func (e *Engine) validateTunnel(ctx context.Context, name string, it *state.Interface, t0 time.Time) error {
	op := e.st.AddOp(&state.Op{Kind: state.OpProbeClean, Iface: name, Table: it.Table, Priority: it.Priority})
	if err := e.save(); err != nil {
		return err
	}
	defer func() {
		_ = e.Sys.ProbeCleanup(context.WithoutCancel(ctx), name, it.Table, it.Priority)
		e.st.RemoveOp(op.ID)
		_ = e.save()
	}()

	start := e.Clock.Now()
	deadline := start.Add(e.Validate)
	nextPort := start.Add(e.PortRetry)
	var lastProbe error
	sawHandshake := false
	for e.Clock.Now().Before(deadline) {
		st, err := e.Sys.WGStatus(ctx, name)
		if err != nil {
			return err
		}
		if !st.Exists {
			return fmt.Errorf("%s: WireGuard interface does not exist", name)
		}
		if !st.Handshake.IsZero() && st.Handshake.Unix() >= t0.Unix() {
			sawHandshake = true
			pctx, cancel := context.WithDeadline(ctx, deadline)
			exit, perr := e.Sys.Probe(pctx, name, it.Table, it.Priority)
			cancel()
			if perr == nil {
				e.logf("%s: tunnel works (handshake ok, exit IP %s)", name, exit)
				return nil
			}
			lastProbe = perr
		} else if !e.Clock.Now().Before(nextPort) {
			if port, err := e.Sys.FreePort(ctx); err == nil {
				if err := e.Sys.WGSetListenPort(ctx, name, port); err == nil {
					e.logf("%s: no handshake yet, new listen port %d", name, port)
				}
			}
			nextPort = e.Clock.Now().Add(e.PortRetry)
		}
		if err := e.Clock.Sleep(ctx, 500*time.Millisecond); err != nil {
			return err
		}
	}
	switch {
	case lastProbe != nil:
		return fmt.Errorf("%s: handshake ok but traffic probe failed within %s: %w", name, e.Validate, lastProbe)
	case sawHandshake:
		return fmt.Errorf("%s: traffic probe did not finish within %s", name, e.Validate)
	}
	return fmt.Errorf("%s: no fresh handshake within %s", name, e.Validate)
}

// startMember writes the WireGuard file and the drop-in, then enables and starts the unit.
func (e *Engine) startMember(ctx context.Context, name string, it *state.Interface, g *state.Group, priv string) (time.Time, error) {
	text, err := e.wgText(name, it, g, priv)
	if err != nil {
		return time.Time{}, err
	}
	if err := e.Sys.WriteWG(name, text); err != nil {
		return time.Time{}, fmt.Errorf("write %s.conf: %w", name, err)
	}
	if err := e.Sys.WriteDropIn(ctx, name); err != nil {
		return time.Time{}, fmt.Errorf("write unit drop-in for %s: %w", name, err)
	}
	if err := e.Sys.UnitEnable(ctx, name); err != nil {
		return time.Time{}, fmt.Errorf("enable %s: %w", name, err)
	}
	t0 := e.Clock.Now()
	if err := e.Sys.UnitStart(ctx, name); err != nil {
		return time.Time{}, fmt.Errorf("start %s: %w", name, err)
	}
	return t0, nil
}

// markReady records a validated interface.
func (e *Engine) markReady(name string) error {
	it := e.st.Interfaces[name]
	it.Phase = state.PhaseReady
	it.ValidatedAt = e.Clock.Now().UTC()
	it.AppliedGen = e.st.Generation
	return e.save()
}

type createItem struct{ iface, group string }

// createMembers makes new interfaces: keys, certificates, addresses (one netplan apply), then WireGuard.
func (e *Engine) createMembers(ctx context.Context, items []createItem) error {
	var errs []error
	var provisioned []string
	abort := func(names ...string) {
		var addrs []netip.Addr
		for _, n := range names {
			if it := e.st.Interfaces[n]; it != nil {
				if a, err := netip.ParseAddr(it.SourceIP); err == nil {
					addrs = append(addrs, a)
				}
				serial := it.CertSerial
				delete(e.st.Interfaces, n)
				delete(e.keys, n)
				_ = e.save()
				_ = e.DeleteOwnedCert(context.WithoutCancel(ctx), serial)
			}
		}
		if err := e.syncNetplan(context.WithoutCancel(ctx), nil, false); err != nil {
			errs = append(errs, fmt.Errorf("netplan cleanup after a failed create: %w", err))
		}
		for _, a := range addrs {
			_ = e.ensureAddrGone(context.WithoutCancel(ctx), a)
		}
	}

	for _, it := range items {
		if err := e.provision(ctx, it); err != nil {
			errs = append(errs, err)
			abort(provisioned...)
			return joinErrs(errs)
		}
		provisioned = append(provisioned, it.iface)
	}
	if len(provisioned) == 0 {
		return nil
	}
	if err := e.syncNetplan(ctx, nil, true); err != nil {
		abort(provisioned...)
		return joinErrs(append(errs, err))
	}
	var ready []string
	for _, n := range provisioned {
		it := e.st.Interfaces[n]
		m, err := e.member(n, it)
		if err == nil {
			err = e.checkMember(ctx, n, m.Addrs, m)
		}
		if err != nil {
			errs = append(errs, err)
			abort(n)
			continue
		}
		ready = append(ready, n)
	}
	for _, n := range ready {
		it := e.st.Interfaces[n]
		g := e.st.Groups[it.Group]
		e.warm(ctx, it.SourceIP, g)
		t0, err := e.startMember(ctx, n, it, g, e.keys[n])
		if err != nil {
			errs = append(errs, err)
			continue
		}
		delete(e.keys, n)
		if err := e.validateTunnel(ctx, n, it, t0); err != nil {
			errs = append(errs, err)
			continue
		}
		if err := e.markReady(n); err != nil {
			errs = append(errs, err)
		}
	}
	return joinErrs(errs)
}

// provision allocates identifiers and a source address, issues the certificate, and saves the interface.
func (e *Engine) provision(ctx context.Context, ci createItem) error {
	g := e.st.Groups[ci.group]
	if g == nil {
		return fmt.Errorf("group %s has no saved server", ci.group)
	}
	used, err := e.usedIDs(ctx)
	if err != nil {
		return err
	}
	ids := alloc.Next(used)
	src, err := e.newSource(ctx)
	if err != nil {
		return err
	}
	is, err := e.issueCert(ctx, ci.iface, g)
	if err != nil {
		return err
	}
	e.st.Interfaces[ci.iface] = &state.Interface{
		Group: ci.group, Device: e.srcDevice(), Gateway: e.Cfg.Gateway.String(), Table: ids.Table, Mark: ids.Mark, Priority: ids.Priority,
		SourceIP: src.String(), CertSerial: is.cert.Serial, CertName: is.name, WGPublicKey: is.cred.WGPublic,
		CertExpires: is.cert.Expiration, CertRefresh: is.cert.Refresh, Phase: state.PhaseProvisioning,
		AppliedGen: e.st.Generation, CreatedAt: e.Clock.Now().UTC(),
	}
	e.keys[ci.iface] = is.cred.WGPrivate
	e.st.RemoveOp(is.op.ID) // the certificate now belongs to the interface entry
	if err := e.save(); err != nil {
		return err
	}
	e.logf("%s: new key, certificate %s, source address %s", ci.iface, is.cert.Serial, src)
	return nil
}

func joinErrs(errs []error) error { return errors.Join(errs...) }
