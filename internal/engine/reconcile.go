package engine

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"time"

	"pvpn/internal/render"
	"pvpn/internal/selector"
	"pvpn/internal/state"
)

// Reconcile makes the managed resources match the config.
// With dryRun it reads and plans but changes nothing, not even tokens.
// The caller holds the state lock (exclusive for a real run, shared for a dry run).
func (e *Engine) Reconcile(ctx context.Context, dryRun bool) (*Plan, error) {
	if e.st == nil {
		if err := e.Load(); err != nil {
			return nil, err
		}
	}
	if !dryRun {
		if err := e.Recover(ctx); err != nil {
			return nil, fmt.Errorf("recovery of earlier operations failed: %w", err)
		}
	}
	info, err := e.API.Info(ctx)
	if err != nil {
		return nil, err
	}
	logicals, err := e.API.Logicals(ctx)
	if err != nil {
		return nil, err
	}
	pl, err := e.plan(ctx, logicals, info.MaxTier)
	if err != nil {
		return pl, err
	}
	if dryRun {
		return pl, nil
	}
	return pl, e.execute(ctx, pl)
}

func (e *Engine) execute(ctx context.Context, pl *Plan) error {
	if pl.Empty() && len(e.st.Pending) == 0 {
		return nil
	}
	e.st.Generation++
	if err := e.save(); err != nil {
		return err
	}
	var errs []error
	fail := func(err error) {
		if err != nil {
			errs = append(errs, err)
		}
	}

	// 0. The netplan file must match the state before any unit starts (for example after an interrupted run).
	if pl.drift {
		if err := e.syncNetplan(ctx, nil, false); err != nil {
			return err
		}
	}

	// 1. Server selection, server replacement, credential renewal.
	for _, gp := range pl.groups {
		switch gp.mode {
		case modeNew:
			g := selector.ToGroup(gp.sel)
			g.SelectedAt = e.Clock.Now().UTC()
			e.st.Groups[gp.name] = &g
			if err := e.save(); err != nil {
				fail(err)
				continue
			}
			e.logf("group %s: selected %s on %s", gp.name, g.Logical, g.Domain)
		case modeReplace:
			g := selector.ToGroup(gp.sel)
			g.SelectedAt = e.Clock.Now().UTC()
			fail(e.groupTxn(ctx, state.TxnReplace, gp.name, &g, gp.members))
		}
		for _, in := range gp.members {
			if reason, ok := gp.renew[in]; ok && gp.mode != modeReplace {
				e.logf("%s: %s", in, reason)
				fail(e.groupTxn(ctx, state.TxnRenew, gp.name, nil, []string{in}))
			}
		}
	}

	// 2. New interfaces, all groups together (one netplan apply).
	var items []createItem
	for _, gp := range pl.groups {
		if e.st.Groups[gp.name] == nil {
			continue
		}
		for _, in := range gp.create {
			items = append(items, createItem{in, gp.name})
		}
	}
	if len(items) > 0 {
		fail(e.createMembers(ctx, items))
	}

	// 3. Repairs.
	fail(e.repair(ctx, pl))

	// 4. Prune.
	if len(pl.prune) > 0 {
		fail(e.prune(ctx, pl.prune))
	}
	return errors.Join(errs...)
}

// repair brings drifted interfaces back. Healthy interfaces are not touched.
func (e *Engine) repair(ctx context.Context, pl *Plan) error {
	var all []*facts
	needNetplan := false
	for _, gp := range pl.groups {
		for _, f := range gp.repair {
			if gp.mode == modeReplace || gp.renew[f.name] != "" {
				continue
			}
			all = append(all, f)
			needNetplan = needNetplan || f.netplan
		}
	}
	if len(all) == 0 {
		return nil
	}
	var errs []error
	if needNetplan {
		if err := e.syncNetplan(ctx, nil, true); err != nil {
			return err
		}
	}
	for _, f := range all {
		if err := e.repairMember(ctx, f); err != nil {
			errs = append(errs, err)
		}
	}
	return errors.Join(errs...)
}

func (e *Engine) repairMember(ctx context.Context, f *facts) error {
	it := e.st.Interfaces[f.name]
	g := e.st.Groups[it.Group]
	m, err := e.member(f.name, it)
	if err != nil {
		return err
	}
	e.logf("%s: repair (%s)", f.name, strings.Join(f.reasons, ", "))
	if err := e.checkMember(ctx, f.name, m.Addrs, m); err != nil {
		return err
	}
	changed := false
	if f.confDiffers {
		text, err := e.wgText(f.name, it, g, f.priv)
		if err != nil {
			return err
		}
		if err := e.Sys.WriteWG(f.name, text); err != nil {
			return err
		}
		changed = true
	}
	if f.needDropIn {
		if err := e.Sys.WriteDropIn(ctx, f.name); err != nil {
			return err
		}
	}
	if f.needEnable {
		if err := e.Sys.UnitEnable(ctx, f.name); err != nil {
			return err
		}
	}
	var t0 time.Time
	started := false
	switch {
	case f.needStart:
		t0 = e.Clock.Now()
		if err := e.Sys.UnitStart(ctx, f.name); err != nil {
			return fmt.Errorf("start %s: %w", f.name, err)
		}
		started = true
	case changed:
		if err := e.Sys.UnitStop(ctx, f.name); err != nil {
			return err
		}
		t0 = e.Clock.Now()
		if err := e.Sys.UnitStart(ctx, f.name); err != nil {
			return fmt.Errorf("start %s: %w", f.name, err)
		}
		started = true
	}
	if started || f.needValidate {
		if err := e.validateTunnel(ctx, f.name, it, t0); err != nil {
			return err
		}
		return e.markReady(f.name)
	}
	return nil
}

// prune removes interfaces that are no longer in the config. Journal entries come before every action,
// so an interruption leaves nothing without an owner.
func (e *Engine) prune(ctx context.Context, names []string) error {
	var errs []error
	var done []string
	for _, n := range names {
		it := e.st.Interfaces[n]
		e.logf("%s: pruning", n)
		_ = e.Sys.UnitDisable(ctx, n)
		_ = e.Sys.UnitStop(ctx, n)
		if active, err := e.Sys.UnitActive(ctx, n); err != nil || active {
			errs = append(errs, fmt.Errorf("%s: unit did not stop", n))
			continue
		}
		if err := e.Sys.RemoveDropIn(ctx, n); err != nil {
			errs = append(errs, fmt.Errorf("%s: %w", n, err))
		}
		if text, err := e.Sys.ReadWG(n); err == nil {
			if render.ParseWG(text).Managed {
				if err := e.Sys.RemoveWG(n); err != nil {
					errs = append(errs, err)
					continue
				}
			} else {
				e.logf("warning: /etc/wireguard/%s.conf is not a pvpn file; it stays", n)
			}
		}
		// State and journal change in one atomic write.
		delete(e.st.Interfaces, n)
		e.st.AddOp(&state.Op{Kind: state.OpCertRevoke, Iface: n, Serial: it.CertSerial})
		e.st.AddOp(&state.Op{Kind: state.OpAddrRemove, Iface: n, Dev: it.Device, Addr: it.SourceIP})
		if err := e.save(); err != nil {
			errs = append(errs, err)
			continue
		}
		done = append(done, n)
	}
	// Groups without interfaces and not in the config lose their saved selection.
	for gname := range e.st.Groups {
		if _, inCfg := e.Cfg.Groups[gname]; inCfg {
			continue
		}
		used := false
		for _, it := range e.st.Interfaces {
			if it.Group == gname {
				used = true
			}
		}
		if !used {
			delete(e.st.Groups, gname)
		}
	}
	if err := e.save(); err != nil {
		errs = append(errs, err)
	}
	if len(done) > 0 {
		if err := e.syncNetplan(ctx, nil, false); err != nil {
			errs = append(errs, fmt.Errorf("netplan after prune: %w", err))
			return errors.Join(errs...) // addr and cert ops stay in the journal
		}
	}
	for _, op := range append([]*state.Op(nil), e.st.Pending...) {
		switch op.Kind {
		case state.OpAddrRemove:
			if err := e.runAddrRemove(ctx, op); err != nil {
				errs = append(errs, err)
			}
		case state.OpCertRevoke:
			_ = e.runRevoke(ctx, op) // a failure stays in the journal
		}
	}
	return errors.Join(errs...)
}
