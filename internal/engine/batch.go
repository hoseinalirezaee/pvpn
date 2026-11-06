package engine

import (
	"context"
	"fmt"
	"net/netip"

	"pvpn/internal/host"
	"pvpn/internal/state"
)

// rotateStop reports the interface at which a rotation stopped.
type rotateStop struct {
	iface string
	err   error
}

func (s *rotateStop) Error() string { return fmt.Sprintf("rotation stopped at %s: %v", s.iface, s.err) }
func (s *rotateStop) Unwrap() error { return s.err }

// rotateBatch rotates the members of one group (or one interface).
//
//  1. Check every member. A problem stops everything before any change.
//  2. One netplan apply adds all new addresses and switches all routes to them. The old addresses stay.
//     The apply waits until every address is active (the kernel checks them in parallel).
//  3. Warm all new sources at once.
//  4. Rotate the members one after another: new key, certificate, handshake, probe, new file and state,
//     and the old certificate is revoked at once.
//  5. One netplan apply removes the old addresses (settleBatch).
//
// It stops at the first failure. Members before it stay rotated. The failed member and the members after it
// keep their old key, address, and route.
func (e *Engine) rotateBatch(ctx context.Context, group string, names []string) error {
	for _, n := range names {
		if err := e.precheckRotate(ctx, n); err != nil {
			return &rotateStop{n, err}
		}
	}

	t := &state.Txn{Kind: state.TxnRotateBatch, Phase: state.TxnPrepared, Group: group}
	srcs := map[string]netip.Addr{}
	var picked []netip.Addr
	for _, n := range names {
		a, err := e.newSource(ctx, picked...)
		if err != nil {
			return err
		}
		picked = append(picked, a)
		srcs[n] = a
		old := *e.st.Interfaces[n]
		nw := old
		nw.SourceIP = a.String()
		t.Members = append(t.Members, state.TxnMember{Iface: n, Old: old, New: nw})
	}
	op := e.st.AddOp(&state.Op{Kind: state.OpTxn, Txn: t, Note: "rotate batch " + group})
	if err := e.save(); err != nil {
		return err
	}
	t.Phase = state.TxnStaged
	if err := e.save(); err != nil {
		return e.settleAfter(ctx, op, err)
	}
	e.logf("group %s: rotating %d member(s)", group, len(names))

	// One apply for all new addresses and routes.
	ov := map[string]override{}
	for _, tm := range t.Members {
		oldA, err := netip.ParseAddr(tm.Old.SourceIP)
		if err != nil {
			return e.settleAfter(ctx, op, fmt.Errorf("%s: bad saved source address", tm.Iface))
		}
		ov[tm.Iface] = override{addrs: []netip.Addr{oldA, srcs[tm.Iface]}, from: srcs[tm.Iface]}
	}
	if err := e.syncNetplan(ctx, ov, true); err != nil {
		return e.settleAfter(ctx, op, err)
	}
	for i := range t.Members {
		tm := &t.Members[i]
		m, err := e.member(tm.Iface, &tm.Old)
		if err == nil {
			m.Addrs, m.From = ov[tm.Iface].addrs, srcs[tm.Iface]
			err = e.checkMember(ctx, tm.Iface, m.Addrs, m)
		}
		if err != nil {
			return e.settleAfter(ctx, op, err)
		}
	}

	// Warm all new sources at once.
	var pairs []host.WarmPair
	for _, tm := range t.Members {
		g := e.st.Groups[tm.Old.Group]
		if d, err := netip.ParseAddr(g.EntryIPv6); err == nil {
			pairs = append(pairs, host.WarmPair{Src: srcs[tm.Iface], Dst: d})
		}
	}
	if err := e.Sys.WarmSources(ctx, pairs); err != nil {
		e.logf("warning: warm-up failed: %v", err)
	}

	for _, n := range names {
		if err := e.rotateMember(ctx, n, srcs[n]); err != nil {
			return e.settleAfter(ctx, op, &rotateStop{n, err})
		}
		e.logf("%s: rotated", n)
	}
	return e.settleBatch(ctx, op)
}

// settleAfter settles the batch after a failure and returns the original error.
func (e *Engine) settleAfter(ctx context.Context, op *state.Op, cause error) error {
	if serr := e.settleBatch(context.WithoutCancel(ctx), op); serr != nil {
		return fmt.Errorf("%w (cleanup incomplete, pending in the journal: %v)", cause, serr)
	}
	return cause
}

// settleBatch makes the host match the state. It renders the netplan file from the state (one apply)
// and removes every address of the batch that no interface owns. It is safe to run again.
func (e *Engine) settleBatch(ctx context.Context, op *state.Op) error {
	t := op.Txn
	t.Phase = state.TxnCommitted // from now on the addresses of this batch no longer count as "in use"
	if err := e.save(); err != nil {
		return err
	}
	var errs []error
	if err := e.syncNetplan(ctx, nil, false); err != nil {
		errs = append(errs, fmt.Errorf("netplan after rotation: %w", err))
	}
	for _, tm := range t.Members {
		for _, s := range []string{tm.Old.SourceIP, tm.New.SourceIP} {
			if a, err := netip.ParseAddr(s); err == nil {
				if err := e.ensureAddrGone(ctx, a); err != nil {
					errs = append(errs, err)
				}
			}
		}
	}
	if len(errs) > 0 {
		return joinErrs(errs) // keep the op: the next command repeats the cleanup
	}
	e.st.RemoveOp(op.ID)
	return e.save()
}
