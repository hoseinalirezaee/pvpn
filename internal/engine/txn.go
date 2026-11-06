package engine

import (
	"context"
	"errors"
	"fmt"
	"net/netip"
	"os"
	"path/filepath"
	"time"

	"pvpn/internal/render"
	"pvpn/internal/state"
)

// ---- backups of WireGuard files ----

func (e *Engine) backupConf(name, opID string) (string, error) {
	text, err := e.Sys.ReadWG(name)
	if errors.Is(err, os.ErrNotExist) {
		return "", nil
	}
	if err != nil {
		return "", err
	}
	dir := e.Store.BackupDir()
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return "", err
	}
	p := filepath.Join(dir, name+".conf."+opID)
	if err := state.WriteFileAtomic(p, []byte(text), 0o600); err != nil {
		return "", err
	}
	return p, nil
}

func removeBackups(t *state.Txn) {
	for _, m := range t.Members {
		if m.Backup != "" {
			_ = os.Remove(m.Backup)
		}
	}
}

// ---- generic group transaction: renew one member, or replace the server of a group ----

// groupTxn gives members new keys and certificates. With newG it also moves them to a new server.
// Source addresses and routing identifiers stay the same.
//
// Order: prepare certificates, stop every old member, write the new files, start the members,
// validate each, then commit the state. Any failure before the commit rolls back to the old server.
func (e *Engine) groupTxn(ctx context.Context, kind, gname string, newG *state.Group, members []string) error {
	cur := e.st.Groups[gname]
	target := cur
	t := &state.Txn{Kind: kind, Phase: state.TxnPrepared, Group: gname}
	if newG != nil {
		old := *cur
		t.OldGroup, t.NewGroup = &old, newG
		target = newG
	}
	op := e.st.AddOp(&state.Op{Kind: state.OpTxn, Txn: t, Note: kind + " " + gname})
	if err := e.save(); err != nil {
		return err
	}
	for _, m := range members {
		old := *e.st.Interfaces[m]
		active, _ := e.Sys.UnitActive(ctx, m)
		backup, err := e.backupConf(m, op.ID)
		if err != nil {
			return e.abortTxn(ctx, op, err)
		}
		is, err := e.issueCert(ctx, m, target)
		if err != nil {
			return e.abortTxn(ctx, op, err)
		}
		nw := old
		nw.CertSerial, nw.CertName, nw.WGPublicKey = is.cert.Serial, is.name, is.cred.WGPublic
		nw.CertExpires, nw.CertRefresh = is.cert.Expiration, is.cert.Refresh
		nw.Phase = state.PhaseReady
		nw.ValidatedAt = time.Time{}
		t.Members = append(t.Members, state.TxnMember{Iface: m, Old: old, New: nw, WasActive: active, Backup: backup})
		e.keys[m] = is.cred.WGPrivate
		e.st.RemoveOp(is.op.ID) // the certificate now belongs to the transaction
		if err := e.save(); err != nil {
			return e.abortTxn(ctx, op, err)
		}
	}

	// The source address, route, and rule must be in place before any unit starts.
	for _, tm := range t.Members {
		m, err := e.member(tm.Iface, &tm.Old)
		if err == nil {
			err = e.checkMember(ctx, tm.Iface, m.Addrs, m)
		}
		if err != nil {
			return e.abortTxn(ctx, op, err)
		}
	}

	t.Phase = state.TxnStaged
	if err := e.save(); err != nil {
		return e.abortTxn(ctx, op, err)
	}
	e.logf("group %s: %s %d member(s)", gname, kind, len(t.Members))
	for _, tm := range t.Members {
		if tm.WasActive {
			if err := e.Sys.UnitStop(ctx, tm.Iface); err != nil {
				return e.abortTxn(ctx, op, fmt.Errorf("stop %s: %w", tm.Iface, err))
			}
		}
	}
	starts := map[string]time.Time{}
	for i := range t.Members {
		tm := &t.Members[i]
		t0, err := e.startMember(ctx, tm.Iface, &tm.New, target, e.keys[tm.Iface])
		if err != nil {
			return e.abortTxn(ctx, op, err)
		}
		starts[tm.Iface] = t0
	}
	for i := range t.Members {
		tm := &t.Members[i]
		if err := e.validateTunnel(ctx, tm.Iface, &tm.New, starts[tm.Iface]); err != nil {
			return e.abortTxn(ctx, op, err)
		}
	}

	if newG != nil {
		e.st.Groups[gname] = newG
	}
	now := e.Clock.Now().UTC()
	for i := range t.Members {
		nn := t.Members[i].New
		nn.Phase, nn.ValidatedAt, nn.AppliedGen = state.PhaseReady, now, e.st.Generation
		e.st.Interfaces[t.Members[i].Iface] = &nn
		delete(e.keys, t.Members[i].Iface)
	}
	t.Phase = state.TxnCommitted
	if err := e.save(); err != nil {
		return err
	}
	return e.finishTxn(ctx, op)
}

// ---- rotation of one interface ----

// precheckRotate checks that an interface can be rotated. It changes nothing.
func (e *Engine) precheckRotate(ctx context.Context, name string) error {
	it := e.st.Interfaces[name]
	if it == nil || e.st.Groups[it.Group] == nil {
		return fmt.Errorf("%s: not managed by pvpn", name)
	}
	if it.Phase != state.PhaseReady {
		return fmt.Errorf("%s: not ready (run `pvpn reconcile` first)", name)
	}
	if ok, err := e.Sys.UnitActive(ctx, name); err != nil {
		return err
	} else if !ok {
		return fmt.Errorf("%s: unit is not running (run `pvpn reconcile` first)", name)
	}
	conf, err := e.Sys.ReadWG(name)
	if err != nil {
		return fmt.Errorf("%s: read WireGuard file: %w (run `pvpn reconcile` first)", name, err)
	}
	if m := render.ParseWG(conf); !m.Managed || m.PrivateKey == "" {
		return fmt.Errorf("%s: WireGuard file is not a pvpn file with a key (run `pvpn reconcile`)", name)
	}
	return nil
}

// rotateMember gives one running interface a new key and certificate. Its source address is newSrc.
// The address and the route are already in place (rotateBatch did that with one netplan apply).
// The server stays the same. The tunnel is updated in place. The caller settles the netplan file.
func (e *Engine) rotateMember(ctx context.Context, name string, newSrc netip.Addr) error {
	it := e.st.Interfaces[name]
	g := e.st.Groups[it.Group]

	t := &state.Txn{Kind: state.TxnRotate, Phase: state.TxnPrepared, Group: it.Group}
	op := e.st.AddOp(&state.Op{Kind: state.OpTxn, Txn: t, Note: "rotate " + name})
	if err := e.save(); err != nil {
		return err
	}
	backup, err := e.backupConf(name, op.ID)
	if err != nil {
		return e.abortTxn(ctx, op, err)
	}
	is, err := e.issueCert(ctx, name, g)
	if err != nil {
		return e.abortTxn(ctx, op, err)
	}
	old := *it
	nw := old
	nw.SourceIP = newSrc.String()
	nw.CertSerial, nw.CertName, nw.WGPublicKey = is.cert.Serial, is.name, is.cred.WGPublic
	nw.CertExpires, nw.CertRefresh = is.cert.Expiration, is.cert.Refresh
	t.Members = []state.TxnMember{{Iface: name, Old: old, New: nw, WasActive: true, Backup: backup}}
	e.st.RemoveOp(is.op.ID)
	if err := e.save(); err != nil {
		return e.abortTxn(ctx, op, err)
	}
	priv := is.cred.WGPrivate

	t.Phase = state.TxnStaged
	if err := e.save(); err != nil {
		return e.abortTxn(ctx, op, err)
	}
	e.logf("%s: rotating (old source %s, new source %s)", name, old.SourceIP, newSrc)

	// New key and a new listen port on the running interface. Then require a fresh handshake and a probe.
	e.warm(ctx, nw.SourceIP, g)
	port, err := e.Sys.FreePort(ctx)
	if err != nil {
		return e.abortTxn(ctx, op, err)
	}
	t0 := e.Clock.Now()
	if err := e.Sys.WGSetKey(ctx, name, priv, port); err != nil {
		return e.abortTxn(ctx, op, err)
	}
	if err := e.validateTunnel(ctx, name, &t.Members[0].New, t0); err != nil {
		return e.abortTxn(ctx, op, err)
	}

	// Commit: new WireGuard file, then new state.
	text, err := e.wgText(name, &t.Members[0].New, g, priv)
	if err != nil {
		return e.abortTxn(ctx, op, err)
	}
	if err := e.Sys.WriteWG(name, text); err != nil {
		return e.abortTxn(ctx, op, err)
	}
	nn := t.Members[0].New
	nn.Phase, nn.ValidatedAt, nn.AppliedGen = state.PhaseReady, e.Clock.Now().UTC(), e.st.Generation
	e.st.Interfaces[name] = &nn
	t.Phase = state.TxnCommitted
	if err := e.save(); err != nil {
		return err
	}
	return e.finishMember(ctx, op)
}

// finishMember revokes the old certificate right after the new tunnel works. This keeps the number of
// sessions at the Proton servers low. The netplan cleanup belongs to the batch (settleBatch).
func (e *Engine) finishMember(ctx context.Context, op *state.Op) error {
	t := op.Txn
	for _, tm := range t.Members {
		if tm.Old.CertSerial != "" && tm.Old.CertSerial != tm.New.CertSerial {
			_ = e.DeleteOwnedCert(ctx, tm.Old.CertSerial) // failure leaves a journal entry
		}
	}
	removeBackups(t)
	e.st.RemoveOp(op.ID)
	return e.save()
}

// ---- finish and rollback ----

// finishTxn runs the cleanup after the commit. It is safe to run more than once.
func (e *Engine) finishTxn(ctx context.Context, op *state.Op) error {
	t := op.Txn
	if t.Kind == state.TxnRotateBatch {
		return e.settleBatch(ctx, op)
	}
	var errs []error
	if t.Kind == state.TxnRotate {
		if err := e.syncNetplan(ctx, nil, false); err != nil {
			errs = append(errs, fmt.Errorf("netplan cleanup after rotation: %w", err))
		}
		for _, tm := range t.Members {
			if tm.Old.SourceIP != tm.New.SourceIP {
				if a, err := netip.ParseAddr(tm.Old.SourceIP); err == nil {
					if err := e.ensureAddrGone(ctx, a); err != nil {
						errs = append(errs, err)
					}
				}
			}
		}
	}
	for _, tm := range t.Members {
		if tm.Old.CertSerial != "" && tm.Old.CertSerial != tm.New.CertSerial {
			_ = e.DeleteOwnedCert(ctx, tm.Old.CertSerial) // failure leaves a journal entry
		}
	}
	if len(errs) > 0 {
		return joinErrs(errs) // keep the transaction op: the next command repeats the cleanup
	}
	removeBackups(t)
	e.st.RemoveOp(op.ID)
	return e.save()
}

// abortTxn rolls back and returns the original error. A failed rollback stays in the journal.
func (e *Engine) abortTxn(ctx context.Context, op *state.Op, cause error) error {
	if rerr := e.rollbackTxn(context.WithoutCancel(ctx), op); rerr != nil {
		return fmt.Errorf("%w (rollback incomplete, pending in the journal: %v)", cause, rerr)
	}
	return cause
}

// rollbackTxn returns the host to the state before the transaction.
// It removes only the resources that this transaction made.
func (e *Engine) rollbackTxn(ctx context.Context, op *state.Op) error {
	t := op.Txn
	if t.Kind == state.TxnRotateBatch {
		return e.settleBatch(ctx, op) // the state decides which addresses stay
	}
	var errs []error
	if t.Phase != state.TxnPrepared {
		switch t.Kind {
		case state.TxnRotate:
			errs = append(errs, e.rollbackRotate(ctx, t)...)
		default:
			errs = append(errs, e.rollbackGroup(ctx, t)...)
		}
	}
	if len(errs) > 0 {
		return joinErrs(errs)
	}
	for _, tm := range t.Members {
		delete(e.keys, tm.Iface)
		if tm.New.CertSerial != "" && tm.New.CertSerial != tm.Old.CertSerial {
			_ = e.DeleteOwnedCert(ctx, tm.New.CertSerial)
		}
	}
	removeBackups(t)
	e.st.RemoveOp(op.ID)
	return e.save()
}

func (e *Engine) rollbackRotate(ctx context.Context, t *state.Txn) []error {
	var errs []error
	if err := e.syncNetplan(ctx, nil, false); err != nil { // state still has the old address and route
		errs = append(errs, fmt.Errorf("restore netplan: %w", err))
	}
	for _, tm := range t.Members {
		// Old key and old file.
		if tm.Backup != "" {
			if b, err := os.ReadFile(tm.Backup); err == nil {
				meta := render.ParseWG(string(b))
				if st, err := e.Sys.WGStatus(ctx, tm.Iface); err == nil && st.Exists && st.PublicKey == tm.New.WGPublicKey && meta.PrivateKey != "" {
					if err := e.Sys.WGSetKey(ctx, tm.Iface, meta.PrivateKey, 0); err != nil {
						errs = append(errs, fmt.Errorf("restore key of %s: %w", tm.Iface, err))
					}
				}
				if err := e.Sys.WriteWG(tm.Iface, string(b)); err != nil {
					errs = append(errs, err)
				}
			}
		}
		if tm.New.SourceIP != tm.Old.SourceIP {
			if a, err := netip.ParseAddr(tm.New.SourceIP); err == nil {
				if err := e.ensureAddrGone(ctx, a); err != nil {
					errs = append(errs, err)
				}
			}
		}
	}
	return errs
}

func (e *Engine) rollbackGroup(ctx context.Context, t *state.Txn) []error {
	var errs []error
	for _, tm := range t.Members {
		_ = e.Sys.UnitStop(ctx, tm.Iface)
	}
	for _, tm := range t.Members {
		if tm.Backup != "" {
			b, err := os.ReadFile(tm.Backup)
			if err != nil {
				errs = append(errs, err)
				continue
			}
			if err := e.Sys.WriteWG(tm.Iface, string(b)); err != nil {
				errs = append(errs, err)
			}
		} else if err := e.Sys.RemoveWG(tm.Iface); err != nil {
			errs = append(errs, err)
		}
		if tm.WasActive && tm.Backup != "" {
			if err := e.Sys.UnitStart(ctx, tm.Iface); err != nil {
				errs = append(errs, fmt.Errorf("restart old %s: %w", tm.Iface, err))
			}
		}
	}
	return errs
}
