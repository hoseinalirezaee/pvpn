package engine

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"

	"pvpn/internal/state"
)

// Recover finishes or undoes operations that an earlier command did not complete.
// Every modifying command calls it first.
func (e *Engine) Recover(ctx context.Context) error {
	if len(e.st.Pending) == 0 {
		return nil
	}
	e.logf("recovering %d pending operation(s)", len(e.st.Pending))
	var errs []error

	// 1. Transactions first. They put the state and the host back in a known shape.
	// Member transactions come before the batch that wraps them. The batch removes addresses
	// only after the members have decided which addresses the state owns.
	for _, batch := range []bool{false, true} {
		for _, op := range append([]*state.Op(nil), e.st.Pending...) {
			if op.Kind != state.OpTxn || op.Txn == nil || (op.Txn.Kind == state.TxnRotateBatch) != batch {
				continue
			}
			var err error
			if op.Txn.Phase == state.TxnCommitted {
				err = e.finishTxn(ctx, op)
			} else {
				err = e.rollbackTxn(ctx, op)
			}
			if err != nil {
				errs = append(errs, fmt.Errorf("transaction %s: %w", op.Note, err))
			}
		}
	}
	if len(errs) > 0 {
		return errors.Join(errs...)
	}

	// 2. The netplan file must match the state before addresses are removed.
	if err := e.syncNetplan(ctx, nil, false); err != nil {
		return fmt.Errorf("netplan: %w", err)
	}

	// 3. Single operations.
	for _, op := range append([]*state.Op(nil), e.st.Pending...) {
		var err error
		switch op.Kind {
		case state.OpCertIssue:
			err = e.recoverIssue(ctx, op)
		case state.OpCertRevoke:
			err = e.runRevoke(ctx, op)
		case state.OpAddrRemove:
			err = e.runAddrRemove(ctx, op)
		case state.OpProbeClean:
			_ = e.Sys.ProbeCleanup(ctx, op.Iface, op.Table, op.Priority)
			e.st.RemoveOp(op.ID)
			err = e.save()
		case state.OpFileRemove:
			if op.Path != "" && filepath.Dir(op.Path) == e.Store.BackupDir() {
				_ = os.Remove(op.Path)
			}
			e.st.RemoveOp(op.ID)
			err = e.save()
		case state.OpNetplanSync:
			e.st.RemoveOp(op.ID)
			err = e.save()
		}
		if err != nil {
			errs = append(errs, fmt.Errorf("%s: %w", op.Kind, err))
		}
	}
	// Leftover backup files of finished operations are harmless but removed when no op needs them.
	return errors.Join(errs...)
}

// adopted reports whether an interface or a transaction member uses the certificate.
func (e *Engine) adopted(serial, deviceName string) bool {
	for _, it := range e.st.Interfaces {
		if (serial != "" && it.CertSerial == serial) || (deviceName != "" && it.CertName == deviceName) {
			return true
		}
	}
	for _, op := range e.st.Pending {
		if op.Txn == nil {
			continue
		}
		for _, m := range op.Txn.Members {
			for _, c := range []state.Interface{m.Old, m.New} {
				if (serial != "" && c.CertSerial == serial) || (deviceName != "" && c.CertName == deviceName) {
					return true
				}
			}
		}
	}
	return false
}

// recoverIssue handles a certificate that was issued but never stored in an interface entry.
// It revokes the certificate only when the journal entry names it (by serial or by device name).
func (e *Engine) recoverIssue(ctx context.Context, op *state.Op) error {
	if e.adopted(op.Serial, op.DeviceName) {
		e.st.RemoveOp(op.ID)
		return e.save()
	}
	serial := op.Serial
	if serial == "" {
		list, err := e.API.ListCerts(ctx)
		if err != nil {
			return err
		}
		for _, c := range list {
			if c.DeviceName == op.DeviceName {
				serial = c.Serial
			}
		}
	}
	if serial != "" {
		if err := e.API.DeleteCert(ctx, serial); err != nil {
			return err
		}
	}
	e.st.RemoveOp(op.ID)
	return e.save()
}
