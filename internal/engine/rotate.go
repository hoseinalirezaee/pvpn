package engine

import (
	"context"
	"errors"
	"fmt"
)

// RotateSel selects what to rotate. Group and Interface exclude each other. Empty means all.
type RotateSel struct {
	Group     string
	Interface string
}

// Rotate gives interfaces a new key, certificate, and source address, one after another.
// It stops at the first failure. The caller holds the exclusive state lock.
func (e *Engine) Rotate(ctx context.Context, sel RotateSel) error {
	if sel.Group != "" && sel.Interface != "" {
		return errors.New("--group and --interface cannot be used together")
	}
	if e.st == nil {
		if err := e.Load(); err != nil {
			return err
		}
	}
	var names []string
	switch {
	case sel.Interface != "":
		if _, ok := e.Cfg.GroupOf(sel.Interface); !ok {
			return fmt.Errorf("interface %q is not in the config", sel.Interface)
		}
		if _, ok := e.st.Interfaces[sel.Interface]; !ok {
			return fmt.Errorf("interface %q does not exist yet; run `pvpn reconcile`", sel.Interface)
		}
		names = []string{sel.Interface}
	case sel.Group != "":
		gc, ok := e.Cfg.Groups[sel.Group]
		if !ok {
			return fmt.Errorf("group %q is not in the config", sel.Group)
		}
		for _, n := range gc.Interfaces {
			if _, ok := e.st.Interfaces[n]; ok {
				names = append(names, n)
			}
		}
	default:
		names = e.orderedInterfaces()
	}
	if err := e.Recover(ctx); err != nil {
		return fmt.Errorf("recovery of earlier operations failed: %w", err)
	}
	if len(names) == 0 {
		return errors.New("no managed interface to rotate; run `pvpn reconcile` first")
	}
	for _, n := range names {
		if err := e.rotateMember(ctx, n); err != nil {
			return fmt.Errorf("rotation stopped at %s: %w", n, err)
		}
		e.logf("%s: rotated", n)
	}
	return nil
}
