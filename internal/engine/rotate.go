package engine

import (
	"context"
	"errors"
	"fmt"

	"pvpn/internal/proton"
	"pvpn/internal/selector"
	"pvpn/internal/state"
)

// RotateSel selects what to rotate. Group and Interface exclude each other. Empty means all.
// By default a rotation gives each member a new key and certificate and keeps its source IP.
// With NewIP, the members also get a new source IP.
// With NewServer, each selected group also moves to another server. NewServer and Interface exclude each other.
// A group move gives new keys and certificates, so NewServer without NewIP rotates nothing more.
type RotateSel struct {
	Group     string
	Interface string
	NewIP     bool
	NewServer bool
}

// rotation is one group and the members to rotate.
type rotation struct {
	group   string
	members []string
}

// Rotate gives interfaces a new key and certificate. With sel.NewIP it also gives them a new source address.
// With sel.NewServer, each group first moves to another server of the same filters.
// It stops at the first failure. The caller holds the exclusive state lock.
func (e *Engine) Rotate(ctx context.Context, sel RotateSel) error {
	if sel.Group != "" && sel.Interface != "" {
		return errors.New("--group and --interface cannot be used together")
	}
	if sel.NewServer && sel.Interface != "" {
		return errors.New("--new-server cannot be used with --interface (a server belongs to a group)")
	}
	if e.st == nil {
		if err := e.Load(); err != nil {
			return err
		}
	}
	var plan []rotation
	switch {
	case sel.Interface != "":
		gname, ok := e.Cfg.GroupOf(sel.Interface)
		if !ok {
			return fmt.Errorf("interface %q is not in the config", sel.Interface)
		}
		if _, ok := e.st.Interfaces[sel.Interface]; !ok {
			return fmt.Errorf("interface %q does not exist yet; run `pvpn reconcile`", sel.Interface)
		}
		plan = []rotation{{gname, []string{sel.Interface}}}
	case sel.Group != "":
		if _, ok := e.Cfg.Groups[sel.Group]; !ok {
			return fmt.Errorf("group %q is not in the config", sel.Group)
		}
		plan = e.rotations([]string{sel.Group})
	default:
		plan = e.rotations(e.Cfg.GroupNames())
	}
	if err := e.Recover(ctx); err != nil {
		return fmt.Errorf("recovery of earlier operations failed: %w", err)
	}
	if len(plan) == 0 {
		return errors.New("no managed interface to rotate; run `pvpn reconcile` first")
	}

	var logicals []proton.Logical
	var maxTier int
	if sel.NewServer {
		info, err := e.API.Info(ctx)
		if err != nil {
			return err
		}
		maxTier = info.MaxTier
		if logicals, err = e.API.Logicals(ctx); err != nil {
			return err
		}
	}
	for _, r := range plan {
		moved := ""
		if sel.NewServer {
			name, err := e.moveGroup(ctx, r, logicals, maxTier)
			if err != nil {
				return fmt.Errorf("group %s: %w", r.group, err)
			}
			moved = name
		}
		if sel.NewServer && !sel.NewIP {
			continue // the group move already gave every member a new key and certificate
		}
		if err := e.rotateBatch(ctx, r.group, r.members, sel.NewIP); err != nil {
			var rs *rotateStop
			if moved != "" && errors.As(err, &rs) {
				return fmt.Errorf("rotation stopped at %s (group %s is already on the new server %s; run `pvpn rotate --group %s` again): %w", rs.iface, r.group, moved, r.group, rs.err)
			}
			return err
		}
	}
	return nil
}

// rotations lists the groups with the members that exist in the state, in config order.
func (e *Engine) rotations(groups []string) []rotation {
	var out []rotation
	for _, g := range groups {
		r := rotation{group: g}
		for _, n := range e.Cfg.Groups[g].Interfaces {
			if _, ok := e.st.Interfaces[n]; ok {
				r.members = append(r.members, n)
			}
		}
		if len(r.members) > 0 {
			out = append(out, r)
		}
	}
	return out
}

// moveGroup moves a group to another logical server that passes the group filters, including max_load.
// All members get new keys and certificates and keep their source addresses. It returns the name of the new server.
// When no other server matches, it stops before any change.
func (e *Engine) moveGroup(ctx context.Context, r rotation, logicals []proton.Logical, maxTier int) (string, error) {
	cur := e.st.Groups[r.group]
	if cur == nil {
		return "", errors.New("the group has no saved server; run `pvpn reconcile` first")
	}
	f := selector.FromConfig(e.Cfg.Groups[r.group].Server, maxTier)
	cands, funnel := selector.Match(logicals, f, false)
	cands = selector.Without(cands, cur.Logical)
	if len(cands) == 0 {
		funnel = append(funnel, selector.Stage{Name: "other than " + cur.Logical, Left: 0})
		return "", &selector.NoCandidatesError{Funnel: funnel}
	}
	c, err := selector.Choose(cands, e.Cfg.Groups[r.group].Server.Select, e.rnd())
	if err != nil {
		return "", err
	}
	g := selector.ToGroup(c)
	g.SelectedAt = e.Clock.Now().UTC()
	e.logf("group %s: moving from %s to %s on %s", r.group, cur.Logical, g.Logical, g.Domain)
	if err := e.groupTxn(ctx, state.TxnReplace, r.group, &g, r.members); err != nil {
		return "", err
	}
	return g.Logical, nil
}
