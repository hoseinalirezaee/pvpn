package engine

import (
	"context"
	"fmt"
	"net/netip"
	"time"

	"pvpn/internal/state"
)

// IfaceStatus is the health of one interface.
type IfaceStatus struct {
	Name, Group, Server string
	SourceIP            string
	Table, Mark, Prio   int
	Active, Enabled     bool
	Handshake           time.Duration // age; negative when there was none
	Rx, Tx              int64
	AddrFlags           string
	CertSerial          string
	CertExpires         time.Time
	CertRefresh         time.Time
	Phase               string
	Warnings            []string
}

// PendingStatus is one journal entry.
type PendingStatus struct{ ID, Kind, Detail string }

// GroupStatus is a saved selection.
type GroupStatus struct {
	Name, Logical, Domain, EntryIPv6 string
	SelectedAt                       time.Time
	Members                          []string
}

// Report is the output of status.
type Report struct {
	Groups     []GroupStatus
	Interfaces []IfaceStatus
	Pending    []PendingStatus
	Warnings   []string
}

// Status reads the state and the host. It never calls the API.
func (e *Engine) Status(ctx context.Context) (*Report, error) {
	if e.st == nil {
		if err := e.Load(); err != nil {
			return nil, err
		}
	}
	r := &Report{}
	now := e.Clock.Now()
	for _, gname := range sortedKeys(e.st.Groups) {
		g := e.st.Groups[gname]
		gs := GroupStatus{Name: gname, Logical: g.Logical, Domain: g.Domain, EntryIPv6: g.EntryIPv6, SelectedAt: g.SelectedAt}
		for _, n := range e.st.InterfaceNames() {
			if e.st.Interfaces[n].Group == gname {
				gs.Members = append(gs.Members, n)
			}
		}
		r.Groups = append(r.Groups, gs)
	}
	var addrs map[netip.Addr]string
	if len(e.st.Interfaces) > 0 {
		list, err := e.Sys.ListAddrs(ctx, e.srcDevice())
		if err != nil {
			r.Warnings = append(r.Warnings, "cannot read addresses: "+err.Error())
		}
		addrs = map[netip.Addr]string{}
		for _, a := range list {
			f := ""
			if a.NoPrefixRoute {
				f += "noprefixroute "
			}
			if a.Deprecated {
				f += "deprecated "
			}
			if a.Tentative {
				f += "tentative "
			}
			if a.DADFailed {
				f += "dadfailed "
			}
			addrs[a.Addr] = f
		}
	}
	for _, n := range e.st.InterfaceNames() {
		it := e.st.Interfaces[n]
		s := IfaceStatus{Name: n, Group: it.Group, SourceIP: it.SourceIP, Table: it.Table, Mark: it.Mark, Prio: it.Priority,
			CertSerial: it.CertSerial, Phase: it.Phase, Handshake: -1}
		if g := e.st.Groups[it.Group]; g != nil {
			s.Server = g.Logical + " (" + g.Domain + ")"
		}
		if it.CertExpires > 0 {
			s.CertExpires = time.Unix(it.CertExpires, 0).UTC()
			if now.Unix() >= it.CertExpires {
				s.Warnings = append(s.Warnings, "certificate expired; run `pvpn reconcile`")
			}
		}
		if it.CertRefresh > 0 {
			s.CertRefresh = time.Unix(it.CertRefresh, 0).UTC()
			if now.Unix() >= it.CertRefresh && (it.CertExpires == 0 || now.Unix() < it.CertExpires) {
				s.Warnings = append(s.Warnings, "certificate is past its refresh time; run `pvpn rotate`")
			}
		}
		s.Active, _ = e.Sys.UnitActive(ctx, n)
		s.Enabled, _ = e.Sys.UnitEnabled(ctx, n)
		if !s.Active {
			s.Warnings = append(s.Warnings, "unit is not running")
		}
		if wg, err := e.Sys.WGStatus(ctx, n); err == nil && wg.Exists {
			s.Rx, s.Tx = wg.RxBytes, wg.TxBytes
			if !wg.Handshake.IsZero() {
				s.Handshake = now.Sub(wg.Handshake).Round(time.Second)
				if s.Handshake > 3*time.Minute {
					s.Warnings = append(s.Warnings, "last handshake is older than 3 minutes")
				}
			} else if s.Active {
				s.Warnings = append(s.Warnings, "no handshake yet")
			}
		}
		if a, err := netip.ParseAddr(it.SourceIP); err == nil && addrs != nil {
			f, ok := addrs[a]
			switch {
			case !ok:
				s.AddrFlags = "missing"
				s.Warnings = append(s.Warnings, "source address is missing on "+it.Device)
			default:
				s.AddrFlags = f
			}
		}
		if it.Phase != state.PhaseReady {
			s.Warnings = append(s.Warnings, "not validated yet (phase "+it.Phase+")")
		}
		r.Interfaces = append(r.Interfaces, s)
	}
	for _, op := range e.st.Pending {
		d := op.Iface
		switch op.Kind {
		case state.OpCertRevoke:
			d = "revoke certificate " + op.Serial
		case state.OpCertIssue:
			d = "certificate for " + op.Iface + " (" + op.DeviceName + ")"
		case state.OpAddrRemove:
			d = "remove address " + op.Addr + " on " + op.Dev
		case state.OpTxn:
			if op.Txn != nil {
				d = fmt.Sprintf("%s of group %s, phase %s", op.Txn.Kind, op.Txn.Group, op.Txn.Phase)
			}
		}
		r.Pending = append(r.Pending, PendingStatus{op.ID, op.Kind, d})
	}
	for _, n := range e.Cfg.AllInterfaces() {
		if _, ok := e.st.Interfaces[n]; !ok {
			r.Warnings = append(r.Warnings, n+" is in the config but not created; run `pvpn reconcile`")
		}
	}
	for _, n := range e.st.InterfaceNames() {
		if _, ok := e.Cfg.GroupOf(n); !ok {
			r.Warnings = append(r.Warnings, n+" is not in the config; `pvpn reconcile` prunes it when reconcile.prune is true")
		}
	}
	return r, nil
}
