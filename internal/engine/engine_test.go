package engine

import (
	"context"
	"errors"
	"fmt"
	"net/netip"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"testing"
	"time"

	"pvpn/internal/alloc"
	"pvpn/internal/proton"
	"pvpn/internal/render"
	"pvpn/internal/state"
)

// assertConsistent checks the invariants that hold after any complete command.
func (w *world) assertConsistent() {
	w.t.Helper()
	t, s := w.t, w.s
	st := w.loadState()
	if len(st.Pending) != 0 {
		t.Errorf("pending journal operations: %+v", st.Pending)
	}
	owned := map[string]bool{}
	tables, marks, prios, srcs := map[int]string{}, map[int]string{}, map[int]string{}, map[string]string{}
	keys := map[string]string{}
	for _, n := range st.InterfaceNames() {
		it := st.Interfaces[n]
		g := st.Groups[it.Group]
		if g == nil {
			t.Errorf("%s: group %s has no saved server", n, it.Group)
			continue
		}
		owned[it.CertSerial] = true
		if prev, dup := tables[it.Table]; dup {
			t.Errorf("table %d used by %s and %s", it.Table, prev, n)
		}
		tables[it.Table], marks[it.Mark], prios[it.Priority], srcs[it.SourceIP] = n, n, n, n
		cert := s.certs[it.CertSerial]
		if cert == nil {
			t.Errorf("%s: certificate %s does not exist at the API", n, it.CertSerial)
		} else if cert.WGPub != it.WGPublicKey || cert.Peer != g.Logical || cert.Label != g.Label {
			t.Errorf("%s: certificate does not match the saved key or server: %+v", n, cert)
		}
		conf, ok := s.wg[n]
		if !ok {
			t.Errorf("%s: WireGuard file missing", n)
			continue
		}
		meta := render.ParseWG(conf)
		pub, _ := proton.PublicFromPrivate(meta.PrivateKey)
		switch {
		case !meta.Managed:
			t.Errorf("%s: file is not marked as managed", n)
		case pub != it.WGPublicKey:
			t.Errorf("%s: file key does not match the saved public key", n)
		case meta.PeerKey != g.PublicKey || meta.Endpoint != "["+g.EntryIPv6+"]:51820":
			t.Errorf("%s: peer in file (%s %s) is not the group server (%s %s)", n, meta.PeerKey, meta.Endpoint, g.PublicKey, g.EntryIPv6)
		case !strings.Contains(conf, "PreUp = ip -6 addr change "+it.SourceIP+"/128 dev eth0 noprefixroute preferred_lft 0\n"):
			t.Errorf("%s: PreUp line is wrong:\n%s", n, conf)
		}
		if prev, dup := keys[meta.PrivateKey]; dup {
			t.Errorf("%s and %s share a private key", prev, n)
		}
		keys[meta.PrivateKey] = n
		if u := s.units[n]; u == nil || !u.active || !u.enabled {
			t.Errorf("%s: unit is not active and enabled: %+v", n, u)
		}
		if !s.dropins[n] {
			t.Errorf("%s: no drop-in", n)
		}
		if l := s.links[n]; l == nil {
			t.Errorf("%s: no live interface", n)
		} else {
			wgs, _ := s.WGStatus(context.Background(), n)
			if l.pub != it.WGPublicKey || wgs.Handshake.IsZero() {
				t.Errorf("%s: live key or handshake wrong: %+v", n, l)
			}
		}
		src := netip.MustParseAddr(it.SourceIP)
		if a := s.addrs[src]; a == nil || !a.noPrefixRoute || !a.deprecated {
			t.Errorf("%s: source address %s missing or without flags: %+v", n, src, a)
		}
		if s.routes[it.Table] != src {
			t.Errorf("%s: route in table %d has source %v, want %v", n, it.Table, s.routes[it.Table], src)
		}
		if r := s.rules[it.Priority]; r != [2]int{it.Mark, it.Table} {
			t.Errorf("%s: rule %v", n, r)
		}
	}
	for serial, c := range s.certs {
		if !owned[serial] {
			t.Errorf("leaked certificate %s (%s)", serial, c.DeviceName)
		}
	}
	for a, x := range s.addrs {
		if x.fromNetplan && srcs[a.String()] == "" {
			t.Errorf("stray source address %s", a)
		}
	}
	if len(s.routes) != len(st.Interfaces) || len(s.rules) != len(st.Interfaces) {
		t.Errorf("routes/rules %d/%d for %d interfaces", len(s.routes), len(s.rules), len(st.Interfaces))
	}
	for name, text := range s.wg {
		if render.ParseWG(text).Managed && st.Interfaces[name] == nil {
			t.Errorf("managed WireGuard file %s without state", name)
		}
	}
	e := w.engine()
	devs, err := e.devices(context.Background(), nil)
	if err != nil {
		t.Fatal(err)
	}
	if string(render.Netplan(devs)) != string(s.managed) {
		t.Errorf("managed netplan file differs from the state:\n%s\n---\n%s", s.managed, render.Netplan(devs))
	}
}

func (w *world) iface(name string) *state.Interface {
	w.t.Helper()
	it := w.loadState().Interfaces[name]
	if it == nil {
		w.t.Fatalf("interface %s is not in the state", name)
	}
	return it
}

func TestReconcileCreatesEverything(t *testing.T) {
	w := newWorld(t)
	p := w.mustReconcile()
	if got := len(p.Actions); got != 6 { // 2 select + 4 create
		t.Fatalf("actions: %d\n%s", got, p)
	}
	st := w.loadState()
	if len(st.Interfaces) != 4 || len(st.Groups) != 2 {
		t.Fatalf("state: %d interfaces, %d groups", len(st.Interfaces), len(st.Groups))
	}
	if g := st.Groups["germany"]; g.Logical != "DE#1" { // lowest load that passes max_load 70 and p2p
		t.Fatalf("germany selected %s", g.Logical)
	}
	if g := st.Groups["netherlands"]; g.Logical != "NL#1" {
		t.Fatalf("netherlands selected %s", g.Logical)
	}
	// Stable identifiers, in config order, starting at the first values.
	want := map[string]alloc.IDs{
		"pvpn-de1": {Table: 5751, Mark: 0x5751, Priority: 101}, "pvpn-de2": {Table: 5752, Mark: 0x5752, Priority: 102},
		"pvpn-nl1": {Table: 5753, Mark: 0x5753, Priority: 103}, "pvpn-nl2": {Table: 5754, Mark: 0x5754, Priority: 104},
	}
	for n, ids := range want {
		it := st.Interfaces[n]
		if (alloc.IDs{Table: it.Table, Mark: it.Mark, Priority: it.Priority}) != ids {
			t.Errorf("%s ids %+v want %+v", n, it, ids)
		}
	}
	if st.Interfaces["pvpn-de1"].SourceIP == st.Interfaces["pvpn-de2"].SourceIP {
		t.Error("group members share a source address")
	}
	w.assertConsistent()
	// One netplan apply for all four members, before the first unit start.
	if n := w.s.count("NetplanApply"); n != 1 {
		t.Errorf("netplan apply count %d", n)
	}
	if w.s.index("NetplanApply") > w.s.index("UnitStart") {
		t.Error("units started before netplan was applied")
	}
	if w.s.count("CreateCert") != 4 {
		t.Errorf("certificates created: %d", w.s.count("CreateCert"))
	}
	for _, n := range []string{"pvpn-de1", "pvpn-de2"} {
		if !strings.Contains(w.s.wg[n], "# server = DE#1") {
			t.Errorf("%s: file lacks the server comment", n)
		}
	}
}

func TestSecondReconcileDoesNothing(t *testing.T) {
	w := newWorld(t)
	w.mustReconcile()
	gen := w.loadState().Generation
	w.s.calls = nil
	p := w.mustReconcile()
	if !p.Empty() {
		t.Fatalf("second plan is not empty:\n%s", p)
	}
	if n := w.s.mutations(); n != 0 {
		t.Fatalf("second reconcile made %d changes: %v", n, w.s.calls)
	}
	if g := w.loadState().Generation; g != gen {
		t.Fatalf("generation changed %d -> %d without work", gen, g)
	}
	w.assertConsistent()
}

func TestDryRunChangesNothing(t *testing.T) {
	w := newWorld(t)
	e := w.engine()
	p, err := e.Reconcile(context.Background(), true)
	if err != nil {
		t.Fatal(err)
	}
	if len(p.Actions) != 6 {
		t.Fatalf("dry run plan:\n%s", p)
	}
	if n := w.s.mutations(); n != 0 {
		t.Fatalf("dry run made changes: %v", w.s.calls)
	}
	if _, err := os.Stat(filepath.Join(w.dir, "state.json")); err == nil {
		t.Fatal("dry run wrote the state file")
	}
	// After a real run, a dry run with pending work must not recover it.
	w.mustReconcile()
	st := w.loadState()
	st.AddOp(&state.Op{Kind: state.OpCertRevoke, Serial: "SN001"})
	store, _ := state.Open(w.dir, false)
	_ = store.Save(st)
	w.s.calls = nil
	p, err = w.engine().Reconcile(context.Background(), true)
	if err != nil || len(p.Warnings) == 0 || w.s.mutations() != 0 {
		t.Fatalf("dry run with pending ops: err=%v warnings=%v calls=%v", err, p.Warnings, w.s.calls)
	}
}

func TestLoadChangeDoesNotMoveGroup(t *testing.T) {
	w := newWorld(t)
	w.mustReconcile()
	w.s.logicals[0].Load = 99 // DE#1 now above max_load 70
	w.s.logicals[1].Load = 1  // DE#2 is far better
	w.s.calls = nil
	p := w.mustReconcile()
	if !p.Empty() || w.s.mutations() != 0 {
		t.Fatalf("a load change must not change anything:\n%s", p)
	}
	if w.loadState().Groups["germany"].Logical != "DE#1" {
		t.Fatal("group moved")
	}
}

func TestAllocationStableWhenConfigOrderChanges(t *testing.T) {
	w := newWorld(t)
	w.mustReconcile()
	before := w.loadState()
	w.setConfig(strings.Replace(testYAML, "[pvpn-de1, pvpn-de2]", "[pvpn-de2, pvpn-de1]", 1))
	w.s.calls = nil
	w.mustReconcile()
	after := w.loadState()
	for n, it := range before.Interfaces {
		a := after.Interfaces[n]
		if a.Table != it.Table || a.Mark != it.Mark || a.Priority != it.Priority || a.SourceIP != it.SourceIP || a.CertSerial != it.CertSerial {
			t.Errorf("%s changed: %+v -> %+v", n, it, a)
		}
	}
	if w.s.mutations() != 0 {
		t.Errorf("reordering made changes: %v", w.s.calls)
	}
}

func TestAllocationSkipsOccupiedValues(t *testing.T) {
	w := newWorld(t)
	used := alloc.NewUsed()
	used.Tables[5751], used.Marks[0x5752], used.Priorities[101] = true, true, true
	w.s.extraUsed = used
	w.mustReconcile()
	it := w.iface("pvpn-de1")
	if it.Table != 5752 || it.Mark != 0x5751 || it.Priority != 102 {
		t.Fatalf("first interface ids: %+v", it)
	}
	w.assertConsistent()
}

func TestSourceAddressesInsideSubnetAndDistinct(t *testing.T) {
	w := newWorld(t)
	w.mustReconcile()
	seen := map[string]bool{}
	for n, it := range w.loadState().Interfaces {
		a := netip.MustParseAddr(it.SourceIP)
		if !w.cfg.Subnets[0].Contains(a) || seen[it.SourceIP] || a == w.cfg.Gateway {
			t.Errorf("%s: bad source %s", n, it.SourceIP)
		}
		seen[it.SourceIP] = true
	}
}

func TestConflictsStopBeforeAnyChange(t *testing.T) {
	cases := []struct {
		name  string
		setup func(w *world)
		want  string
	}{
		{"unmanaged wg file", func(w *world) { w.s.wg["pvpn-nl1"] = "[Interface]\nPrivateKey = x\n" }, "not managed by pvpn"},
		{"managed file without state", func(w *world) { w.s.wg["pvpn-de2"] = render.ManagedHeader + "\n[Interface]\n" }, "state has no such interface"},
		{"live link with that name", func(w *world) { w.s.netlinks["pvpn-de1"] = true }, "already exists"},
		{"managed netplan file with empty state", func(w *world) { w.s.managed = []byte("# managed-by: pvpn\n") }, "state is empty"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			w := newWorld(t)
			tc.setup(w)
			_, err := w.reconcile()
			if err == nil || !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("want error containing %q, got %v", tc.want, err)
			}
			if n := w.s.mutations(); n != 0 {
				t.Fatalf("%d changes before the conflict was reported: %v", n, w.s.calls)
			}
		})
	}
}

func TestUnmanagedFileOfExistingInterfaceStopsReconcile(t *testing.T) {
	w := newWorld(t)
	w.mustReconcile()
	w.s.wg["pvpn-de1"] = "[Interface]\nPrivateKey = hand-written\n"
	w.s.calls = nil
	_, err := w.reconcile()
	if err == nil || !strings.Contains(err.Error(), "not managed by pvpn") || w.s.mutations() != 0 {
		t.Fatalf("err=%v mutations=%d", err, w.s.mutations())
	}
}

func TestNoCandidatesIsClearAndSafe(t *testing.T) {
	w := newWorld(t)
	w.setConfig(strings.Replace(testYAML, "city: Frankfurt", "city: Paris", 1))
	_, err := w.reconcile()
	if err == nil || !strings.Contains(err.Error(), "no server matches the filters") || !strings.Contains(err.Error(), "germany") {
		t.Fatalf("got %v", err)
	}
	if w.s.mutations() != 0 {
		t.Fatalf("changes made: %v", w.s.calls)
	}
}

func TestAccountTierIsEnforced(t *testing.T) {
	w := newWorld(t)
	w.s.maxTier = 1
	_, err := w.reconcile()
	if err == nil || !strings.Contains(err.Error(), "account tier") {
		t.Fatalf("got %v", err)
	}
}

func TestLoginRequiredStopsEverything(t *testing.T) {
	w := newWorld(t)
	w.s.failErr["Info"] = fmt.Errorf("%w (test)", proton.ErrLoginRequired)
	_, err := w.reconcile()
	if !errors.Is(err, proton.ErrLoginRequired) || w.s.mutations() != 0 {
		t.Fatalf("err=%v mutations=%d", err, w.s.mutations())
	}
}

func TestPruneRemovesOnlyManagedThings(t *testing.T) {
	w := newWorld(t)
	w.mustReconcile()
	// Things pvpn does not own.
	w.s.wg["warp"] = "[Interface]\nPrivateKey = keep\n"
	w.s.units["warp"] = &simUnit{active: true, enabled: true}
	w.s.certs["FOREIGN"] = &simCert{Serial: "FOREIGN", DeviceName: "pvpn-pvpn-nl2-cafebabe"} // looks like ours, is not
	w.s.certs["OTHER"] = &simCert{Serial: "OTHER", DeviceName: "laptop"}
	nl2 := w.iface("pvpn-nl2")
	oldAddr := netip.MustParseAddr(nl2.SourceIP)

	w.setConfig(strings.Replace(testYAML, "[pvpn-nl1, pvpn-nl2]", "[pvpn-nl1]", 1))
	w.s.calls = nil
	p := w.mustReconcile()
	if len(p.Actions) != 1 || p.Actions[0].Kind != "prune" {
		t.Fatalf("plan:\n%s", p)
	}
	if _, ok := w.s.wg["pvpn-nl2"]; ok || w.s.units["pvpn-nl2"].active || w.s.units["pvpn-nl2"].enabled || w.s.dropins["pvpn-nl2"] {
		t.Error("pvpn-nl2 not fully removed")
	}
	if _, ok := w.s.addrs[oldAddr]; ok {
		t.Error("source address of pvpn-nl2 still on the device")
	}
	if _, ok := w.s.certs[nl2.CertSerial]; ok {
		t.Error("certificate of pvpn-nl2 not revoked")
	}
	for _, keep := range []string{"FOREIGN", "OTHER"} {
		if w.s.certs[keep] == nil {
			t.Errorf("foreign certificate %s was revoked", keep)
		}
	}
	if w.s.wg["warp"] == "" || !w.s.units["warp"].active {
		t.Error("unmanaged tunnel was touched")
	}
	delete(w.s.certs, "FOREIGN")
	delete(w.s.certs, "OTHER")
	w.assertConsistent()
	if _, ok := w.loadState().Interfaces["pvpn-nl2"]; ok {
		t.Error("state still lists pvpn-nl2")
	}
}

func TestPruneDisabledOnlyWarns(t *testing.T) {
	w := newWorld(t)
	w.mustReconcile()
	w.setConfig(strings.Replace(strings.Replace(testYAML, "prune: true", "prune: false", 1), "[pvpn-nl1, pvpn-nl2]", "[pvpn-nl1]", 1))
	w.s.calls = nil
	p := w.mustReconcile()
	if len(p.Warnings) != 1 || !strings.Contains(p.Warnings[0], "pvpn-nl2") || w.s.mutations() != 0 {
		t.Fatalf("plan:\n%s calls=%v", p, w.s.calls)
	}
}

func TestPruneEverything(t *testing.T) {
	w := newWorld(t)
	w.mustReconcile()
	w.setConfig("version: 1\npaths: {state_dir: STATE}\nreconcile: {prune: true}\ngroups: {}\n")
	w.mustReconcile()
	st := w.loadState()
	if len(st.Interfaces) != 0 || len(st.Groups) != 0 || len(st.Pending) != 0 {
		t.Fatalf("state not empty: %+v", st)
	}
	if w.s.managed != nil || len(w.s.certs) != 0 || len(w.s.wg) != 0 || len(w.s.routes) != 0 || len(w.s.rules) != 0 {
		t.Fatalf("host not clean: managed=%v certs=%d wg=%d", w.s.managed != nil, len(w.s.certs), len(w.s.wg))
	}
	for a, x := range w.s.addrs {
		if x.fromNetplan {
			t.Errorf("source address %s left", a)
		}
	}
	for n, u := range w.s.units {
		if u.active || u.enabled {
			t.Errorf("unit %s left", n)
		}
	}
}

func TestStickyAddressIsDeletedDirectly(t *testing.T) {
	w := newWorld(t)
	w.s.stickyAddr = true // netplan does not remove addresses (older networkd behavior)
	w.mustReconcile()
	w.setConfig(strings.Replace(testYAML, "[pvpn-nl1, pvpn-nl2]", "[pvpn-nl1]", 1))
	w.mustReconcile()
	if w.s.count("DelAddr") != 1 {
		t.Fatalf("expected one direct address delete: %v", w.s.calls)
	}
	w.assertConsistent()
}

func TestNewInterfaceReusesFreedIDs(t *testing.T) {
	w := newWorld(t)
	w.mustReconcile()
	w.setConfig(strings.Replace(testYAML, "[pvpn-nl1, pvpn-nl2]", "[pvpn-nl1]", 1))
	w.mustReconcile()
	w.setConfig(strings.Replace(testYAML, "[pvpn-nl1, pvpn-nl2]", "[pvpn-nl1, pvpn-nl3]", 1))
	w.mustReconcile()
	it := w.iface("pvpn-nl3")
	if it.Table != 5754 || it.Priority != 104 {
		t.Fatalf("pvpn-nl3: %+v", it)
	}
	w.assertConsistent()
}

func TestGroupServerReplacement(t *testing.T) {
	w := newWorld(t)
	w.mustReconcile()
	before := w.loadState()
	oldSerials := map[string]string{}
	for n, it := range before.Interfaces {
		oldSerials[n] = it.CertSerial
	}
	w.setConfig(strings.Replace(testYAML, "city: Frankfurt", "city: Berlin", 1)) // only DE#3 matches
	w.s.calls = nil
	p := w.mustReconcile()
	if len(p.Actions) != 1 || p.Actions[0].Kind != "replace-server" {
		t.Fatalf("plan:\n%s", p)
	}
	st := w.loadState()
	if st.Groups["germany"].Logical != "DE#3" {
		t.Fatalf("group is on %s", st.Groups["germany"].Logical)
	}
	// Every old member stops before any member starts on the new server.
	if w.s.lastIndex("UnitStop") > w.s.index("UnitStart") {
		t.Errorf("a unit started before all old members stopped: %v", w.s.calls)
	}
	if w.s.count("UnitStop") != 2 || w.s.count("UnitStart") != 2 {
		t.Errorf("stops/starts: %v", w.s.calls)
	}
	// Same source addresses and identifiers. New keys and certificates. Old certificates revoked.
	for _, n := range []string{"pvpn-de1", "pvpn-de2"} {
		a, b := before.Interfaces[n], st.Interfaces[n]
		if a.SourceIP != b.SourceIP || a.Table != b.Table || a.Mark != b.Mark || a.Priority != b.Priority {
			t.Errorf("%s: identifiers changed", n)
		}
		if a.CertSerial == b.CertSerial || a.WGPublicKey == b.WGPublicKey {
			t.Errorf("%s: no new key or certificate", n)
		}
		if _, ok := w.s.certs[oldSerials[n]]; ok {
			t.Errorf("%s: old certificate not revoked", n)
		}
	}
	if w.s.count("NetplanApply") != 0 {
		t.Error("a server change must not touch netplan")
	}
	// The other group did not move.
	if st.Interfaces["pvpn-nl1"].CertSerial != before.Interfaces["pvpn-nl1"].CertSerial {
		t.Error("netherlands changed")
	}
	w.assertConsistent()
}

func TestGroupReplacementFailureRollsBack(t *testing.T) {
	w := newWorld(t)
	w.mustReconcile()
	before := w.loadState()
	oldConf := map[string]string{"pvpn-de1": w.s.wg["pvpn-de1"], "pvpn-de2": w.s.wg["pvpn-de2"]}
	w.setConfig(strings.Replace(testYAML, "city: Frankfurt", "city: Berlin", 1))
	w.s.probeFail["pvpn-de2"] = errors.New("probe: no traffic")
	_, err := w.reconcile()
	if err == nil || !strings.Contains(err.Error(), "no traffic") {
		t.Fatalf("got %v", err)
	}
	delete(w.s.probeFail, "pvpn-de2")
	st := w.loadState()
	if st.Groups["germany"].Logical != "DE#1" {
		t.Fatalf("group moved despite the failure: %s", st.Groups["germany"].Logical)
	}
	for n, c := range oldConf {
		if w.s.wg[n] != c {
			t.Errorf("%s: old file not restored", n)
		}
		if st.Interfaces[n].CertSerial != before.Interfaces[n].CertSerial {
			t.Errorf("%s: state changed", n)
		}
	}
	w.assertConsistent() // old tunnels run, old certs live, new certs revoked
}

func TestRotateOneInterface(t *testing.T) {
	w := newWorld(t)
	w.mustReconcile()
	before := w.loadState()
	oldConf := w.s.wg["pvpn-de1"]
	others := map[string]string{}
	for _, n := range []string{"pvpn-de2", "pvpn-nl1", "pvpn-nl2"} {
		others[n] = w.s.wg[n]
	}
	w.s.calls = nil
	if err := w.engine().Rotate(context.Background(), RotateSel{Interface: "pvpn-de1"}); err != nil {
		t.Fatal(err)
	}
	st := w.loadState()
	a, b := before.Interfaces["pvpn-de1"], st.Interfaces["pvpn-de1"]
	if a.SourceIP == b.SourceIP || a.CertSerial == b.CertSerial || a.WGPublicKey == b.WGPublicKey {
		t.Fatalf("not rotated: %+v -> %+v", a, b)
	}
	if a.Table != b.Table || a.Mark != b.Mark || a.Priority != b.Priority {
		t.Error("identifiers must stay")
	}
	if st.Groups["germany"].Logical != before.Groups["germany"].Logical {
		t.Error("rotation changed the server")
	}
	if w.s.wg["pvpn-de1"] == oldConf || !strings.Contains(w.s.wg["pvpn-de1"], b.SourceIP) {
		t.Error("WireGuard file not updated")
	}
	for n, c := range others {
		if w.s.wg[n] != c || st.Interfaces[n].CertSerial != before.Interfaces[n].CertSerial {
			t.Errorf("%s changed", n)
		}
	}
	if _, ok := w.s.addrs[netip.MustParseAddr(a.SourceIP)]; ok {
		t.Error("old address still present")
	}
	if _, ok := w.s.certs[a.CertSerial]; ok {
		t.Error("old certificate not revoked")
	}
	// Order: two netplan applies (candidate, route switch) before the key change, one cleanup after it.
	if n := w.s.count("NetplanApply"); n != 3 {
		t.Errorf("netplan applies: %d", n)
	}
	if w.s.index("WGSetKey") < w.s.index("NetplanApply") || w.s.count("UnitStop")+w.s.count("UnitStart") != 0 {
		t.Errorf("unexpected order or restart: %v", w.s.calls)
	}
	// The old certificate is revoked only after the new tunnel works.
	if w.s.index("DeleteCert") < w.s.index("Probe:pvpn-de1") {
		t.Error("old certificate revoked before validation")
	}
	w.assertConsistent()
}

func TestRotateFailureRestoresEverything(t *testing.T) {
	w := newWorld(t)
	w.mustReconcile()
	before := w.loadState()
	oldConf := w.s.wg["pvpn-de1"]
	oldNetplan := string(w.s.managed)
	w.s.probeFail["pvpn-de1"] = errors.New("probe: no traffic")
	err := w.engine().Rotate(context.Background(), RotateSel{Interface: "pvpn-de1"})
	if err == nil || !strings.Contains(err.Error(), "pvpn-de1") {
		t.Fatalf("got %v", err)
	}
	delete(w.s.probeFail, "pvpn-de1")
	if w.s.wg["pvpn-de1"] != oldConf || string(w.s.managed) != oldNetplan {
		t.Error("old file or netplan content not restored")
	}
	st := w.loadState()
	if st.Interfaces["pvpn-de1"].CertSerial != before.Interfaces["pvpn-de1"].CertSerial || st.Interfaces["pvpn-de1"].SourceIP != before.Interfaces["pvpn-de1"].SourceIP {
		t.Error("state changed")
	}
	if w.s.count("WGSetKey") != 2 { // new key, then the old key back
		t.Errorf("WGSetKey calls: %d", w.s.count("WGSetKey"))
	}
	w.assertConsistent() // old key live, old address and route, no leaked cert or address
}

func TestRotateAllStopsAtFirstFailure(t *testing.T) {
	w := newWorld(t)
	w.mustReconcile()
	before := w.loadState()
	w.s.probeFail["pvpn-de2"] = errors.New("probe: no traffic")
	err := w.engine().Rotate(context.Background(), RotateSel{})
	if err == nil || !strings.Contains(err.Error(), "stopped at pvpn-de2") {
		t.Fatalf("got %v", err)
	}
	delete(w.s.probeFail, "pvpn-de2")
	st := w.loadState()
	if st.Interfaces["pvpn-de1"].CertSerial == before.Interfaces["pvpn-de1"].CertSerial {
		t.Error("pvpn-de1 (first) should have rotated")
	}
	for _, n := range []string{"pvpn-de2", "pvpn-nl1", "pvpn-nl2"} {
		if st.Interfaces[n].CertSerial != before.Interfaces[n].CertSerial {
			t.Errorf("%s changed after the failure", n)
		}
	}
	w.assertConsistent()
}

func TestRotateAddressFailureLeavesOldConfigUsable(t *testing.T) {
	cases := map[string]func(w *world, known map[netip.Addr]bool){
		"duplicate address": func(w *world, known map[netip.Addr]bool) {
			w.s.dadFn = func(a netip.Addr) bool { return !known[a] && w.cfg.Subnets[0].Contains(a) }
		},
		"address never appears": func(w *world, known map[netip.Addr]bool) { w.s.failures["NetplanApply"] = 1 },
		"tentative forever":     func(w *world, known map[netip.Addr]bool) { w.s.slowTentat = time.Hour },
	}
	for name, inject := range cases {
		t.Run(name, func(t *testing.T) {
			w := newWorld(t)
			w.mustReconcile()
			known := map[netip.Addr]bool{}
			for _, it := range w.loadState().Interfaces {
				known[netip.MustParseAddr(it.SourceIP)] = true
			}
			serial := w.iface("pvpn-nl1").CertSerial
			inject(w, known)
			err := w.engine().Rotate(context.Background(), RotateSel{Interface: "pvpn-nl1"})
			if err == nil {
				t.Fatal("rotation must fail")
			}
			w.s.dadFn, w.s.slowTentat = nil, 2*time.Second
			if w.iface("pvpn-nl1").CertSerial != serial {
				t.Error("state changed")
			}
			w.assertConsistent()
		})
	}
}

func TestRotateValidationDeadlineIs30Seconds(t *testing.T) {
	w := newWorld(t)
	w.mustReconcile()
	w.s.hsPolicy = func(string, int) bool { return false } // the server never answers
	start := w.s.clock.Now()
	err := w.engine().Rotate(context.Background(), RotateSel{Interface: "pvpn-de1"})
	if err == nil || !strings.Contains(err.Error(), "no fresh handshake within 30s") {
		t.Fatalf("got %v", err)
	}
	if el := w.s.clock.Now().Sub(start); el < 30*time.Second || el > 40*time.Second {
		t.Fatalf("validation took %s on the sim clock", el)
	}
	w.s.hsPolicy = nil
	w.assertConsistent()
}

func TestHandshakeRetriesWithNewListenPort(t *testing.T) {
	w := newWorld(t)
	w.mustReconcile()
	w.s.hsPolicy = func(iface string, attempt int) bool { return iface != "pvpn-de1" || attempt >= 2 } // cold start fails twice
	w.s.calls = nil
	if err := w.engine().Rotate(context.Background(), RotateSel{Interface: "pvpn-de1"}); err != nil {
		t.Fatal(err)
	}
	if n := w.s.count("WGSetListenPort"); n != 2 {
		t.Fatalf("new listen ports: %d", n)
	}
	w.assertConsistent()
}

func TestProbeIsBoundToTheInterfaceItChecks(t *testing.T) {
	w := newWorld(t)
	w.mustReconcile()
	// pvpn-de1 gets a handshake but its traffic does not pass. pvpn-de2 is healthy.
	w.s.calls = nil
	w.s.probeFail["pvpn-de1"] = errors.New("probe through pvpn-de1: timeout")
	err := w.engine().Rotate(context.Background(), RotateSel{Interface: "pvpn-de1"})
	if err == nil {
		t.Fatal("another healthy tunnel must not satisfy the check")
	}
	if w.s.count("Probe:pvpn-de2") != 0 {
		t.Error("probe used another interface")
	}
}

func TestRotateSelectors(t *testing.T) {
	w := newWorld(t)
	w.mustReconcile()
	ctx := context.Background()
	if err := w.engine().Rotate(ctx, RotateSel{Group: "germany", Interface: "pvpn-de1"}); err == nil || !strings.Contains(err.Error(), "cannot be used together") {
		t.Errorf("both selectors: %v", err)
	}
	if err := w.engine().Rotate(ctx, RotateSel{Group: "nope"}); err == nil {
		t.Error("unknown group accepted")
	}
	if err := w.engine().Rotate(ctx, RotateSel{Interface: "nope"}); err == nil {
		t.Error("unknown interface accepted")
	}
	before := w.loadState()
	if err := w.engine().Rotate(ctx, RotateSel{Group: "netherlands"}); err != nil {
		t.Fatal(err)
	}
	st := w.loadState()
	for _, n := range []string{"pvpn-nl1", "pvpn-nl2"} {
		if st.Interfaces[n].CertSerial == before.Interfaces[n].CertSerial {
			t.Errorf("%s not rotated", n)
		}
	}
	for _, n := range []string{"pvpn-de1", "pvpn-de2"} {
		if st.Interfaces[n].CertSerial != before.Interfaces[n].CertSerial {
			t.Errorf("%s rotated by a group selector for another group", n)
		}
	}
	// A new interface that does not exist yet cannot be rotated.
	w.setConfig(strings.Replace(testYAML, "[pvpn-nl1, pvpn-nl2]", "[pvpn-nl1, pvpn-nl2, pvpn-nl9]", 1))
	if err := w.engine().Rotate(ctx, RotateSel{Interface: "pvpn-nl9"}); err == nil || !strings.Contains(err.Error(), "does not exist yet") {
		t.Errorf("rotating a missing interface: %v", err)
	}
	w.setConfig(testYAML)
	w.assertConsistent()
}

func TestExpiredCertificateIsReplaced(t *testing.T) {
	w := newWorld(t)
	w.mustReconcile()
	before := w.loadState()
	w.s.clock.now = w.s.clock.now.Add(366 * 24 * time.Hour)
	w.s.calls = nil
	p := w.mustReconcile()
	renews := 0
	for _, a := range p.Actions {
		if a.Kind == "renew" {
			renews++
		}
	}
	if renews != 4 {
		t.Fatalf("plan:\n%s", p)
	}
	st := w.loadState()
	for n, it := range before.Interfaces {
		b := st.Interfaces[n]
		if b.SourceIP != it.SourceIP || b.CertSerial == it.CertSerial || b.WGPublicKey == it.WGPublicKey {
			t.Errorf("%s: source must stay, key and certificate must change: %+v -> %+v", n, it, b)
		}
	}
	if st.Groups["germany"].Logical != before.Groups["germany"].Logical {
		t.Error("server changed")
	}
	if w.s.count("NetplanApply") != 0 {
		t.Error("renewal must not touch netplan")
	}
	w.assertConsistent()
}

func TestMissingFileIsReplacedWithNewCredential(t *testing.T) {
	w := newWorld(t)
	w.mustReconcile()
	before := w.loadState()
	delete(w.s.wg, "pvpn-de1") // the file with the private key is gone
	p := w.mustReconcile()
	if len(p.Actions) != 1 || p.Actions[0].Kind != "renew" {
		t.Fatalf("plan:\n%s", p)
	}
	b := w.iface("pvpn-de1")
	if b.SourceIP != before.Interfaces["pvpn-de1"].SourceIP || b.CertSerial == before.Interfaces["pvpn-de1"].CertSerial {
		t.Errorf("%+v", b)
	}
	w.assertConsistent()
}

func TestDriftIsRepaired(t *testing.T) {
	w := newWorld(t)
	w.mustReconcile()
	it := w.iface("pvpn-nl2")
	src := netip.MustParseAddr(it.SourceIP)
	delete(w.s.addrs, src) // address, route and rule vanished (for example after a manual netplan change)
	delete(w.s.routes, it.Table)
	delete(w.s.rules, it.Priority)
	w.s.units["pvpn-de1"].active = false
	delete(w.s.links, "pvpn-de1")
	w.s.units["pvpn-de2"].enabled = false
	w.s.calls = nil
	p := w.mustReconcile()
	kinds := map[string]bool{}
	for _, a := range p.Actions {
		kinds[a.Iface+":"+a.Kind] = true
	}
	if !kinds["pvpn-nl2:repair"] || !kinds["pvpn-de1:repair"] || !kinds["pvpn-de2:repair"] || len(p.Actions) != 3 {
		t.Fatalf("plan:\n%s", p)
	}
	if w.s.count("NetplanApply") != 1 {
		t.Errorf("netplan applies: %d", w.s.count("NetplanApply"))
	}
	w.assertConsistent()
	if w.iface("pvpn-nl2").CertSerial != it.CertSerial {
		t.Error("repair must keep the credential")
	}
}

func TestForeignCertificatesAreNeverRevoked(t *testing.T) {
	w := newWorld(t)
	w.s.certs["F1"] = &simCert{Serial: "F1", DeviceName: "pvpn-pvpn-de1-00000000"}
	w.s.certs["F2"] = &simCert{Serial: "F2", DeviceName: "laptop"}
	w.mustReconcile()
	if err := w.engine().Rotate(context.Background(), RotateSel{}); err != nil {
		t.Fatal(err)
	}
	w.setConfig("version: 1\npaths: {state_dir: STATE}\nreconcile: {prune: true}\ngroups: {}\n")
	w.mustReconcile()
	if len(w.s.certs) != 2 || w.s.certs["F1"] == nil || w.s.certs["F2"] == nil {
		t.Fatalf("certificates now: %v", sortedKeys(w.s.certs))
	}
}

func TestStatusReport(t *testing.T) {
	w := newWorld(t)
	w.mustReconcile()
	w.s.units["pvpn-de2"].active = false
	delete(w.s.links, "pvpn-de2")
	e := w.engine()
	st := e.State()
	st.AddOp(&state.Op{Kind: state.OpCertRevoke, Serial: "SN999"})
	r, err := e.Status(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if len(r.Groups) != 2 || len(r.Interfaces) != 4 || len(r.Pending) != 1 {
		t.Fatalf("report: %d groups %d interfaces %d pending", len(r.Groups), len(r.Interfaces), len(r.Pending))
	}
	byName := map[string]IfaceStatus{}
	for _, i := range r.Interfaces {
		byName[i.Name] = i
	}
	if i := byName["pvpn-de1"]; !i.Active || i.CertExpires.IsZero() || i.AddrFlags != "noprefixroute deprecated " || len(i.Warnings) != 0 {
		t.Errorf("pvpn-de1: %+v", i)
	}
	if i := byName["pvpn-de2"]; i.Active || len(i.Warnings) == 0 {
		t.Errorf("pvpn-de2 should warn: %+v", i)
	}
	if w.s.mutations() != w.s.mutations() || w.s.count("CreateCert") != 4 {
		t.Error("status changed something")
	}
	// Past the refresh time, status warns.
	w.s.clock.now = w.s.clock.now.Add(300 * 24 * time.Hour)
	r, _ = w.engine().Status(context.Background())
	warned := false
	for _, i := range r.Interfaces {
		for _, x := range i.Warnings {
			if strings.Contains(x, "refresh time") {
				warned = true
			}
		}
	}
	if !warned {
		t.Error("no refresh warning")
	}
}

// ---- crash recovery ----

// convergeAfterCrash restarts the "process" until a run finishes, then checks the invariants.
func (w *world) convergeAfterCrash(final func() error) {
	w.t.Helper()
	w.s.crashAt = 0
	for i := 0; i < 4; i++ {
		if err := final(); err == nil {
			w.assertConsistent()
			return
		} else if i == 3 {
			w.t.Fatalf("no convergence after a crash: %v", err)
		}
	}
}

func runCrashMatrix(t *testing.T, name string, prepare func(w *world), act func(w *world) error, converge func(w *world) error) {
	t.Helper()
	completed := false
	crashPoints := 0
	for crashAt := 1; crashAt < 600 && !completed; crashAt++ {
		w := newWorld(t)
		prepare(w)
		w.s.steps = 0
		w.s.crashAt = crashAt
		crashed := crashRun(func() { _ = act(w) })
		if !crashed {
			completed = true
			w.s.crashAt = 0
			w.assertConsistent()
			continue
		}
		crashPoints++
		func() {
			defer func() {
				if t.Failed() {
					t.Logf("%s: failure after a crash at step %d (calls: %v)", name, crashAt, w.s.calls)
				}
			}()
			w.convergeAfterCrash(func() error { return converge(w) })
		}()
		if t.Failed() {
			return
		}
	}
	if !completed {
		t.Fatalf("%s: the operation never completed within the step limit", name)
	}
	t.Logf("%s: recovered from a crash at each of %d steps", name, crashPoints)
}

func TestCrashDuringFirstReconcile(t *testing.T) {
	rec := func(w *world) error { _, err := w.reconcile(); return err }
	runCrashMatrix(t, "first reconcile", func(w *world) {}, rec, rec)
}

func TestCrashDuringRotation(t *testing.T) {
	runCrashMatrix(t, "rotate", func(w *world) { w.mustReconcile() },
		func(w *world) error { return w.engine().Rotate(context.Background(), RotateSel{Interface: "pvpn-de1"}) },
		func(w *world) error { _, err := w.reconcile(); return err })
}

func TestCrashDuringServerReplacement(t *testing.T) {
	cfg := strings.Replace(testYAML, "city: Frankfurt", "city: Berlin", 1)
	runCrashMatrix(t, "replace", func(w *world) { w.mustReconcile(); w.setConfig(cfg) },
		func(w *world) error { _, err := w.reconcile(); return err },
		func(w *world) error { _, err := w.reconcile(); return err })
}

func TestCrashDuringPrune(t *testing.T) {
	cfg := strings.Replace(testYAML, "[pvpn-nl1, pvpn-nl2]", "[pvpn-nl1]", 1)
	runCrashMatrix(t, "prune", func(w *world) { w.mustReconcile(); w.setConfig(cfg) },
		func(w *world) error { _, err := w.reconcile(); return err },
		func(w *world) error { _, err := w.reconcile(); return err })
}

func TestCrashDuringRenewal(t *testing.T) {
	runCrashMatrix(t, "renew", func(w *world) { w.mustReconcile(); delete(w.s.wg, "pvpn-de2") },
		func(w *world) error { _, err := w.reconcile(); return err },
		func(w *world) error { _, err := w.reconcile(); return err })
}

func TestRecoveryRevokesCertificateOfInterruptedIssue(t *testing.T) {
	w := newWorld(t)
	w.mustReconcile()
	// A certificate was created at the API, but the process died before it stored the serial.
	w.s.certs["SN900"] = &simCert{Serial: "SN900", DeviceName: "pvpn-pvpn-de1-abcd1234"}
	st := w.loadState()
	st.AddOp(&state.Op{Kind: state.OpCertIssue, Iface: "pvpn-de1", DeviceName: "pvpn-pvpn-de1-abcd1234"})
	store, _ := state.Open(w.dir, false)
	_ = store.Save(st)
	w.mustReconcile()
	if w.s.certs["SN900"] != nil {
		t.Fatal("orphan certificate of the journal entry was not revoked")
	}
	w.assertConsistent()
}

func TestRecoveryKeepsRevokeWhenAPIFails(t *testing.T) {
	w := newWorld(t)
	w.mustReconcile()
	st := w.loadState()
	st.AddOp(&state.Op{Kind: state.OpCertRevoke, Serial: "GONE"})
	store, _ := state.Open(w.dir, false)
	_ = store.Save(st)
	w.s.failures["DeleteCert"] = 1
	if _, err := w.reconcile(); err == nil {
		t.Fatal("failed cleanup must be reported")
	}
	if len(w.loadState().Pending) != 1 {
		t.Fatal("the failed revoke must stay in the journal")
	}
	w.mustReconcile() // the next modifying command finishes it
	w.assertConsistent()
}

var _ = sort.Strings

func TestCrashDuringRotationRollback(t *testing.T) {
	runCrashMatrix(t, "rotate rollback", func(w *world) { w.mustReconcile(); w.s.probeFail["pvpn-de1"] = errors.New("probe: no traffic") },
		func(w *world) error { return w.engine().Rotate(context.Background(), RotateSel{Interface: "pvpn-de1"}) },
		func(w *world) error { delete(w.s.probeFail, "pvpn-de1"); _, err := w.reconcile(); return err })
}

func TestCrashDuringReplacementRollback(t *testing.T) {
	cfg := strings.Replace(testYAML, "city: Frankfurt", "city: Berlin", 1)
	runCrashMatrix(t, "replace rollback", func(w *world) {
		w.mustReconcile()
		w.setConfig(cfg)
		w.s.probeFail["pvpn-de2"] = errors.New("probe: no traffic")
	},
		func(w *world) error { _, err := w.reconcile(); return err },
		func(w *world) error {
			delete(w.s.probeFail, "pvpn-de2")
			w.setConfig(testYAML) // back to the old server: the rolled-back state is correct
			_, err := w.reconcile()
			return err
		})
}

// ---- rotate --new-server ----

func TestRotateNewServer(t *testing.T) {
	w := newWorld(t)
	w.mustReconcile()
	before := w.loadState()
	w.s.calls = nil
	if err := w.engine().Rotate(context.Background(), RotateSel{Group: "germany", NewServer: true}); err != nil {
		t.Fatal(err)
	}
	st := w.loadState()
	// DE#1 is the saved server. Only DE#2 passes the filters (DE#3 is in Berlin, DE#4 is above max_load).
	if got := st.Groups["germany"].Logical; got != "DE#2" {
		t.Fatalf("group is on %s, want DE#2", got)
	}
	for _, n := range []string{"pvpn-de1", "pvpn-de2"} {
		a, b := before.Interfaces[n], st.Interfaces[n]
		if a.SourceIP == b.SourceIP || a.CertSerial == b.CertSerial || a.WGPublicKey == b.WGPublicKey {
			t.Errorf("%s: not fully rotated: %+v -> %+v", n, a, b)
		}
		if a.Table != b.Table || a.Mark != b.Mark || a.Priority != b.Priority {
			t.Errorf("%s: identifiers changed", n)
		}
		if _, ok := w.s.addrs[netip.MustParseAddr(a.SourceIP)]; ok {
			t.Errorf("%s: old address still present", n)
		}
		if _, ok := w.s.certs[a.CertSerial]; ok {
			t.Errorf("%s: old certificate not revoked", n)
		}
	}
	// The server change stops every old member before any member starts. The rotation after it works in place.
	if w.s.lastIndex("UnitStop") > w.s.index("UnitStart") {
		t.Errorf("a unit started before all old members stopped: %v", w.s.calls)
	}
	if w.s.count("UnitStop") != 2 || w.s.count("UnitStart") != 2 {
		t.Errorf("stops/starts: %v", w.s.calls)
	}
	if w.s.lastIndex("UnitStart") > w.s.index("NetplanApply") {
		t.Errorf("source rotation must follow the server change: %v", w.s.calls)
	}
	for _, n := range []string{"pvpn-nl1", "pvpn-nl2"} {
		if st.Interfaces[n].CertSerial != before.Interfaces[n].CertSerial {
			t.Errorf("%s changed", n)
		}
	}
	if st.Groups["netherlands"].Logical != before.Groups["netherlands"].Logical {
		t.Error("netherlands moved")
	}
	w.assertConsistent()
	// The next reconcile keeps the new server.
	if p := w.mustReconcile(); !p.Empty() {
		t.Errorf("reconcile after a new-server rotation:\n%s", p)
	}
}

func TestRotateNewServerAllGroups(t *testing.T) {
	w := newWorld(t)
	w.mustReconcile()
	before := w.loadState()
	if err := w.engine().Rotate(context.Background(), RotateSel{NewServer: true}); err != nil {
		t.Fatal(err)
	}
	st := w.loadState()
	for g, want := range map[string]string{"germany": "DE#2", "netherlands": "NL#2"} {
		if got := st.Groups[g].Logical; got != want || got == before.Groups[g].Logical {
			t.Errorf("group %s is on %s (was %s), want %s", g, got, before.Groups[g].Logical, want)
		}
	}
	w.assertConsistent()
}

func TestRotateNewServerNoOtherCandidate(t *testing.T) {
	w := newWorld(t)
	w.mustReconcile()
	before := w.loadState()
	w.setConfig(strings.Replace(testYAML, "max_load: 70", "max_load: 40", 1)) // only DE#1 (load 30) passes
	w.s.calls = nil
	err := w.engine().Rotate(context.Background(), RotateSel{Group: "germany", NewServer: true})
	if err == nil || !strings.Contains(err.Error(), "no server matches") || !strings.Contains(err.Error(), "other than DE#1") {
		t.Fatalf("got %v", err)
	}
	if w.s.count("CreateCert") != 0 || w.s.count("UnitStop") != 0 || w.s.count("NetplanApply") != 0 {
		t.Errorf("the failed lookup changed something: %v", w.s.calls)
	}
	after := w.loadState()
	if after.Generation != before.Generation || after.Groups["germany"].Logical != "DE#1" {
		t.Error("state changed")
	}
	for n, it := range before.Interfaces {
		if after.Interfaces[n].CertSerial != it.CertSerial {
			t.Errorf("%s changed", n)
		}
	}
	w.setConfig(testYAML)
	w.assertConsistent()
}

func TestRotateNewServerFailureRollsBack(t *testing.T) {
	w := newWorld(t)
	w.mustReconcile()
	before := w.loadState()
	oldConf := map[string]string{"pvpn-de1": w.s.wg["pvpn-de1"], "pvpn-de2": w.s.wg["pvpn-de2"]}
	w.s.probeFail["pvpn-de2"] = errors.New("probe: no traffic")
	err := w.engine().Rotate(context.Background(), RotateSel{Group: "germany", NewServer: true})
	if err == nil || !strings.Contains(err.Error(), "no traffic") {
		t.Fatalf("got %v", err)
	}
	delete(w.s.probeFail, "pvpn-de2")
	st := w.loadState()
	if st.Groups["germany"].Logical != "DE#1" {
		t.Fatalf("group moved despite the failure: %s", st.Groups["germany"].Logical)
	}
	for n, c := range oldConf {
		if w.s.wg[n] != c || st.Interfaces[n].CertSerial != before.Interfaces[n].CertSerial || st.Interfaces[n].SourceIP != before.Interfaces[n].SourceIP {
			t.Errorf("%s: not restored", n)
		}
	}
	w.assertConsistent()
}

func TestRotateNewServerRejectsInterface(t *testing.T) {
	w := newWorld(t)
	w.mustReconcile()
	err := w.engine().Rotate(context.Background(), RotateSel{Interface: "pvpn-de1", NewServer: true})
	if err == nil || !strings.Contains(err.Error(), "--new-server cannot be used with --interface") {
		t.Fatalf("got %v", err)
	}
}

func TestCrashDuringNewServerRotation(t *testing.T) {
	runCrashMatrix(t, "rotate --new-server", func(w *world) { w.mustReconcile() },
		func(w *world) error {
			return w.engine().Rotate(context.Background(), RotateSel{Group: "germany", NewServer: true})
		},
		func(w *world) error { _, err := w.reconcile(); return err })
}
