package state

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestSaveLoadRoundTripModes(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "pvpn")
	s, err := Open(dir, true)
	if err != nil {
		t.Fatal(err)
	}
	if fi, _ := os.Stat(dir); fi.Mode().Perm() != 0o700 {
		t.Fatalf("dir mode %o", fi.Mode().Perm())
	}
	st, err := s.Load()
	if err != nil || st.Version != Version || len(st.Interfaces) != 0 {
		t.Fatalf("empty load: %+v %v", st, err)
	}
	st.Generation = 3
	st.Groups["g"] = &Group{Logical: "DE#1", Domain: "node-de-1.protonvpn.net"}
	st.Interfaces["i1"] = &Interface{Group: "g", Table: 5751, Mark: 0x5751, Priority: 101, SourceIP: "2001:db8::1", CertSerial: "S1"}
	st.AddOp(&Op{Kind: OpCertRevoke, Serial: "S0"})
	if err := s.Save(st); err != nil {
		t.Fatal(err)
	}
	fi, err := os.Stat(s.StatePath())
	if err != nil || fi.Mode().Perm() != 0o600 {
		t.Fatalf("file mode: %v %v", fi, err)
	}
	got, err := s.Load()
	if err != nil {
		t.Fatal(err)
	}
	if got.Generation != 3 || got.Interfaces["i1"].Table != 5751 || got.Groups["g"].Logical != "DE#1" || len(got.Pending) != 1 {
		t.Fatalf("round trip lost data: %+v", got)
	}
	ents, _ := os.ReadDir(dir)
	for _, e := range ents {
		if strings.HasSuffix(e.Name(), ".tmp") {
			t.Fatalf("temp file left: %s", e.Name())
		}
	}
}

func TestLoadRejectsNewerAndDamaged(t *testing.T) {
	dir := t.TempDir()
	s, _ := Open(dir, true)
	_ = os.WriteFile(s.StatePath(), []byte(`{"version": 99}`), 0o600)
	if _, err := s.Load(); err == nil || !strings.Contains(err.Error(), "newer") {
		t.Fatalf("want newer error, got %v", err)
	}
	_ = os.WriteFile(s.StatePath(), []byte(`{not json`), 0o600)
	if _, err := s.Load(); err == nil || !strings.Contains(err.Error(), "damaged") {
		t.Fatalf("want damaged error, got %v", err)
	}
	_ = os.WriteFile(s.StatePath(), []byte(`{}`), 0o600)
	if _, err := s.Load(); err == nil {
		t.Fatal("want error for missing version")
	}
}

func TestLockExclusion(t *testing.T) {
	dir := t.TempDir()
	a, _ := Open(dir, true)
	b, _ := Open(dir, true)
	if err := a.Lock(true); err != nil {
		t.Fatal(err)
	}
	if err := b.Lock(true); err != ErrLocked {
		t.Fatalf("exclusive while exclusive: %v", err)
	}
	if err := b.Lock(false); err != ErrLocked {
		t.Fatalf("shared while exclusive: %v", err)
	}
	a.Unlock()
	if err := b.Lock(false); err != nil {
		t.Fatalf("shared after unlock: %v", err)
	}
	c, _ := Open(dir, true)
	if err := c.Lock(false); err != nil {
		t.Fatalf("two shared locks: %v", err)
	}
	if err := a.Lock(true); err != ErrLocked {
		t.Fatalf("exclusive while shared: %v", err)
	}
	b.Unlock()
	c.Unlock()
}

func TestSharedLockOnMissingDir(t *testing.T) {
	s, _ := Open(filepath.Join(t.TempDir(), "none"), false)
	if err := s.Lock(false); err != nil {
		t.Fatal(err)
	}
	if st, err := s.Load(); err != nil || len(st.Interfaces) != 0 {
		t.Fatalf("%v %v", st, err)
	}
	if _, err := os.Stat(s.Dir); err == nil {
		t.Fatal("read-only open created the directory")
	}
}

func TestOwnsSerial(t *testing.T) {
	st := newState()
	st.Interfaces["a"] = &Interface{CertSerial: "S1"}
	st.AddOp(&Op{Kind: OpCertRevoke, Serial: "S2"})
	st.AddOp(&Op{Kind: OpTxn, Txn: &Txn{Members: []TxnMember{{Old: Interface{CertSerial: "S3"}, New: Interface{CertSerial: "S4"}}}}})
	for _, s := range []string{"S1", "S2", "S3", "S4"} {
		if !st.OwnsSerial(s) {
			t.Errorf("should own %s", s)
		}
	}
	if st.OwnsSerial("S9") || st.OwnsSerial("") {
		t.Error("should not own S9 or empty")
	}
}

func TestOpHelpers(t *testing.T) {
	st := newState()
	a := st.AddOp(&Op{Kind: OpFileRemove, Path: "/x"})
	b := st.AddOp(&Op{Kind: OpFileRemove, Path: "/y"})
	if a.ID == "" || a.ID == b.ID || len(st.Pending) != 2 {
		t.Fatalf("ops: %+v %+v", a, b)
	}
	st.RemoveOp(a.ID)
	if len(st.Pending) != 1 || st.Pending[0].ID != b.ID {
		t.Fatalf("remove failed: %+v", st.Pending)
	}
}
