package selector

import (
	"encoding/base64"
	"fmt"
	"strings"
	"testing"

	"pvpn/internal/config"
	"pvpn/internal/proton"
)

var goodKey = base64.StdEncoding.EncodeToString(make([]byte, 32))

func phys(domain string) proton.Physical {
	return proton.Physical{ID: domain, Domain: domain, EntryIP: "1.1.1.1", EntryIPv6: "2001:db8::1", X25519PublicKey: goodKey, Label: "1", Status: 1}
}

func logical(name, cc, city string, tier, feats, load int, servers ...proton.Physical) proton.Logical {
	return proton.Logical{ID: name, Name: name, EntryCountry: cc, ExitCountry: cc, City: city, Tier: tier, Features: feats, Status: 1, Load: load, Servers: servers}
}

func names(c []Candidate) string {
	var out []string
	for _, x := range c {
		out = append(out, x.Logical.Name+"@"+x.Server.Domain)
	}
	return strings.Join(out, ",")
}

func world() []proton.Logical {
	return []proton.Logical{
		logical("DE#1", "DE", "Frankfurt", 2, 4|16, 30, phys("m1")),
		logical("DE#2", "DE", "Frankfurt", 2, 4|16, 80, phys("m1"), phys("m2")),
		logical("DE#3", "DE", "Berlin", 2, 4|16, 10, phys("m3")),
		logical("DE#4", "DE", "Frankfurt", 2, 16, 20, phys("m4")),         // no p2p
		logical("DE#5-TOR", "DE", "Frankfurt", 2, 4|2|16, 20, phys("m5")), // tor
		logical("CH-DE#1", "DE", "Frankfurt", 2, 4|1|16, 20, phys("m6")),  // secure core (exit DE)
		logical("DE#6", "DE", "Frankfurt", 0, 4|16, 5, phys("m7")),        // free tier
		logical("NL#1", "NL", "Amsterdam", 2, 4|16, 5, phys("n1")),
	}
}

func TestMatchCombinedFilters(t *testing.T) {
	f := Filter{Country: "DE", City: "frankfurt", MaxLoad: 70, Require: config.FeatP2P, MaxTier: 2}
	got, _ := Match(world(), f, false)
	// DE#1 ok. DE#2 load 80 too high. DE#3 wrong city. DE#4 no p2p. DE#5-TOR implicit tor exclusion.
	// CH-DE#1 implicit secure-core exclusion. DE#6 passes tier (0 <= 2) and load.
	if want := "DE#1@m1,DE#6@m7"; names(got) != want {
		t.Fatalf("got %s want %s", names(got), want)
	}
}

func TestMatchPinnedName(t *testing.T) {
	got, _ := Match(world(), Filter{Country: "DE", Name: "de#2", MaxTier: 2}, false)
	if want := "DE#2@m1,DE#2@m2"; names(got) != want {
		t.Fatalf("got %s want %s", names(got), want)
	}
}

func TestMatchExcludeNamesAndDomains(t *testing.T) {
	f := Filter{Country: "DE", City: "Frankfurt", Exclude: []string{"DE#1", " M2 "}, Require: config.FeatP2P, MaxTier: 2}
	got, _ := Match(world(), f, false)
	if want := "DE#2@m1,DE#6@m7"; names(got) != want {
		t.Fatalf("got %s want %s", names(got), want)
	}
}

func TestMatchForbidAndRequireFeatures(t *testing.T) {
	f := Filter{Country: "DE", City: "Frankfurt", Forbid: config.FeatP2P, MaxTier: 2}
	got, _ := Match(world(), f, false)
	if want := "DE#4@m4"; names(got) != want {
		t.Fatalf("forbid p2p: got %s want %s", names(got), want)
	}
	got, _ = Match(world(), Filter{Country: "DE", Require: config.FeatTor, MaxTier: 2}, false)
	if want := "DE#5-TOR@m5"; names(got) != want {
		t.Fatalf("require tor: got %s want %s", names(got), want)
	}
	got, _ = Match(world(), Filter{Country: "DE", Require: config.FeatSecureCore, MaxTier: 2}, false)
	if want := "CH-DE#1@m6"; names(got) != want {
		t.Fatalf("require secure_core: got %s want %s", names(got), want)
	}
}

func TestMatchAccountAccess(t *testing.T) {
	ls := world()
	got, _ := Match(ls, Filter{Country: "DE", City: "Frankfurt", Require: config.FeatP2P, MaxTier: 0}, false)
	if want := "DE#6@m7"; names(got) != want {
		t.Fatalf("free account: got %s want %s", names(got), want)
	}
}

func TestMatchRequiresEnabledAndEndpoint(t *testing.T) {
	ls := []proton.Logical{
		logical("A#1", "DE", "X", 2, 0, 1, phys("ok")),
		logical("A#2", "DE", "X", 2, 0, 1, phys("disabled")),
		logical("A#3", "DE", "X", 2, 0, 1, phys("nov6")),
		logical("A#4", "DE", "X", 2, 0, 1, phys("nokey")),
		logical("A#5", "DE", "X", 2, 0, 1, phys("shortkey")),
		logical("A#6", "DE", "X", 2, 0, 1, phys("v4mapped")),
		logical("A#7", "DE", "X", 2, 0, 1, phys("m")),
	}
	ls[1].Servers[0].Status = 0
	ls[2].Servers[0].EntryIPv6 = ""
	ls[3].Servers[0].X25519PublicKey = ""
	ls[4].Servers[0].X25519PublicKey = base64.StdEncoding.EncodeToString([]byte("short"))
	ls[5].Servers[0].EntryIPv6 = "::ffff:1.2.3.4"
	ls[6].Status = 0 // logical disabled
	got, funnel := Match(ls, Filter{Country: "DE", MaxTier: 2}, false)
	if names(got) != "A#1@ok" {
		t.Fatalf("got %s", names(got))
	}
	if funnel[0].Left != 7 {
		t.Fatalf("funnel start: %+v", funnel)
	}
}

func TestMatchMaxLoadIgnored(t *testing.T) {
	f := Filter{Country: "DE", City: "Frankfurt", MaxLoad: 25, Require: config.FeatP2P, MaxTier: 2}
	got, _ := Match(world(), f, false)
	if names(got) != "DE#6@m7" {
		t.Fatalf("with load: %s", names(got))
	}
	got, _ = Match(world(), f, true)
	if names(got) != "DE#1@m1,DE#2@m1,DE#2@m2,DE#6@m7" {
		t.Fatalf("ignoring load: %s", names(got))
	}
}

func TestEmptyResultError(t *testing.T) {
	cands, funnel := Match(world(), Filter{Country: "DE", City: "Paris", MaxTier: 2}, false)
	if len(cands) != 0 {
		t.Fatal("expected none")
	}
	err := (&NoCandidatesError{Funnel: funnel}).Error()
	if !strings.Contains(err, "no server matches") || !strings.Contains(err, "city Paris: 0") || strings.Contains(err, "enabled") {
		t.Fatalf("error text: %s", err)
	}
	if _, e := Choose(nil, config.SelectRandom, nil); e == nil {
		t.Fatal("Choose on empty must fail")
	}
}

func TestChooseLeastLoad(t *testing.T) {
	cands, _ := Match(world(), Filter{Country: "DE", Require: config.FeatP2P, MaxTier: 2}, false)
	c, err := Choose(cands, config.SelectLeastLoad, func(n int) int { return 0 })
	if err != nil || c.Logical.Name != "DE#6" { // load 5 is the lowest
		t.Fatalf("got %+v %v", c.Logical.Name, err)
	}
	// Tie: both loads equal. The random function decides.
	ls := []proton.Logical{logical("T#1", "DE", "", 2, 0, 9, phys("a")), logical("T#2", "DE", "", 2, 0, 9, phys("b"))}
	cands, _ = Match(ls, Filter{Country: "DE", MaxTier: 2}, false)
	c0, _ := Choose(cands, config.SelectLeastLoad, func(n int) int { return 0 })
	c1, _ := Choose(cands, config.SelectLeastLoad, func(n int) int { return n - 1 })
	if c0.Logical.Name == c1.Logical.Name {
		t.Fatal("tie should depend on the random function")
	}
}

func TestChooseRandomCoversAll(t *testing.T) {
	cands, _ := Match(world(), Filter{Country: "DE", City: "Frankfurt", Require: config.FeatP2P, MaxTier: 2}, false)
	seen := map[string]bool{}
	for i := 0; i < 400; i++ {
		c, err := Choose(cands, config.SelectRandom, nil)
		if err != nil {
			t.Fatal(err)
		}
		seen[c.Logical.Name+"@"+c.Server.Domain] = true
	}
	if len(seen) != 4 { // DE#1@m1, DE#2@m1, DE#2@m2, DE#6@m7
		t.Fatalf("random choice reached %d of 4: %v", len(seen), seen)
	}
}

func TestRevalidateKeepsAndDetectsChange(t *testing.T) {
	ls := world()
	f := Filter{Country: "DE", City: "Frankfurt", MaxLoad: 50, Require: config.FeatP2P, MaxTier: 2}
	cands, _ := Match(ls, f, false)
	c, _ := Choose(cands, config.SelectLeastLoad, func(int) int { return 0 })
	saved := ToGroup(c)
	if saved.Logical != "DE#6" || saved.Domain != "m7" {
		t.Fatalf("saved: %+v", saved)
	}
	// DE#2 has load 80, above max_load, but a saved DE#2 selection stays valid.
	saved2 := ToGroup(Candidate{&ls[1], &ls[1].Servers[0]})
	got, ok := Revalidate(&saved2, ls, f)
	if !ok || !SameEndpoint(&saved2, got) {
		t.Fatalf("saved selection above max_load must stay valid: %v", ok)
	}
	// A changed public key is detected.
	ls[1].Servers[0].X25519PublicKey = base64.StdEncoding.EncodeToString([]byte(strings.Repeat("k", 32)))
	got, ok = Revalidate(&saved2, ls, f)
	if !ok || SameEndpoint(&saved2, got) {
		t.Fatalf("changed key should still be valid but not the same: ok=%v", ok)
	}
	// Disabled server is invalid.
	ls[1].Status = 0
	if _, ok := Revalidate(&saved2, ls, f); ok {
		t.Fatal("disabled logical must be invalid")
	}
	// Filter change (other city) makes the selection invalid.
	f2 := f
	f2.City = "Berlin"
	if _, ok := Revalidate(&saved, world(), f2); ok {
		t.Fatal("city change must invalidate")
	}
	_ = fmt.Sprint()
}
