package config

import (
	"strings"
	"testing"
)

const good = `
version: 1
paths:
  state_dir: /var/lib/pvpn
reconcile:
  prune: true
defaults:
  source:
    device: eth0
    gateway: fe80::1
    subnets:
      - "2a01:4f8:1c1b:21a0::/64"
groups:
  germany:
    server:
      country: DE
      city: Frankfurt
      exclude:
        - "DE#53-TOR"
        - "node-de-16.protonvpn.net"
      max_load: 70
      require_features: [p2p]
      exclude_features: [tor, secure_core]
      select: random
    interfaces:
      - pvpn-de1
      - pvpn-de2
  netherlands:
    server:
      country: NL
      select: least_load
    interfaces: [pvpn-nl1, pvpn-nl2]
`

func TestParseGood(t *testing.T) {
	c, err := Parse([]byte(good))
	if err != nil {
		t.Fatal(err)
	}
	g := c.Groups["germany"].Server
	if g.Require != FeatP2P || g.Forbid != FeatTor|FeatSecureCore || g.MaxLoad != 70 || g.Select != SelectRandom {
		t.Fatalf("bad derived server: %+v", g)
	}
	if !c.Reconcile.Prune || c.Paths.StateDir != "/var/lib/pvpn" {
		t.Fatalf("bad paths/reconcile: %+v", c)
	}
	if len(c.Subnets) != 1 || c.Gateway.String() != "fe80::1" {
		t.Fatalf("bad derived source: %v %v", c.Subnets, c.Gateway)
	}
	if got := strings.Join(c.AllInterfaces(), ","); got != "pvpn-de1,pvpn-de2,pvpn-nl1,pvpn-nl2" {
		t.Fatalf("interfaces order: %s", got)
	}
	if g, ok := c.GroupOf("pvpn-nl2"); !ok || g != "netherlands" {
		t.Fatalf("GroupOf: %q %v", g, ok)
	}
}

func TestDefaults(t *testing.T) {
	c, err := Parse([]byte(`
version: 1
defaults: {source: {device: eth0, gateway: "fe80::1", subnets: ["2001:db8::/64"]}}
groups: {a: {server: {country: de}, interfaces: [x1]}}
`))
	if err != nil {
		t.Fatal(err)
	}
	if c.Paths.StateDir != DefaultStateDir || c.Reconcile.Prune || c.Groups["a"].Server.Select != SelectRandom || c.Groups["a"].Server.Country != "DE" {
		t.Fatalf("defaults not applied: %+v", c)
	}
}

func TestEmptyGroupsAllowed(t *testing.T) {
	if _, err := Parse([]byte("version: 1\nreconcile: {prune: true}\ngroups: {}\n")); err != nil {
		t.Fatal(err)
	}
}

func TestRejects(t *testing.T) {
	base := func(mut func(string) string) string { return mut(good) }
	cases := []struct {
		name, yaml, want string
	}{
		{"unknown top field", base(func(s string) string { return s + "\nextra: 1\n" }), "field extra not found"},
		{"unknown nested field", base(func(s string) string { return strings.Replace(s, "select: random", "selekt: random", 1) }), "selekt"},
		{"bad version", base(func(s string) string { return strings.Replace(s, "version: 1", "version: 2", 1) }), "version must be 1"},
		{"duplicate interface in group", base(func(s string) string { return strings.Replace(s, "pvpn-de2", "pvpn-de1", 1) }), `"pvpn-de1" is listed twice`},
		{"duplicate interface across groups", base(func(s string) string { return strings.Replace(s, "pvpn-nl1", "pvpn-de1", 1) }), `"pvpn-de1" is listed twice`},
		{"unsafe interface name slash", base(func(s string) string { return strings.Replace(s, "pvpn-de2", `"../etc/x"`, 1) }), "not safe"},
		{"unsafe interface name space", base(func(s string) string { return strings.Replace(s, "pvpn-de2", `"a b"`, 1) }), "not safe"},
		{"interface name too long", base(func(s string) string { return strings.Replace(s, "pvpn-de2", "abcdefghijklmnop", 1) }), "not safe"},
		{"leading dash", base(func(s string) string { return strings.Replace(s, "pvpn-de2", `"-x"`, 1) }), "not safe"},
		{"ipv4 subnet", base(func(s string) string { return strings.Replace(s, "2a01:4f8:1c1b:21a0::/64", "10.0.0.0/24", 1) }), "not IPv6"},
		{"tiny subnet", base(func(s string) string { return strings.Replace(s, "2a01:4f8:1c1b:21a0::/64", "2001:db8::/125", 1) }), "too small"},
		{"link-local subnet", base(func(s string) string { return strings.Replace(s, "2a01:4f8:1c1b:21a0::/64", "fe80::/64", 1) }), "not a global"},
		{"bad subnet", base(func(s string) string { return strings.Replace(s, "2a01:4f8:1c1b:21a0::/64", "nope", 1) }), "not a CIDR"},
		{"ipv4 gateway", base(func(s string) string { return strings.Replace(s, "fe80::1", "10.0.0.1", 1) }), "not IPv6"},
		{"bad gateway", base(func(s string) string { return strings.Replace(s, "fe80::1", "gw", 1) }), "not an IP"},
		{"bad device", base(func(s string) string { return strings.Replace(s, "device: eth0", "device: 'a/b'", 1) }), "not a valid device"},
		{"unknown feature", base(func(s string) string { return strings.Replace(s, "[p2p]", "[p2p, streaming]", 1) }), `unknown feature "streaming"`},
		{"conflicting features", base(func(s string) string { return strings.Replace(s, "[tor, secure_core]", "[p2p]", 1) }), "share p2p"},
		{"duplicate feature", base(func(s string) string { return strings.Replace(s, "[p2p]", "[p2p, p2p]", 1) }), "listed twice"},
		{"bad max_load", base(func(s string) string { return strings.Replace(s, "max_load: 70", "max_load: 101", 1) }), "max_load"},
		{"bad select", base(func(s string) string { return strings.Replace(s, "select: random", "select: best", 1) }), "random or least_load"},
		{"bad country", base(func(s string) string { return strings.Replace(s, "country: DE", "country: Germany", 1) }), "2-letter"},
		{"no interfaces", base(func(s string) string {
			return strings.Replace(s, "interfaces: [pvpn-nl1, pvpn-nl2]", "interfaces: []", 1)
		}), "no interfaces"},
		{"no subnets", base(func(s string) string {
			return strings.Replace(s, "subnets:\n      - \"2a01:4f8:1c1b:21a0::/64\"", "subnets: []", 1)
		}), "at least one"},
		{"relative state dir", base(func(s string) string { return strings.Replace(s, "/var/lib/pvpn", "var/lib", 1) }), "absolute"},
		{"empty exclude entry", base(func(s string) string { return strings.Replace(s, `"DE#53-TOR"`, `""`, 1) }), "empty entry"},
		{"two documents", good + "\n---\nversion: 1\n", "more than one"},
		{"duplicate key", "version: 1\nversion: 1\n", "already defined"},
		{"empty file", "", "empty"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			_, err := Parse([]byte(tc.yaml))
			if err == nil {
				t.Fatalf("expected error containing %q", tc.want)
			}
			if !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("error %q does not contain %q", err, tc.want)
			}
		})
	}
}

func TestReportsAllErrors(t *testing.T) {
	_, err := Parse([]byte(`
version: 3
defaults: {source: {device: eth0, gateway: "fe80::1", subnets: ["10.0.0.0/8"]}}
groups: {a: {server: {country: XX1, select: z}, interfaces: [a, a]}}
`))
	if err == nil {
		t.Fatal("expected errors")
	}
	for _, w := range []string{"version must be 1", "not IPv6", "2-letter", "random or least_load", "listed twice"} {
		if !strings.Contains(err.Error(), w) {
			t.Errorf("missing %q in %v", w, err)
		}
	}
}

func TestFreeFeatureNames(t *testing.T) {
	doc := func(req, excl string) string {
		return "version: 1\ndefaults:\n  source:\n    device: eth0\n    gateway: fe80::1\n    subnets: [\"2001:db8::/64\"]\n" +
			"groups:\n  g:\n    server:\n      country: DE\n      require_features: " + req + "\n      exclude_features: " + excl + "\n    interfaces: [a1]\n"
	}
	cfg, err := Parse([]byte(doc("[p2p]", "[free]")))
	if err != nil {
		t.Fatal(err)
	}
	if g := cfg.Groups["g"].Server; g.Forbid != FeatFree || g.Require != FeatP2P {
		t.Errorf("masks: require %d forbid %d", g.Require, g.Forbid)
	}
	if _, err := Parse([]byte(doc("[free]", "[]"))); err != nil {
		t.Errorf("require free: %v", err)
	}
	if _, err := Parse([]byte(doc("[free]", "[free]"))); err == nil || !strings.Contains(err.Error(), "share free") {
		t.Errorf("free in both lists: %v", err)
	}
	if _, err := Parse([]byte(doc("[streaming]", "[]"))); err == nil || !strings.Contains(err.Error(), "allowed: p2p, tor, secure_core, free") {
		t.Errorf("unknown feature text: %v", err)
	}
}
