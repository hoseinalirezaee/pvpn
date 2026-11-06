// Package config loads and validates the pvpn YAML file.
package config

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"net/netip"
	"os"
	"regexp"
	"sort"
	"strings"

	"go.yaml.in/yaml/v3"
)

// DefaultStateDir is used when paths.state_dir is empty.
const DefaultStateDir = "/var/lib/pvpn"

// Feature bits of a Proton logical server.
const (
	FeatSecureCore = 1
	FeatTor        = 2
	FeatP2P        = 4
	// FeatFree is not a Proton feature bit. The selector sets it for free-tier servers (Tier 0).
	FeatFree = 1 << 30
)

var featureBits = map[string]int{"p2p": FeatP2P, "tor": FeatTor, "secure_core": FeatSecureCore, "free": FeatFree}

type Config struct {
	Version   int               `yaml:"version"`
	Paths     Paths             `yaml:"paths"`
	Reconcile Reconcile         `yaml:"reconcile"`
	Defaults  Defaults          `yaml:"defaults"`
	Groups    map[string]*Group `yaml:"groups"`

	// Derived by Validate.
	Gateway netip.Addr     `yaml:"-"`
	Subnets []netip.Prefix `yaml:"-"`
}

type Paths struct {
	StateDir string `yaml:"state_dir"`
}

type Reconcile struct {
	Prune bool `yaml:"prune"`
}

type Defaults struct {
	Source Source `yaml:"source"`
}

type Source struct {
	Device  string   `yaml:"device"`
	Gateway string   `yaml:"gateway"`
	Subnets []string `yaml:"subnets"`
}

type Group struct {
	Server     Server   `yaml:"server"`
	Interfaces []string `yaml:"interfaces"`
}

type Server struct {
	Country         string   `yaml:"country"`
	City            string   `yaml:"city"`
	Name            string   `yaml:"name"`
	Exclude         []string `yaml:"exclude"`
	MaxLoad         int      `yaml:"max_load"`
	RequireFeatures []string `yaml:"require_features"`
	ExcludeFeatures []string `yaml:"exclude_features"`
	Select          string   `yaml:"select"`

	// Derived by Validate.
	Require int `yaml:"-"`
	Forbid  int `yaml:"-"`
}

const (
	SelectRandom    = "random"
	SelectLeastLoad = "least_load"
)

var (
	reIface = regexp.MustCompile(`^[A-Za-z0-9_][A-Za-z0-9_=+.-]{0,14}$`)
	reGroup = regexp.MustCompile(`^[A-Za-z0-9_][A-Za-z0-9_.-]{0,31}$`)
	reDev   = regexp.MustCompile(`^[A-Za-z0-9_][A-Za-z0-9_.:@-]{0,14}$`)
	reCC    = regexp.MustCompile(`^[A-Z]{2}$`)
)

// Load reads and validates a config file.
func Load(path string) (*Config, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	return Parse(b)
}

// Parse decodes and validates YAML. It reports every problem it finds.
func Parse(b []byte) (*Config, error) {
	dec := yaml.NewDecoder(bytes.NewReader(b))
	dec.KnownFields(true)
	var c Config
	if err := dec.Decode(&c); err != nil {
		if errors.Is(err, io.EOF) {
			return nil, errors.New("config is empty")
		}
		return nil, fmt.Errorf("config: %w", err)
	}
	var extra yaml.Node
	if err := dec.Decode(&extra); !errors.Is(err, io.EOF) {
		return nil, errors.New("config: more than one YAML document")
	}
	if err := c.Validate(); err != nil {
		return nil, err
	}
	return &c, nil
}

// Validate checks the whole config and fills derived fields.
func (c *Config) Validate() error {
	var errs []error
	bad := func(f string, a ...any) { errs = append(errs, fmt.Errorf(f, a...)) }

	if c.Version != 1 {
		bad("version must be 1 (got %d)", c.Version)
	}
	if c.Paths.StateDir == "" {
		c.Paths.StateDir = DefaultStateDir
	}
	if !strings.HasPrefix(c.Paths.StateDir, "/") {
		bad("paths.state_dir must be an absolute path")
	}

	src := &c.Defaults.Source
	if len(c.Groups) > 0 {
		if !reDev.MatchString(src.Device) {
			bad("defaults.source.device %q is not a valid device name", src.Device)
		}
		gw, err := netip.ParseAddr(src.Gateway)
		switch {
		case err != nil:
			bad("defaults.source.gateway %q is not an IP address", src.Gateway)
		case !gw.Is6() || gw.Is4In6():
			bad("defaults.source.gateway %q is not IPv6", src.Gateway)
		case gw.IsUnspecified() || gw.IsMulticast() || gw.IsLoopback():
			bad("defaults.source.gateway %q is not usable", src.Gateway)
		default:
			c.Gateway = gw
		}
		if len(src.Subnets) == 0 {
			bad("defaults.source.subnets must list at least one IPv6 subnet")
		}
		c.Subnets = c.Subnets[:0]
		for _, s := range src.Subnets {
			p, err := netip.ParsePrefix(s)
			switch {
			case err != nil:
				bad("subnet %q is not a CIDR", s)
			case !p.Addr().Is6() || p.Addr().Is4In6():
				bad("subnet %q is not IPv6", s)
			case p.Bits() > 120:
				bad("subnet %q is too small (longest allowed prefix is /120)", s)
			case p.Addr().IsLoopback() || p.Addr().IsLinkLocalUnicast() || p.Addr().IsMulticast() || p.Addr().IsUnspecified():
				bad("subnet %q is not a global or unique-local range", s)
			default:
				c.Subnets = append(c.Subnets, p.Masked())
			}
		}
	}

	seen := map[string]string{}
	for _, name := range c.GroupNames() {
		g := c.Groups[name]
		if !reGroup.MatchString(name) {
			bad("group name %q is not valid", name)
		}
		if g == nil {
			bad("group %q is empty", name)
			continue
		}
		c.validateServer(name, &g.Server, bad)
		if len(g.Interfaces) == 0 {
			bad("group %q has no interfaces", name)
		}
		for _, in := range g.Interfaces {
			switch {
			case !reIface.MatchString(in):
				bad("group %q: interface name %q is not safe (use 1-15 of A-Z a-z 0-9 _ = + . -, no leading - or .)", name, in)
			case seen[in] != "":
				bad("interface %q is listed twice (groups %q and %q)", in, seen[in], name)
			default:
				seen[in] = name
			}
		}
	}
	return errors.Join(errs...)
}

func (c *Config) validateServer(group string, s *Server, bad func(string, ...any)) {
	s.Country = strings.ToUpper(strings.TrimSpace(s.Country))
	if !reCC.MatchString(s.Country) {
		bad("group %q: server.country %q must be a 2-letter country code", group, s.Country)
	}
	s.City = strings.TrimSpace(s.City)
	s.Name = strings.TrimSpace(s.Name)
	if s.MaxLoad < 0 || s.MaxLoad > 100 {
		bad("group %q: server.max_load %d must be between 1 and 100", group, s.MaxLoad)
	}
	switch s.Select {
	case "":
		s.Select = SelectRandom
	case SelectRandom, SelectLeastLoad:
	default:
		bad("group %q: server.select %q must be random or least_load", group, s.Select)
	}
	for _, e := range s.Exclude {
		if strings.TrimSpace(e) == "" {
			bad("group %q: server.exclude has an empty entry", group)
		}
	}
	req, err1 := featureMask(s.RequireFeatures)
	forb, err2 := featureMask(s.ExcludeFeatures)
	if err1 != nil {
		bad("group %q: require_features: %v", group, err1)
	}
	if err2 != nil {
		bad("group %q: exclude_features: %v", group, err2)
	}
	if req&forb != 0 {
		bad("group %q: require_features and exclude_features share %s", group, strings.Join(featureNames(req&forb), ", "))
	}
	s.Require, s.Forbid = req, forb
}

func featureMask(list []string) (int, error) {
	m := 0
	seen := map[string]bool{}
	for _, f := range list {
		bit, ok := featureBits[f]
		switch {
		case !ok:
			return 0, fmt.Errorf("unknown feature %q (allowed: p2p, tor, secure_core, free)", f)
		case seen[f]:
			return 0, fmt.Errorf("feature %q is listed twice", f)
		}
		seen[f] = true
		m |= bit
	}
	return m, nil
}

func featureNames(mask int) []string {
	var out []string
	for n, b := range featureBits {
		if mask&b != 0 {
			out = append(out, n)
		}
	}
	sort.Strings(out)
	return out
}

// GroupNames returns group names in sorted order.
func (c *Config) GroupNames() []string {
	names := make([]string, 0, len(c.Groups))
	for n := range c.Groups {
		names = append(names, n)
	}
	sort.Strings(names)
	return names
}

// GroupOf returns the group that lists the interface.
func (c *Config) GroupOf(iface string) (string, bool) {
	for n, g := range c.Groups {
		if g == nil {
			continue
		}
		for _, i := range g.Interfaces {
			if i == iface {
				return n, true
			}
		}
	}
	return "", false
}

// AllInterfaces returns every configured interface in group then list order.
func (c *Config) AllInterfaces() []string {
	var out []string
	for _, n := range c.GroupNames() {
		out = append(out, c.Groups[n].Interfaces...)
	}
	return out
}
