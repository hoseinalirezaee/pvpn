// Package selector filters Proton servers and chooses one for a group.
package selector

import (
	"crypto/rand"
	"encoding/base64"
	"fmt"
	"math/big"
	"net/netip"
	"sort"
	"strings"

	"pvpn/internal/config"
	"pvpn/internal/proton"
	"pvpn/internal/state"
)

// Filter is the set of conditions a server must meet.
type Filter struct {
	Country string
	City    string
	Name    string
	Exclude []string
	MaxLoad int // 0 means no limit
	Require int // feature bits that must be set
	Forbid  int // feature bits that must not be set
	MaxTier int // highest tier the account may use
}

// FromConfig builds the filter of a group. maxTier comes from the account.
func FromConfig(s config.Server, maxTier int) Filter {
	return Filter{Country: s.Country, City: s.City, Name: s.Name, Exclude: s.Exclude, MaxLoad: s.MaxLoad, Require: s.Require, Forbid: s.Forbid, MaxTier: maxTier}
}

// Candidate is one logical server with one physical endpoint.
type Candidate struct {
	Logical *proton.Logical
	Server  *proton.Physical
}

// Stage is one step of the filter funnel.
type Stage struct {
	Name string
	Left int
}

// NoCandidatesError says which filter removed the last candidates.
type NoCandidatesError struct{ Funnel []Stage }

func (e *NoCandidatesError) Error() string {
	var b strings.Builder
	b.WriteString("no server matches the filters")
	last := 0
	for i, s := range e.Funnel {
		if i == 0 {
			fmt.Fprintf(&b, " (%s: %d", s.Name, s.Left)
		} else {
			fmt.Fprintf(&b, " -> %s: %d", s.Name, s.Left)
		}
		last = s.Left
		if last == 0 {
			break
		}
	}
	b.WriteString(")")
	return b.String()
}

type stage struct {
	name string
	keep func(l *proton.Logical, p *proton.Physical) bool
}

func feat(l *proton.Logical, bit int) bool { return l.Features&bit != 0 }

func (f Filter) stages(ignoreLoad bool) []stage {
	forbid := f.Forbid
	// Tor and Secure Core servers are separate products. A group gets them only when it asks for them.
	if f.Require&config.FeatSecureCore == 0 {
		forbid |= config.FeatSecureCore
	}
	if f.Require&config.FeatTor == 0 {
		forbid |= config.FeatTor
	}
	ex := make([]string, len(f.Exclude))
	for i, e := range f.Exclude {
		ex[i] = strings.ToLower(strings.TrimSpace(e))
	}
	st := []stage{
		{"country " + f.Country, func(l *proton.Logical, _ *proton.Physical) bool { return strings.EqualFold(l.ExitCountry, f.Country) }},
	}
	if f.City != "" {
		st = append(st, stage{"city " + f.City, func(l *proton.Logical, _ *proton.Physical) bool { return strings.EqualFold(l.City, f.City) }})
	}
	if f.Name != "" {
		st = append(st, stage{"name " + f.Name, func(l *proton.Logical, _ *proton.Physical) bool { return strings.EqualFold(l.Name, f.Name) }})
	}
	st = append(st,
		stage{"not excluded", func(l *proton.Logical, p *proton.Physical) bool {
			for _, e := range ex {
				if strings.EqualFold(l.Name, e) || strings.EqualFold(p.Domain, e) {
					return false
				}
			}
			return true
		}},
		stage{"enabled", func(l *proton.Logical, p *proton.Physical) bool { return l.Status == 1 && p.Status == 1 }},
		stage{"account tier", func(l *proton.Logical, _ *proton.Physical) bool { return l.Tier <= f.MaxTier }},
		stage{"IPv6 endpoint and key", func(_ *proton.Logical, p *proton.Physical) bool { return validEndpoint(p) }},
		stage{"features", func(l *proton.Logical, _ *proton.Physical) bool {
			return l.Features&f.Require == f.Require && l.Features&forbid == 0
		}},
	)
	if f.MaxLoad > 0 && !ignoreLoad {
		st = append(st, stage{fmt.Sprintf("max_load %d", f.MaxLoad), func(l *proton.Logical, _ *proton.Physical) bool { return l.Load <= f.MaxLoad }})
	}
	return st
}

func validEndpoint(p *proton.Physical) bool {
	a, err := netip.ParseAddr(p.EntryIPv6)
	if err != nil || !a.Is6() || a.Is4In6() {
		return false
	}
	k, err := base64.StdEncoding.DecodeString(p.X25519PublicKey)
	return err == nil && len(k) == 32
}

// Match returns every candidate that passes all filters, with the funnel counts.
// With ignoreLoad, max_load is skipped (used to keep a saved selection).
func Match(ls []proton.Logical, f Filter, ignoreLoad bool) ([]Candidate, []Stage) {
	var pairs []Candidate
	for i := range ls {
		for j := range ls[i].Servers {
			pairs = append(pairs, Candidate{&ls[i], &ls[i].Servers[j]})
		}
	}
	funnel := []Stage{{"servers listed", len(pairs)}}
	for _, s := range f.stages(ignoreLoad) {
		out := pairs[:0:0]
		for _, c := range pairs {
			if s.keep(c.Logical, c.Server) {
				out = append(out, c)
			}
		}
		pairs = out
		funnel = append(funnel, Stage{s.name, len(pairs)})
	}
	sort.SliceStable(pairs, func(i, j int) bool {
		if pairs[i].Logical.Name != pairs[j].Logical.Name {
			return pairs[i].Logical.Name < pairs[j].Logical.Name
		}
		return pairs[i].Server.Domain < pairs[j].Server.Domain
	})
	return pairs, funnel
}

// Rand returns a random integer in [0, n).
type Rand func(n int) int

// CryptoRand is the default Rand.
func CryptoRand(n int) int {
	v, err := rand.Int(rand.Reader, big.NewInt(int64(n)))
	if err != nil {
		panic(err) // the system random source failed
	}
	return int(v.Int64())
}

// Choose picks one logical server, then one of its physical endpoints.
// mode is config.SelectRandom or config.SelectLeastLoad.
func Choose(cands []Candidate, mode string, rnd Rand) (Candidate, error) {
	if len(cands) == 0 {
		return Candidate{}, &NoCandidatesError{}
	}
	if rnd == nil {
		rnd = CryptoRand
	}
	byName := map[string][]Candidate{}
	var names []string
	for _, c := range cands {
		if _, ok := byName[c.Logical.Name]; !ok {
			names = append(names, c.Logical.Name)
		}
		byName[c.Logical.Name] = append(byName[c.Logical.Name], c)
	}
	sort.Strings(names)
	pool := names
	if mode == config.SelectLeastLoad {
		best := -1
		pool = nil
		for _, n := range names {
			l := byName[n][0].Logical.Load
			switch {
			case best < 0 || l < best:
				best, pool = l, []string{n}
			case l == best:
				pool = append(pool, n)
			}
		}
	}
	name := pool[rnd(len(pool))]
	ps := byName[name]
	return ps[rnd(len(ps))], nil
}

// ToGroup converts a candidate to the saved form (SelectedAt is left for the caller).
func ToGroup(c Candidate) state.Group {
	return state.Group{
		Logical: c.Logical.Name, Domain: c.Server.Domain, EntryIPv4: c.Server.EntryIP, EntryIPv6: c.Server.EntryIPv6,
		PublicKey: c.Server.X25519PublicKey, Label: c.Server.Label,
		Country: c.Logical.ExitCountry, City: c.Logical.City, Tier: c.Logical.Tier,
	}
}

// Revalidate checks that a saved selection still passes every filter except max_load.
// It returns the current data of the same logical server and machine.
func Revalidate(saved *state.Group, ls []proton.Logical, f Filter) (Candidate, bool) {
	cands, _ := Match(ls, f, true)
	for _, c := range cands {
		if c.Logical.Name == saved.Logical && c.Server.Domain == saved.Domain {
			return c, true
		}
	}
	return Candidate{}, false
}

// SameEndpoint reports whether the saved group still describes the candidate.
func SameEndpoint(saved *state.Group, c Candidate) bool {
	return saved.Logical == c.Logical.Name && saved.Domain == c.Server.Domain &&
		saved.EntryIPv6 == c.Server.EntryIPv6 && saved.PublicKey == c.Server.X25519PublicKey && saved.Label == c.Server.Label
}
