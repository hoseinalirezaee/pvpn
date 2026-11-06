// Package alloc picks routing table, firewall mark, priority, and random source addresses.
package alloc

import (
	"crypto/rand"
	"errors"
	"fmt"
	"io"
	"net/netip"
)

// First values of each allocation range.
const (
	FirstTable    = 5751
	FirstMark     = 0x5751
	FirstPriority = 101
)

// Used holds values that other things on the host already use.
type Used struct {
	Tables, Marks, Priorities map[int]bool
}

func NewUsed() *Used {
	return &Used{Tables: map[int]bool{}, Marks: map[int]bool{}, Priorities: map[int]bool{}}
}

// Merge copies all values of o into u.
func (u *Used) Merge(o *Used) {
	if o == nil {
		return
	}
	for k := range o.Tables {
		u.Tables[k] = true
	}
	for k := range o.Marks {
		u.Marks[k] = true
	}
	for k := range o.Priorities {
		u.Priorities[k] = true
	}
}

// IDs is one routing identity.
type IDs struct{ Table, Mark, Priority int }

// Next returns the lowest free value of each kind, starting at the first values.
// It marks the result as used, so repeated calls give different values.
func Next(u *Used) IDs {
	pick := func(set map[int]bool, start int) int {
		for v := start; ; v++ {
			if !set[v] {
				set[v] = true
				return v
			}
		}
	}
	return IDs{
		Table:    pick(u.Tables, FirstTable),
		Mark:     pick(u.Marks, FirstMark),
		Priority: pick(u.Priorities, FirstPriority),
	}
}

// RandomAddr returns a random address inside one of the prefixes.
// It skips the subnet-router anycast address (all host bits zero) and any address that avoid rejects.
// rnd may be nil. Then crypto/rand is used.
func RandomAddr(prefixes []netip.Prefix, rnd io.Reader, avoid func(netip.Addr) bool) (netip.Addr, error) {
	if len(prefixes) == 0 {
		return netip.Addr{}, errors.New("no source subnets configured")
	}
	if rnd == nil {
		rnd = rand.Reader
	}
	for try := 0; try < 100; try++ {
		var pick [1]byte
		if _, err := io.ReadFull(rnd, pick[:]); err != nil {
			return netip.Addr{}, err
		}
		p := prefixes[int(pick[0])%len(prefixes)]
		a, err := randomIn(p, rnd)
		if err != nil {
			return netip.Addr{}, err
		}
		if a == p.Masked().Addr() { // subnet-router anycast
			continue
		}
		if avoid != nil && avoid(a) {
			continue
		}
		return a, nil
	}
	return netip.Addr{}, fmt.Errorf("no free random address found in %v after 100 tries", prefixes)
}

func randomIn(p netip.Prefix, rnd io.Reader) (netip.Addr, error) {
	base := p.Masked().Addr().As16()
	var r [16]byte
	if _, err := io.ReadFull(rnd, r[:]); err != nil {
		return netip.Addr{}, err
	}
	bits := p.Bits()
	for i := 0; i < 16; i++ {
		lo, hi := i*8, i*8+8
		switch {
		case hi <= bits: // all network bits
		case lo >= bits: // all host bits
			base[i] = r[i]
		default: // mixed byte
			keep := uint(bits - lo)
			mask := byte(0xff) << (8 - keep)
			base[i] = (base[i] & mask) | (r[i] &^ mask)
		}
	}
	return netip.AddrFrom16(base), nil
}
