package alloc

import (
	"bytes"
	"net/netip"
	"testing"
)

func TestNextStartsAtFirstValues(t *testing.T) {
	u := NewUsed()
	if got := Next(u); got != (IDs{5751, 0x5751, 101}) {
		t.Fatalf("first: %+v", got)
	}
	if got := Next(u); got != (IDs{5752, 0x5752, 102}) {
		t.Fatalf("second: %+v", got)
	}
}

func TestNextSkipsOccupied(t *testing.T) {
	u := NewUsed()
	u.Tables[5751], u.Tables[5752] = true, true
	u.Marks[0x5751] = true
	u.Priorities[102] = true
	if got := Next(u); got != (IDs{5753, 0x5752, 101}) {
		t.Fatalf("got %+v", got)
	}
	// 101 was just taken, 102 is occupied: the next free is 103.
	if got := Next(u); got != (IDs{5754, 0x5753, 103}) {
		t.Fatalf("got %+v", got)
	}
}

func TestMerge(t *testing.T) {
	a, b := NewUsed(), NewUsed()
	b.Tables[1], b.Marks[2], b.Priorities[3] = true, true, true
	a.Merge(b)
	a.Merge(nil)
	if !a.Tables[1] || !a.Marks[2] || !a.Priorities[3] {
		t.Fatal("merge lost values")
	}
}

func TestRandomAddrInsidePrefix(t *testing.T) {
	ps := []netip.Prefix{netip.MustParsePrefix("2a01:4f8:1c1b:21a0::/64"), netip.MustParsePrefix("2001:db8:5::/117")}
	seen := map[netip.Addr]bool{}
	big := 0
	for i := 0; i < 500; i++ {
		a, err := RandomAddr(ps, nil, nil)
		if err != nil {
			t.Fatal(err)
		}
		if !ps[0].Contains(a) && !ps[1].Contains(a) {
			t.Fatalf("%v is outside the prefixes", a)
		}
		if ps[0].Contains(a) {
			big++
			seen[a] = true
		}
	}
	if big < 150 || len(seen) != big {
		t.Fatalf("/64 draws: %d, unique: %d (want many draws, all unique)", big, len(seen))
	}
}

func TestRandomAddrMixedByteBoundary(t *testing.T) {
	p := netip.MustParsePrefix("2001:db8::/117") // 11 host bits: crosses a byte boundary
	for i := 0; i < 300; i++ {
		a, err := RandomAddr([]netip.Prefix{p}, nil, nil)
		if err != nil || !p.Contains(a) {
			t.Fatalf("%v %v", a, err)
		}
	}
}

func TestRandomAddrAvoidsAndSkipsAnycast(t *testing.T) {
	p := netip.MustParsePrefix("2001:db8::/120")
	taken := map[netip.Addr]bool{}
	for i := 1; i < 256; i++ { // all but one host value are taken
		a := netip.MustParseAddr("2001:db8::")
		b := a.As16()
		b[15] = byte(i)
		if i != 77 {
			taken[netip.AddrFrom16(b)] = true
		}
	}
	// A fixed byte stream: pick byte, then 16 random bytes whose last byte walks 0..255.
	var stream bytes.Buffer
	for v := 0; v < 256; v++ {
		stream.WriteByte(0)
		stream.Write(append(make([]byte, 15), byte(v)))
	}
	a, err := RandomAddr([]netip.Prefix{p}, &stream, func(a netip.Addr) bool { return taken[a] })
	if err == nil && a.As16()[15] != 77 {
		t.Fatalf("got %v, want host 77 or an error", a)
	}
	if err == nil && a == p.Addr() {
		t.Fatal("returned the anycast address")
	}
}

func TestRandomAddrExhausted(t *testing.T) {
	p := netip.MustParsePrefix("2001:db8::/120")
	_, err := RandomAddr([]netip.Prefix{p}, nil, func(netip.Addr) bool { return true })
	if err == nil {
		t.Fatal("expected error when every address is rejected")
	}
	if _, err := RandomAddr(nil, nil, nil); err == nil {
		t.Fatal("expected error without subnets")
	}
}
