// Package host is the boundary between pvpn and the operating system.
// The System interface lists every side effect. Real implements it with ip, wg, netplan, and systemctl.
package host

import (
	"context"
	"errors"
	"net/netip"
	"time"

	"pvpn/internal/alloc"
	"pvpn/internal/render"
)

// Errors of the address check.
var (
	ErrAddrMissing   = errors.New("address does not exist on the device")
	ErrDADFailed     = errors.New("duplicate address detection failed (dadfailed)")
	ErrAddrTentative = errors.New("address is still tentative")
)

// ErrLinkMissing is returned when a WireGuard interface does not exist.
var ErrLinkMissing = errors.New("interface does not exist")

// DeviceRef is the netplan definition of a kernel device.
type DeviceRef struct {
	Section string // for example "ethernets"
	ID      string // netplan ID
}

// WGStatus is the live state of a WireGuard interface.
type WGStatus struct {
	Exists     bool
	PublicKey  string // own public key
	ListenPort int
	FwMark     int
	PeerKey    string
	Endpoint   string
	Handshake  time.Time // zero when no handshake yet
	RxBytes    int64
	TxBytes    int64
}

// AddrInfo is one IPv6 address on a device.
type AddrInfo struct {
	Addr          netip.Addr
	PrefixLen     int
	Tentative     bool
	DADFailed     bool
	Deprecated    bool
	NoPrefixRoute bool
}

// Clock lets tests control time.
type Clock interface {
	Now() time.Time
	Sleep(ctx context.Context, d time.Duration) error
}

// RealClock uses the system clock.
type RealClock struct{}

func (RealClock) Now() time.Time { return time.Now() }
func (RealClock) Sleep(ctx context.Context, d time.Duration) error {
	t := time.NewTimer(d)
	defer t.Stop()
	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-t.C:
		return nil
	}
}

// System lists every action pvpn takes on the host.
type System interface {
	// Netplan.
	NetplanDevice(ctx context.Context, dev string) (DeviceRef, error)
	NetplanManaged() ([]byte, error)
	// NetplanApply validates content in a temp root, installs it as the managed file (nil removes the file),
	// and runs netplan apply. If anything fails it restores the old file and applies again.
	NetplanApply(ctx context.Context, content []byte, devs []render.Device) error
	// UsedIDs returns tables, marks, and priorities that other things use on the host.
	UsedIDs(ctx context.Context) (*alloc.Used, error)

	// Addresses, routes, and rules.
	ListAddrs(ctx context.Context, dev string) ([]AddrInfo, error)
	// EnsureAddr sets noprefixroute and preferred_lft 0 on the address, then waits up to wait until it
	// exists, has no dadfailed flag, and is not tentative.
	EnsureAddr(ctx context.Context, dev string, ip netip.Addr, wait time.Duration) error
	DelAddr(ctx context.Context, dev string, ip netip.Addr) error
	CheckResources(ctx context.Context, dev string, m render.Member) error

	// WireGuard.
	WGStatus(ctx context.Context, iface string) (WGStatus, error)
	WGSetKey(ctx context.Context, iface, privateKey string, listenPort int) error
	WGSetListenPort(ctx context.Context, iface string, port int) error
	FreePort(ctx context.Context) (int, error)
	// WarmSource sends a few small UDP packets from src to dst:51820. A new source address is then known
	// on the path before the first handshake.
	WarmSource(ctx context.Context, src, dst netip.Addr) error
	// Probe sends an HTTPS request through the interface only. It returns the exit IP the target saw.
	Probe(ctx context.Context, iface string, table, prio int) (string, error)
	ProbeCleanup(ctx context.Context, iface string, table, prio int) error

	// Files in /etc/wireguard.
	ReadWG(name string) (string, error) // os.ErrNotExist when missing
	WriteWG(name, content string) error
	RemoveWG(name string) error
	ListWG() ([]string, error)

	// systemd.
	LinkExists(ctx context.Context, name string) (bool, error)
	UnitActive(ctx context.Context, iface string) (bool, error)
	UnitEnabled(ctx context.Context, iface string) (bool, error)
	UnitStart(ctx context.Context, iface string) error
	UnitStop(ctx context.Context, iface string) error
	UnitEnable(ctx context.Context, iface string) error
	UnitDisable(ctx context.Context, iface string) error
	WriteDropIn(ctx context.Context, iface string) error
	RemoveDropIn(ctx context.Context, iface string) error
	HasDropIn(iface string) bool
}
