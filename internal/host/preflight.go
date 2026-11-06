package host

import (
	"context"
	"fmt"
	"os/exec"
	"strings"
)

// RequiredTools are the programs pvpn runs.
var RequiredTools = []string{"wg", "wg-quick", "ip", "netplan", "systemctl"}

// CheckTools verifies that the tools exist and that systemd-networkd is running.
func CheckTools(ctx context.Context, r Runner) error {
	var missing []string
	for _, t := range RequiredTools {
		if _, err := exec.LookPath(t); err != nil {
			missing = append(missing, t)
		}
	}
	if len(missing) > 0 {
		return fmt.Errorf("missing tools: %s (install wireguard-tools, iproute2, netplan.io, systemd)", strings.Join(missing, ", "))
	}
	if _, err := r.Run(ctx, nil, "systemctl", "is-active", "--quiet", "systemd-networkd"); err != nil {
		return fmt.Errorf("systemd-networkd is not running; pvpn needs the networkd renderer of netplan")
	}
	return nil
}
