//go:build netplan

package host

import (
	"context"
	"fmt"
	"net/netip"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"pvpn/internal/alloc"
	"pvpn/internal/render"
)

const fxCloudInit = `network:
  version: 2
  ethernets:
    eth0:
      match:
        macaddress: "92:00:0a:68:c0:fb"
      addresses:
      - "2a01:4f8:1c1b:a31::1/64"
      nameservers:
        addresses:
        - 2a01:4ff:ff00::add:2
        - 2a01:4ff:ff00::add:1
      dhcp4: true
      set-name: "eth0"
      routes:
      - on-link: true
        to: "default"
        via: "fe80::1"
`

const fxIPv6 = `network:
  version: 2
  ethernets:
    eth0:
      addresses:
        - 2a01:4f8:1c1b:a31:f765:3f06:68a9:c06d/64
      routes:
        - to: default
          via: fe80::1
        - to: 2a01:4f8:1c1b:a31::/64
          scope: host
          type: local
`

// A second tunnel manager owns table 8000 and mark 4242 in another file. pvpn must keep out of its way.
const fxOther = `network:
  version: 2
  ethernets:
    eth0:
      routes:
        - to: 192.0.2.0/24
          via: 172.31.1.1
          table: 8000
      routing-policy:
        - from: 192.0.2.0/24
          table: 8000
          mark: 4242
          priority: 555
`

const containerScript = `set -e
export DEBIAN_FRONTEND=noninteractive
apt-get update -qq >/dev/null 2>&1
apt-get install -y -qq netplan.io >/dev/null 2>&1
dpkg -s netplan.io | grep '^Version' > /out/version
R=/tmp/root; mkdir -p $R/etc/netplan; cp /fx/*.yaml $R/etc/netplan/; chmod 600 $R/etc/netplan/*.yaml
set +e
netplan generate --root-dir $R >/out/gen.stdout 2>/out/gen.stderr; echo $? >/out/gen.rc
set -e
cp $R/run/systemd/network/*.network /out/
chmod a+r /out/*
netplan get all --root-dir $R > /out/get.yaml
`

// TestNetplanMatrix renders the managed file with pvpn and runs the real netplan of each Ubuntu release.
// Run: go test -tags netplan ./internal/host -run TestNetplanMatrix -v
func TestNetplanMatrix(t *testing.T) {
	if _, err := exec.LookPath("docker"); err != nil {
		t.Skip("docker is not available")
	}
	gw := netip.MustParseAddr("fe80::1")
	mk := func(iface string, n int, addrs ...string) render.Member {
		var as []netip.Addr
		for _, a := range addrs {
			as = append(as, netip.MustParseAddr(a))
		}
		return render.Member{Iface: iface, Table: 5750 + n, Mark: 0x5750 + n, Priority: 100 + n, Addrs: as, From: as[len(as)-1], Gateway: gw}
	}
	devs := []render.Device{{Section: "ethernets", ID: "eth0", Members: []render.Member{
		mk("pvpn-de1", 1, "2a01:4f8:1c1b:a31:1:2:3:4"),
		mk("pvpn-de2", 2, "2a01:4f8:1c1b:a31:5:6:7:8"),
		mk("pvpn-nl1", 3, "2a01:4f8:1c1b:a31:9:a:b:c", "2a01:4f8:1c1b:a31:d:e:f:1"), // rotation: old and new address
	}}}
	content := render.Netplan(devs)

	for _, ver := range []string{"22.04", "24.04", "26.04"} {
		t.Run("ubuntu-"+ver, func(t *testing.T) {
			t.Parallel()
			dir := t.TempDir()
			fx, out := filepath.Join(dir, "fx"), filepath.Join(dir, "out")
			for _, d := range []string{fx, out} {
				if err := os.MkdirAll(d, 0o777); err != nil {
					t.Fatal(err)
				}
			}
			_ = os.Chmod(out, 0o777)
			files := map[string][]byte{"50-cloud-init.yaml": []byte(fxCloudInit), "60-ipv6.yaml": []byte(fxIPv6), "70-other.yaml": []byte(fxOther), ManagedName: content}
			for name, text := range files {
				if err := os.WriteFile(filepath.Join(fx, name), text, 0o644); err != nil {
					t.Fatal(err)
				}
			}
			script := filepath.Join(dir, "run.sh")
			_ = os.WriteFile(script, []byte(containerScript), 0o755)
			cmd := exec.Command("docker", "run", "--rm", "-v", fx+":/fx:ro", "-v", out+":/out", "-v", script+":/run.sh:ro", "ubuntu:"+ver, "bash", "/run.sh")
			if b, err := cmd.CombinedOutput(); err != nil {
				t.Fatalf("container failed: %v\n%s", err, b)
			}
			read := func(n string) string { b, _ := os.ReadFile(filepath.Join(out, n)); return strings.TrimSpace(string(b)) }
			t.Logf("%s, generate exit code %s", read("version"), read("gen.rc"))
			if ents, _ := os.ReadDir(out); true {
				var names []string
				for _, e := range ents {
					names = append(names, e.Name())
				}
				t.Logf("output files: %v; stdout=%q stderr=%q", names, read("gen.stdout"), read("gen.stderr"))
			}
			if rc := read("gen.rc"); rc != "0" {
				err := &CmdError{Cmd: "netplan generate", Code: 1, Stderr: read("gen.stderr")}
				if !onlySystemdNoise(err) {
					t.Fatalf("netplan generate failed (rc %s): %s", rc, read("gen.stderr"))
				}
				t.Logf("generate printed only systemd noise: %s", read("gen.stderr"))
			}
			var text strings.Builder
			ents, _ := os.ReadDir(out)
			for _, e := range ents {
				if strings.HasSuffix(e.Name(), ".network") {
					b, _ := os.ReadFile(filepath.Join(out, e.Name()))
					text.Write(b)
					text.WriteString("\n")
				}
			}
			if err := checkGenerated(text.String(), devs); err != nil {
				t.Fatalf("%v\n--- networkd output:\n%s", err, text.String())
			}
			// The existing definitions survive the merge.
			for _, want := range []string{"Address=2a01:4f8:1c1b:a31::1/64", "Address=2a01:4f8:1c1b:a31:f765:3f06:68a9:c06d/64", "DHCP=ipv4", "Table=8000", "FirewallMark=4242", "Destination=2a01:4f8:1c1b:a31::/64"} {
				if !strings.Contains(text.String(), want) {
					t.Errorf("merged networkd output lacks %q", want)
				}
			}
			// Device lookup works on this release's `netplan get` output.
			get, _ := os.ReadFile(filepath.Join(out, "get.yaml"))
			if ref, err := findDevice(get, "eth0"); err != nil || ref != (DeviceRef{"ethernets", "eth0"}) {
				t.Errorf("findDevice: %+v %v", ref, err)
			}
			// Used-ID scan sees the other file's table, mark, and priority.
			u := alloc.NewUsed()
			mergeNetplanUsed(get, u)
			if !u.Tables[8000] || !u.Marks[4242] || !u.Priorities[555] {
				t.Errorf("used IDs not found: %+v", u)
			}
			_ = context.Background()
			_ = fmt.Sprint()
		})
	}
}
