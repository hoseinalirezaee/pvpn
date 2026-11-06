package host

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"

	"go.yaml.in/yaml/v3"

	"pvpn/internal/alloc"
	"pvpn/internal/render"
	"pvpn/internal/state"
)

var deviceSections = []string{"ethernets", "bonds", "bridges", "vlans"}

// NetplanDevice finds the netplan definition of a kernel device.
// It matches the netplan ID or the set-name. The renderer must be networkd.
func (r *Real) NetplanDevice(ctx context.Context, dev string) (DeviceRef, error) {
	out, err := r.Run.Run(ctx, nil, "netplan", "get", "all")
	if err != nil {
		return DeviceRef{}, fmt.Errorf("netplan get: %w", err)
	}
	return findDevice(out, dev)
}

func findDevice(netplanGet []byte, dev string) (DeviceRef, error) {
	var doc struct {
		Network map[string]any `yaml:"network"`
	}
	if err := yaml.Unmarshal(netplanGet, &doc); err != nil {
		return DeviceRef{}, fmt.Errorf("netplan get: bad YAML: %w", err)
	}
	global, _ := doc.Network["renderer"].(string)
	for _, sec := range deviceSections {
		m, _ := doc.Network[sec].(map[string]any)
		ids := make([]string, 0, len(m))
		for id := range m {
			ids = append(ids, id)
		}
		sort.Strings(ids)
		for _, id := range ids {
			d, _ := m[id].(map[string]any)
			if sn, _ := d["set-name"].(string); id != dev && sn != dev {
				continue
			}
			rend, _ := d["renderer"].(string)
			if rend == "" {
				rend = global
			}
			if rend != "" && rend != "networkd" {
				return DeviceRef{}, fmt.Errorf("netplan device %q uses renderer %q; pvpn needs networkd", id, rend)
			}
			return DeviceRef{Section: sec, ID: id}, nil
		}
	}
	return DeviceRef{}, fmt.Errorf("device %q has no netplan definition (checked %s)", dev, strings.Join(deviceSections, ", "))
}

// NetplanManaged returns the current managed file, or nil when it does not exist.
func (r *Real) NetplanManaged() ([]byte, error) {
	b, err := os.ReadFile(r.managedPath())
	if errors.Is(err, os.ErrNotExist) {
		return nil, nil
	}
	return b, err
}

// buildRoot copies the netplan files to a temp root. It leaves out the managed file
// and adds candidate (if not nil) in its place.
func (r *Real) buildRoot(candidate []byte) (string, error) {
	root, err := os.MkdirTemp("", "pvpn-netplan-")
	if err != nil {
		return "", err
	}
	copyDir := func(src string) error {
		ents, err := os.ReadDir(src)
		if errors.Is(err, os.ErrNotExist) {
			return nil
		}
		if err != nil {
			return err
		}
		dst := filepath.Join(root, src)
		if src == r.NetplanDir {
			dst = filepath.Join(root, "etc", "netplan")
		}
		if err := os.MkdirAll(dst, 0o755); err != nil {
			return err
		}
		for _, e := range ents {
			if e.IsDir() || !strings.HasSuffix(e.Name(), ".yaml") || (src == r.NetplanDir && e.Name() == ManagedName) {
				continue
			}
			b, err := os.ReadFile(filepath.Join(src, e.Name()))
			if err != nil {
				return err
			}
			if err := os.WriteFile(filepath.Join(dst, e.Name()), b, 0o600); err != nil {
				return err
			}
		}
		return nil
	}
	for _, d := range append([]string{r.NetplanDir}, r.NetplanExtra...) {
		if err := copyDir(d); err != nil {
			os.RemoveAll(root)
			return "", err
		}
	}
	if candidate != nil {
		dst := filepath.Join(root, "etc", "netplan")
		_ = os.MkdirAll(dst, 0o755)
		if err := os.WriteFile(filepath.Join(dst, ManagedName), candidate, 0o600); err != nil {
			os.RemoveAll(root)
			return "", err
		}
	}
	return root, nil
}

// validate runs netplan generate in an isolated temp root and checks the networkd output.
func (r *Real) validate(ctx context.Context, content []byte, devs []render.Device) error {
	root, err := r.buildRoot(content)
	if err != nil {
		return err
	}
	defer os.RemoveAll(root)
	_, gerr := r.Run.Run(ctx, nil, "netplan", "generate", "--root-dir", root)
	netdir := filepath.Join(root, "run", "systemd", "network")
	ents, _ := os.ReadDir(netdir)
	if gerr != nil && !(onlySystemdNoise(gerr) && len(ents) > 0) {
		return fmt.Errorf("netplan generate rejected the configuration: %w", gerr)
	}
	var texts []string
	for _, e := range ents {
		if strings.HasSuffix(e.Name(), ".network") {
			b, err := os.ReadFile(filepath.Join(netdir, e.Name()))
			if err != nil {
				return err
			}
			texts = append(texts, string(b))
		}
	}
	return checkGenerated(strings.Join(texts, "\n"), devs)
}

// onlySystemdNoise reports whether a netplan generate error only came from
// a missing systemd in a container or a temp-root run.
func onlySystemdNoise(err error) bool {
	var ce *CmdError
	if !errors.As(err, &ce) {
		return false
	}
	for _, ln := range strings.Split(ce.Stderr, "\n") {
		ln = strings.TrimSpace(ln)
		if ln == "" || strings.Contains(ln, "systemctl") || strings.Contains(ln, "reload request") ||
			strings.Contains(ln, "booted with systemd") || strings.Contains(ln, "Failed to connect to bus") ||
			strings.Contains(ln, "exit status") || strings.Contains(ln, "returned non-zero exit status") {
			continue
		}
		return false
	}
	return true
}

type iniBlock struct {
	name string
	kv   map[string]string
}

func parseINI(text string) []iniBlock {
	var out []iniBlock
	var cur *iniBlock
	for _, ln := range strings.Split(text, "\n") {
		ln = strings.TrimSpace(ln)
		switch {
		case ln == "" || strings.HasPrefix(ln, "#"):
		case strings.HasPrefix(ln, "[") && strings.HasSuffix(ln, "]"):
			out = append(out, iniBlock{name: ln[1 : len(ln)-1], kv: map[string]string{}})
			cur = &out[len(out)-1]
		default:
			if k, v, ok := strings.Cut(ln, "="); ok && cur != nil {
				cur.kv[strings.TrimSpace(k)] = strings.TrimSpace(v)
			}
		}
	}
	return out
}

// checkGenerated verifies that every member has its address, route, and rule in the networkd files.
func checkGenerated(text string, devs []render.Device) error {
	blocks := parseINI(text)
	has := func(section string, want map[string]string) bool {
		for _, b := range blocks {
			if b.name != section {
				continue
			}
			ok := true
			for k, v := range want {
				if b.kv[k] != v {
					ok = false
				}
			}
			if ok {
				return true
			}
		}
		return false
	}
	var miss []string
	for _, d := range devs {
		for _, m := range d.Members {
			for _, a := range m.Addrs {
				if !has("Address", map[string]string{"Address": a.String() + "/128", "PreferredLifetime": "0"}) {
					miss = append(miss, fmt.Sprintf("%s: address %s with PreferredLifetime=0", m.Iface, a))
				}
			}
			if !has("Route", map[string]string{"Gateway": m.Gateway.String(), "PreferredSource": m.From.String(), "Table": strconv.Itoa(m.Table), "GatewayOnLink": "true"}) {
				miss = append(miss, fmt.Sprintf("%s: route table %d via %s src %s", m.Iface, m.Table, m.Gateway, m.From))
			}
			if !has("RoutingPolicyRule", map[string]string{"FirewallMark": strconv.Itoa(m.Mark), "Table": strconv.Itoa(m.Table), "Priority": strconv.Itoa(m.Priority)}) {
				miss = append(miss, fmt.Sprintf("%s: rule mark %d table %d priority %d", m.Iface, m.Mark, m.Table, m.Priority))
			}
		}
	}
	if len(miss) > 0 {
		return fmt.Errorf("netplan generated no networkd entry for: %s", strings.Join(miss, "; "))
	}
	return nil
}

// NetplanApply validates, installs, and applies the managed netplan file.
func (r *Real) NetplanApply(ctx context.Context, content []byte, devs []render.Device) error {
	if err := r.validate(ctx, content, devs); err != nil {
		return err
	}
	old, err := r.NetplanManaged()
	if err != nil {
		return err
	}
	if err := os.MkdirAll(r.BackupDir, 0o700); err != nil {
		return err
	}
	if old != nil {
		if err := state.WriteFileAtomic(filepath.Join(r.BackupDir, ManagedName+".prev"), old, 0o600); err != nil {
			return fmt.Errorf("save previous netplan file: %w", err)
		}
	}
	if err := r.install(content); err != nil {
		return err
	}
	actx, cancel := context.WithTimeout(ctx, r.ApplyTimeout)
	defer cancel()
	if _, aerr := r.Run.Run(actx, nil, "netplan", "apply"); aerr != nil {
		rerr := r.install(old)
		bctx, bcancel := context.WithTimeout(context.WithoutCancel(ctx), r.ApplyTimeout)
		defer bcancel()
		_, rap := r.Run.Run(bctx, nil, "netplan", "apply")
		msg := fmt.Sprintf("netplan apply failed: %v", aerr)
		if rerr != nil || rap != nil {
			msg += fmt.Sprintf(" (restore of the old file also failed: install=%v apply=%v)", rerr, rap)
		} else {
			msg += " (old file restored and applied)"
		}
		return errors.New(msg)
	}
	return nil
}

func (r *Real) install(content []byte) error {
	if content == nil {
		if err := os.Remove(r.managedPath()); err != nil && !errors.Is(err, os.ErrNotExist) {
			return err
		}
		return state.SyncDir(r.NetplanDir)
	}
	return state.WriteFileAtomic(r.managedPath(), content, 0o600)
}

// UsedIDs finds tables, marks, and priorities that the host already uses.
// It reads live rules and routes, the netplan files without the managed one, and the other wg-quick files.
func (r *Real) UsedIDs(ctx context.Context) (*alloc.Used, error) {
	u := alloc.NewUsed()
	for _, fam := range []string{"-4", "-6"} {
		rs, err := r.rules(ctx, fam)
		if err != nil {
			return nil, err
		}
		for _, ru := range rs {
			u.Priorities[ru.Priority] = true
			if m, ok := parseMark(ru.Fwmark); ok {
				u.Marks[m] = true
			}
			if t, err := strconv.Atoi(ru.Table); err == nil {
				u.Tables[t] = true
			}
		}
		out, err := r.Run.Run(ctx, nil, "ip", "-j", fam, "route", "show", "table", "all")
		if err != nil {
			return nil, err
		}
		var routes []jsonRoute
		if err := jsonUnmarshal(out, &routes); err != nil {
			return nil, fmt.Errorf("ip route show: bad JSON: %w", err)
		}
		for _, rt := range routes {
			if t, err := strconv.Atoi(rt.Table); err == nil {
				u.Tables[t] = true
			}
		}
	}
	// Other netplan files (without ours).
	root, err := r.buildRoot(nil)
	if err != nil {
		return nil, err
	}
	defer os.RemoveAll(root)
	if out, err := r.Run.Run(ctx, nil, "netplan", "get", "all", "--root-dir", root); err == nil {
		mergeNetplanUsed(out, u)
	}
	// Other wg-quick files and live fwmarks.
	names, _ := r.ListWG()
	for _, n := range names {
		b, err := os.ReadFile(r.wgPath(n))
		if err != nil {
			continue
		}
		for _, ln := range strings.Split(string(b), "\n") {
			k, v, ok := strings.Cut(strings.TrimSpace(ln), "=")
			if !ok {
				continue
			}
			switch strings.TrimSpace(k) {
			case "FwMark":
				if m, ok := parseMark(v); ok {
					u.Marks[m] = true
				}
			case "Table":
				if t, err := strconv.Atoi(strings.TrimSpace(v)); err == nil {
					u.Tables[t] = true
				}
			}
		}
	}
	if out, err := r.Run.Run(ctx, nil, "wg", "show", "all", "fwmark"); err == nil {
		for _, ln := range strings.Split(string(out), "\n") {
			if f := strings.Fields(ln); len(f) == 2 {
				if m, ok := parseMark(f[1]); ok {
					u.Marks[m] = true
				}
			}
		}
	}
	return u, nil
}

func mergeNetplanUsed(netplanGet []byte, u *alloc.Used) {
	var doc struct {
		Network map[string]any `yaml:"network"`
	}
	if yaml.Unmarshal(netplanGet, &doc) != nil {
		return
	}
	asInt := func(v any) (int, bool) {
		switch x := v.(type) {
		case int:
			return x, true
		case string:
			n, err := strconv.Atoi(x)
			return n, err == nil
		}
		return 0, false
	}
	for _, sec := range deviceSections {
		devs, _ := doc.Network[sec].(map[string]any)
		for _, d := range devs {
			dm, _ := d.(map[string]any)
			for _, rt := range asList(dm["routes"]) {
				if t, ok := asInt(rt["table"]); ok {
					u.Tables[t] = true
				}
			}
			for _, rp := range asList(dm["routing-policy"]) {
				if t, ok := asInt(rp["table"]); ok {
					u.Tables[t] = true
				}
				if m, ok := asInt(rp["mark"]); ok {
					u.Marks[m] = true
				}
				if p, ok := asInt(rp["priority"]); ok {
					u.Priorities[p] = true
				}
			}
		}
	}
}

func asList(v any) []map[string]any {
	var out []map[string]any
	l, _ := v.([]any)
	for _, x := range l {
		if m, ok := x.(map[string]any); ok {
			out = append(out, m)
		}
	}
	return out
}
