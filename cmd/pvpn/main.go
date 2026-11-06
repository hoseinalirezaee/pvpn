// Command pvpn manages Proton VPN WireGuard interfaces from a YAML config.
package main

import (
	"bufio"
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"text/tabwriter"
	"time"

	"pvpn/internal/config"
	"pvpn/internal/engine"
	"pvpn/internal/host"
	"pvpn/internal/proton"
	"pvpn/internal/selector"
	"pvpn/internal/state"
)

var version = "dev"

const defaultConfig = "/etc/pvpn/config.yaml"

const usage = `pvpn manages Proton VPN WireGuard interfaces.

Usage: pvpn <command> [flags]

Commands:
  login                         Log in to Proton (asks for user name, password, and TOTP when needed).
  logout                        Revoke the API session and remove the local session file.
  servers [--group G]           List the servers that match the group filters.
  status                        Show selections, interface health, certificate expiry, pending work.
  reconcile [--dry-run]         Make the managed resources match the config.
  rotate [--group G | --interface I] [--new-server]
                                Give interfaces a new key, certificate, and source address.
                                With --new-server, each group also moves to another server (not with --interface).
  version                       Print the version.

Every command accepts --config PATH (default ` + defaultConfig + `).
Run as root.
`

func main() {
	os.Exit(run(os.Args[1:], os.Stdin, os.Stdout, os.Stderr))
}

// Exit codes.
const (
	exitOK     = 0
	exitError  = 1
	exitUsage  = 2
	exitLogin  = 3
	exitLocked = 4
)

func run(args []string, stdin io.Reader, stdout, stderr io.Writer) int {
	if len(args) == 0 || args[0] == "-h" || args[0] == "--help" || args[0] == "help" {
		fmt.Fprint(stdout, usage)
		if len(args) == 0 {
			return exitUsage
		}
		return exitOK
	}
	cmd, rest := args[0], args[1:]
	if cmd == "version" {
		fmt.Fprintln(stdout, "pvpn", version)
		return exitOK
	}
	fs := flag.NewFlagSet("pvpn "+cmd, flag.ContinueOnError)
	fs.SetOutput(stderr)
	cfgPath := fs.String("config", defaultConfig, "config file")
	var group, iface *string
	var dry, newServer *bool
	switch cmd {
	case "servers":
		group = fs.String("group", "", "only this group")
	case "reconcile":
		dry = fs.Bool("dry-run", false, "show planned actions; change nothing")
	case "rotate":
		group = fs.String("group", "", "rotate the interfaces of this group")
		iface = fs.String("interface", "", "rotate this interface")
		newServer = fs.Bool("new-server", false, "also move each group to another server that matches its filters")
	case "login", "logout", "status":
	default:
		fmt.Fprintf(stderr, "pvpn: unknown command %q\n\n%s", cmd, usage)
		return exitUsage
	}
	if err := fs.Parse(rest); err != nil {
		return exitUsage
	}
	if fs.NArg() > 0 {
		fmt.Fprintf(stderr, "pvpn: unexpected argument %q\n", fs.Arg(0))
		return exitUsage
	}
	if cmd == "rotate" && *group != "" && *iface != "" {
		fmt.Fprintln(stderr, "pvpn: --group and --interface cannot be used together")
		return exitUsage
	}
	if cmd == "rotate" && *newServer && *iface != "" {
		fmt.Fprintln(stderr, "pvpn: --new-server cannot be used with --interface (a server belongs to a group)")
		return exitUsage
	}
	if os.Geteuid() != 0 {
		fmt.Fprintln(stderr, "pvpn: run as root (it changes network configuration and reads /etc/netplan)")
		return exitError
	}

	cfg, err := config.Load(*cfgPath)
	if err != nil {
		fmt.Fprintf(stderr, "pvpn: %v\n", err)
		return exitUsage
	}
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	a := &app{cfg: cfg, in: bufio.NewReader(stdin), out: stdout, err: stderr}
	switch cmd {
	case "login":
		err = a.login(ctx)
	case "logout":
		err = a.logout(ctx)
	case "servers":
		err = a.servers(ctx, *group)
	case "status":
		err = a.status(ctx)
	case "reconcile":
		err = a.reconcile(ctx, *dry)
	case "rotate":
		err = a.rotate(ctx, engine.RotateSel{Group: *group, Interface: *iface, NewServer: *newServer})
	}
	switch {
	case err == nil:
		return exitOK
	case errors.Is(err, proton.ErrLoginRequired):
		fmt.Fprintf(stderr, "pvpn: %v\n", err)
		return exitLogin
	case errors.Is(err, state.ErrLocked):
		fmt.Fprintf(stderr, "pvpn: %v\n", err)
		return exitLocked
	default:
		fmt.Fprintf(stderr, "pvpn: %v\n", err)
		return exitError
	}
}

type app struct {
	cfg *config.Config
	in  *bufio.Reader
	out io.Writer
	err io.Writer
}

func (a *app) logf(format string, args ...any) {
	fmt.Fprintf(a.err, "pvpn: "+format+"\n", args...)
}

// open prepares the state directory and the lock. modifying commands take an exclusive lock.
func (a *app) open(modifying bool) (*state.Store, func(), error) {
	store, err := state.Open(a.cfg.Paths.StateDir, modifying)
	if err != nil {
		return nil, nil, err
	}
	if err := store.Lock(modifying); err != nil {
		return nil, nil, err
	}
	return store, store.Unlock, nil
}

func (a *app) client(store *state.Store, noRefresh bool) (*proton.Client, error) {
	sess, err := proton.LoadSession(store.SessionPath())
	if err != nil {
		return nil, err
	}
	c := proton.New(sess, store.SessionPath())
	c.NoRefresh = noRefresh
	return c, nil
}

func (a *app) engine(store *state.Store, api engine.API) *engine.Engine {
	e := engine.New(a.cfg, store, api, host.NewReal(store.BackupDir()))
	e.Logf = a.logf
	return e
}

// ---- login and logout ----

func (a *app) prompt(label string) (string, error) {
	fmt.Fprint(a.err, label)
	line, err := a.in.ReadString('\n')
	if err != nil && (err != io.EOF || line == "") {
		return "", err
	}
	return strings.TrimSpace(line), nil
}

func (a *app) login(ctx context.Context) error {
	if !isTerminal(int(os.Stdin.Fd())) {
		return errors.New("login needs a terminal (it asks for a hidden password)")
	}
	store, unlock, err := a.open(true)
	if err != nil {
		return err
	}
	defer unlock()

	user, err := a.prompt("Proton user name: ")
	if err != nil || user == "" {
		return errors.New("no user name given")
	}
	fmt.Fprint(a.err, "Password: ")
	pass, err := readPassword(int(os.Stdin.Fd()))
	fmt.Fprintln(a.err)
	if err != nil || len(pass) == 0 {
		return errors.New("no password given")
	}
	defer func() {
		for i := range pass {
			pass[i] = 0
		}
	}()
	c := proton.New(nil, store.SessionPath())
	sess, err := c.Login(ctx, user, pass, func() (string, error) {
		code, err := a.prompt("TOTP code: ")
		if err != nil || code == "" {
			return "", errors.New("no TOTP code given")
		}
		return code, nil
	})
	if err != nil {
		return err
	}
	// Replace an older session on the server (best effort), then save the new one.
	if old, err := proton.LoadSession(store.SessionPath()); err == nil {
		oc := proton.New(old, store.SessionPath())
		octx, cancel := context.WithTimeout(context.WithoutCancel(ctx), 15*time.Second)
		_ = oc.Logout(octx)
		cancel()
	}
	if err := proton.SaveSession(store.SessionPath(), sess); err != nil {
		lctx, cancel := context.WithTimeout(context.WithoutCancel(ctx), 15*time.Second)
		_ = c.Logout(lctx)
		cancel()
		return fmt.Errorf("save session: %w (the new session was logged out)", err)
	}
	info, err := c.Info(ctx)
	if err != nil {
		a.logf("logged in, but the account check failed: %v", err)
		return nil
	}
	fmt.Fprintf(a.out, "logged in: plan %s, max tier %d, up to %d connections\n", info.PlanName, info.MaxTier, info.MaxConnect)
	return nil
}

func (a *app) logout(ctx context.Context) error {
	store, unlock, err := a.open(true)
	if err != nil {
		return err
	}
	defer unlock()
	sess, err := proton.LoadSession(store.SessionPath())
	if err != nil {
		if errors.Is(err, proton.ErrLoginRequired) {
			fmt.Fprintln(a.out, "not logged in")
			return nil
		}
		return err
	}
	c := proton.New(sess, store.SessionPath())
	if err := c.Logout(ctx); err != nil {
		return fmt.Errorf("revoke session: %w (the local session file stays)", err)
	}
	if err := proton.RemoveSession(store.SessionPath()); err != nil {
		return err
	}
	fmt.Fprintln(a.out, "logged out; session file removed")
	return nil
}

// ---- servers ----

func (a *app) servers(ctx context.Context, only string) error {
	if only != "" {
		if _, ok := a.cfg.Groups[only]; !ok {
			return fmt.Errorf("group %q is not in the config", only)
		}
	}
	store, unlock, err := a.open(true) // a token refresh writes the session file
	if err != nil {
		return err
	}
	defer unlock()
	c, err := a.client(store, false)
	if err != nil {
		return err
	}
	info, err := c.Info(ctx)
	if err != nil {
		return err
	}
	logicals, err := c.Logicals(ctx)
	if err != nil {
		return err
	}
	st, err := store.Load()
	if err != nil {
		return err
	}
	for _, name := range a.cfg.GroupNames() {
		if only != "" && name != only {
			continue
		}
		gc := a.cfg.Groups[name]
		cands, funnel := selector.Match(logicals, selector.FromConfig(gc.Server, info.MaxTier), false)
		fmt.Fprintf(a.out, "group %s (%d eligible endpoints, select %s)\n", name, len(cands), gc.Server.Select)
		if len(cands) == 0 {
			fmt.Fprintf(a.out, "  %v\n\n", &selector.NoCandidatesError{Funnel: funnel})
			continue
		}
		tw := tabwriter.NewWriter(a.out, 2, 4, 2, ' ', 0)
		fmt.Fprintln(tw, "  \tNAME\tCITY\tLOAD\tTIER\tFEATURES\tMACHINE\tENTRY IPV6")
		for _, c := range cands {
			mark := " "
			if g := st.Groups[name]; g != nil && g.Logical == c.Logical.Name && g.Domain == c.Server.Domain {
				mark = "*"
			}
			fmt.Fprintf(tw, "%s\t%s\t%s\t%d\t%d\t%s\t%s\t%s\n", mark, c.Logical.Name, c.Logical.City, c.Logical.Load, c.Logical.Tier,
				features(selector.Features(c.Logical)), c.Server.Domain, c.Server.EntryIPv6)
		}
		tw.Flush()
		fmt.Fprintln(a.out)
	}
	fmt.Fprintln(a.out, "* = saved selection")
	return nil
}

func features(f int) string {
	var out []string
	for _, x := range []struct {
		bit  int
		name string
	}{{config.FeatSecureCore, "secure_core"}, {config.FeatTor, "tor"}, {config.FeatP2P, "p2p"}, {config.FeatFree, "free"}} {
		if f&x.bit != 0 {
			out = append(out, x.name)
		}
	}
	if len(out) == 0 {
		return "-"
	}
	return strings.Join(out, ",")
}

// ---- status, reconcile, rotate ----

func (a *app) status(ctx context.Context) error {
	store, unlock, err := a.open(false)
	if err != nil {
		return err
	}
	defer unlock()
	if err := host.CheckTools(ctx, host.ExecRunner{}); err != nil {
		a.logf("warning: %v", err)
	}
	e := a.engine(store, nil)
	r, err := e.Status(ctx)
	if err != nil {
		return err
	}
	if sess, err := proton.LoadSession(store.SessionPath()); err != nil {
		fmt.Fprintln(a.out, "session: none (run `pvpn login`)")
	} else {
		fmt.Fprintf(a.out, "session: saved %s ago\n", time.Since(sess.SavedAt).Round(time.Minute))
	}
	fmt.Fprintln(a.out, "\nGroups:")
	tw := tabwriter.NewWriter(a.out, 2, 4, 2, ' ', 0)
	for _, g := range r.Groups {
		fmt.Fprintf(tw, "  %s\t%s\t%s\t[%s]\tselected %s\t%s\n", g.Name, g.Logical, g.Domain, g.EntryIPv6, g.SelectedAt.Format("2006-01-02"), strings.Join(g.Members, ","))
	}
	tw.Flush()
	fmt.Fprintln(a.out, "\nInterfaces:")
	tw = tabwriter.NewWriter(a.out, 2, 4, 2, ' ', 0)
	fmt.Fprintln(tw, "  NAME\tGROUP\tUNIT\tHANDSHAKE\tSOURCE IPV6\tADDRESS FLAGS\tTABLE/MARK/PRIO\tCERT SERIAL\tCERT EXPIRES")
	for _, i := range r.Interfaces {
		unit := "stopped"
		if i.Active {
			unit = "running"
		}
		if i.Enabled {
			unit += ",enabled"
		}
		hs := "never"
		if i.Handshake >= 0 {
			hs = i.Handshake.String() + " ago"
		}
		exp := "-"
		if !i.CertExpires.IsZero() {
			exp = fmt.Sprintf("%s (%d days)", i.CertExpires.Format("2006-01-02"), int(time.Until(i.CertExpires).Hours()/24))
		}
		fmt.Fprintf(tw, "  %s\t%s\t%s\t%s\t%s\t%s\t%d/0x%x/%d\t%s\t%s\n", i.Name, i.Group, unit, hs, i.SourceIP, strings.TrimSpace(i.AddrFlags), i.Table, i.Mark, i.Prio, i.CertSerial, exp)
	}
	tw.Flush()
	for _, i := range r.Interfaces {
		for _, w := range i.Warnings {
			fmt.Fprintf(a.out, "  warning: %s: %s\n", i.Name, w)
		}
	}
	fmt.Fprintln(a.out, "\nPending operations:")
	if len(r.Pending) == 0 {
		fmt.Fprintln(a.out, "  none")
	}
	for _, p := range r.Pending {
		fmt.Fprintf(a.out, "  %s  %s  %s\n", p.ID, p.Kind, p.Detail)
	}
	for _, w := range r.Warnings {
		fmt.Fprintf(a.out, "\nwarning: %s\n", w)
	}
	return nil
}

func (a *app) reconcile(ctx context.Context, dry bool) error {
	store, unlock, err := a.open(!dry)
	if err != nil {
		return err
	}
	defer unlock()
	if err := host.CheckTools(ctx, host.ExecRunner{}); err != nil {
		return err
	}
	c, err := a.client(store, dry)
	if err != nil {
		return err
	}
	e := a.engine(store, c)
	pl, err := e.Reconcile(ctx, dry)
	if dry {
		if pl != nil {
			fmt.Fprintln(a.out, "Planned actions (dry run, nothing changed):")
			fmt.Fprint(a.out, pl.String())
		}
		return err
	}
	if err != nil {
		return err
	}
	if pl.Empty() {
		fmt.Fprintln(a.out, "nothing to do: the host matches the config")
	} else {
		fmt.Fprintf(a.out, "reconcile done: %d action(s)\n", len(pl.Actions))
	}
	return nil
}

func (a *app) rotate(ctx context.Context, sel engine.RotateSel) error {
	if sel.Group != "" && sel.Interface != "" {
		return errors.New("--group and --interface cannot be used together")
	}
	store, unlock, err := a.open(true)
	if err != nil {
		return err
	}
	defer unlock()
	if err := host.CheckTools(ctx, host.ExecRunner{}); err != nil {
		return err
	}
	c, err := a.client(store, false)
	if err != nil {
		return err
	}
	e := a.engine(store, c)
	if err := e.Load(); err != nil {
		return err
	}
	if err := e.Rotate(ctx, sel); err != nil {
		return err
	}
	fmt.Fprintln(a.out, "rotation done")
	return nil
}

// ---- terminal input ----

func isTerminal(fd int) bool {
	var t syscall.Termios
	_, _, e := syscall.Syscall(syscall.SYS_IOCTL, uintptr(fd), uintptr(syscall.TCGETS), uintptr(unsafePointer(&t)))
	return e == 0
}

// readPassword reads a line with echo turned off.
func readPassword(fd int) ([]byte, error) {
	var old syscall.Termios
	if _, _, e := syscall.Syscall(syscall.SYS_IOCTL, uintptr(fd), uintptr(syscall.TCGETS), uintptr(unsafePointer(&old))); e != 0 {
		return nil, e
	}
	noecho := old
	noecho.Lflag &^= syscall.ECHO
	if _, _, e := syscall.Syscall(syscall.SYS_IOCTL, uintptr(fd), uintptr(syscall.TCSETS), uintptr(unsafePointer(&noecho))); e != 0 {
		return nil, e
	}
	restore := func() {
		syscall.Syscall(syscall.SYS_IOCTL, uintptr(fd), uintptr(syscall.TCSETS), uintptr(unsafePointer(&old)))
	}
	defer restore()
	sig := make(chan os.Signal, 1)
	signal.Notify(sig, os.Interrupt, syscall.SIGTERM)
	defer signal.Stop(sig)
	go func() {
		if _, ok := <-sig; ok {
			restore()
			os.Exit(130)
		}
	}()
	var pw []byte
	buf := make([]byte, 1)
	for {
		n, err := os.Stdin.Read(buf)
		if n == 1 {
			if buf[0] == '\n' || buf[0] == '\r' {
				return pw, nil
			}
			pw = append(pw, buf[0])
		}
		if err != nil {
			if err == io.EOF && len(pw) > 0 {
				return pw, nil
			}
			return pw, err
		}
	}
}
