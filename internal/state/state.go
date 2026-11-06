// Package state keeps the versioned pvpn state, the operation journal, and the state lock.
package state

import (
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"syscall"
	"time"
)

// Version is the state schema version this build reads and writes.
const Version = 1

// Interface phases.
const (
	PhaseProvisioning = "provisioning" // cert exists, WireGuard not started yet
	PhaseReady        = "ready"
)

// ErrLocked means another pvpn command holds the state lock.
var ErrLocked = errors.New("another pvpn command is running (state lock is busy)")

type State struct {
	Version    int                   `json:"version"`
	Generation int64                 `json:"generation"`
	Groups     map[string]*Group     `json:"groups"`
	Interfaces map[string]*Interface `json:"interfaces"`
	Pending    []*Op                 `json:"pending"`
}

// Group is the saved server selection of a group.
type Group struct {
	Logical    string    `json:"logical"`
	Domain     string    `json:"domain"`
	EntryIPv4  string    `json:"entry_ipv4"`
	EntryIPv6  string    `json:"entry_ipv6"`
	PublicKey  string    `json:"public_key"`
	Label      string    `json:"label"`
	Country    string    `json:"country"`
	City       string    `json:"city"`
	Tier       int       `json:"tier"`
	SelectedAt time.Time `json:"selected_at"`
}

// Interface is the saved allocation and credential of one managed interface.
// The private key is not here. It lives only in the WireGuard file.
type Interface struct {
	Group       string    `json:"group"`
	Device      string    `json:"device"`
	Gateway     string    `json:"gateway"`
	Table       int       `json:"table"`
	Mark        int       `json:"mark"`
	Priority    int       `json:"priority"`
	SourceIP    string    `json:"source_ip"`
	CertSerial  string    `json:"cert_serial"`
	CertName    string    `json:"cert_name"`
	WGPublicKey string    `json:"wg_public_key"`
	CertExpires int64     `json:"cert_expires"`
	CertRefresh int64     `json:"cert_refresh"`
	Phase       string    `json:"phase"`
	ValidatedAt time.Time `json:"validated_at,omitzero"`
	AppliedGen  int64     `json:"applied_generation"`
	CreatedAt   time.Time `json:"created_at"`
}

// Operation kinds in the journal.
const (
	OpCertIssue   = "cert_issue"   // DeviceName set, Serial unknown until the API answers
	OpCertRevoke  = "cert_revoke"  // Serial set
	OpAddrRemove  = "addr_remove"  // Dev, Addr set
	OpFileRemove  = "file_remove"  // Path set
	OpProbeClean  = "probe_clean"  // Iface, table and priority in Txn-less fields
	OpTxn         = "txn"          // multi-step credential change, see Txn
	OpNetplanSync = "netplan_sync" // netplan must be rendered again from state
)

// Op is one pending journal entry.
type Op struct {
	ID         string    `json:"id"`
	Kind       string    `json:"kind"`
	Iface      string    `json:"iface,omitempty"`
	Serial     string    `json:"serial,omitempty"`
	DeviceName string    `json:"device_name,omitempty"`
	Addr       string    `json:"addr,omitempty"`
	Dev        string    `json:"dev,omitempty"`
	Path       string    `json:"path,omitempty"`
	Table      int       `json:"table,omitempty"`
	Priority   int       `json:"priority,omitempty"`
	Txn        *Txn      `json:"txn,omitempty"`
	Note       string    `json:"note,omitempty"`
	CreatedAt  time.Time `json:"created_at"`
}

// Txn kinds and phases.
const (
	TxnRotate  = "rotate"  // new key, cert, and source address; same server
	TxnRenew   = "renew"   // new key and cert; same source address and server
	TxnReplace = "replace" // new server for a group; new keys and certs; same source addresses
	// TxnRotateBatch wraps the rotation of the members of one group. It holds only the source addresses.
	// Its recovery rebuilds the netplan file from the state and removes the addresses that nothing owns.
	TxnRotateBatch = "rotate_batch"

	TxnPrepared  = "prepared"  // new certs exist; nothing changed on the host
	TxnStaged    = "staged"    // candidate resources exist on the host
	TxnCommitted = "committed" // new state and files are installed; cleanup of old resources remains
)

// Txn records what a rollback or a roll-forward needs.
type Txn struct {
	Kind     string      `json:"kind"`
	Phase    string      `json:"phase"`
	Group    string      `json:"group"`
	Members  []TxnMember `json:"members"`
	OldGroup *Group      `json:"old_group,omitempty"`
	NewGroup *Group      `json:"new_group,omitempty"`
}

type TxnMember struct {
	Iface     string    `json:"iface"`
	Old       Interface `json:"old"`
	New       Interface `json:"new"`
	WasActive bool      `json:"was_active"`
	Backup    string    `json:"backup,omitempty"`
}

// NewID returns a random 8-character hex id.
func NewID() string {
	var b [4]byte
	_, _ = rand.Read(b[:])
	return hex.EncodeToString(b[:])
}

func newState() *State {
	return &State{Version: Version, Groups: map[string]*Group{}, Interfaces: map[string]*Interface{}}
}

// InterfaceNames returns saved interface names in sorted order.
func (s *State) InterfaceNames() []string {
	out := make([]string, 0, len(s.Interfaces))
	for n := range s.Interfaces {
		out = append(out, n)
	}
	sort.Strings(out)
	return out
}

// AddOp appends a journal entry and returns it.
func (s *State) AddOp(op *Op) *Op {
	if op.ID == "" {
		op.ID = NewID()
	}
	if op.CreatedAt.IsZero() {
		op.CreatedAt = time.Now().UTC()
	}
	s.Pending = append(s.Pending, op)
	return op
}

// RemoveOp deletes a journal entry by id.
func (s *State) RemoveOp(id string) {
	out := s.Pending[:0]
	for _, op := range s.Pending {
		if op.ID != id {
			out = append(out, op)
		}
	}
	s.Pending = out
}

// OwnsSerial reports whether a certificate serial belongs to this tool.
func (s *State) OwnsSerial(serial string) bool {
	if serial == "" {
		return false
	}
	for _, i := range s.Interfaces {
		if i.CertSerial == serial {
			return true
		}
	}
	for _, op := range s.Pending {
		if op.Serial == serial {
			return true
		}
		if op.Txn != nil {
			for _, m := range op.Txn.Members {
				if m.Old.CertSerial == serial || m.New.CertSerial == serial {
					return true
				}
			}
		}
	}
	return false
}

// Store reads and writes the state directory.
type Store struct {
	Dir  string
	lock *os.File
}

// Open prepares the state directory. With create=false it does not create anything.
func Open(dir string, create bool) (*Store, error) {
	if create {
		if err := os.MkdirAll(dir, 0o700); err != nil {
			return nil, err
		}
		if err := os.Chmod(dir, 0o700); err != nil {
			return nil, err
		}
	}
	return &Store{Dir: dir}, nil
}

func (s *Store) StatePath() string   { return filepath.Join(s.Dir, "state.json") }
func (s *Store) SessionPath() string { return filepath.Join(s.Dir, "session.json") }
func (s *Store) BackupDir() string   { return filepath.Join(s.Dir, "backup") }
func (s *Store) lockPath() string    { return filepath.Join(s.Dir, "pvpn.lock") }

// Lock takes the state lock without waiting. Use exclusive for any command that changes state.
// A shared lock on a missing directory succeeds without a lock file.
func (s *Store) Lock(exclusive bool) error {
	how := syscall.LOCK_SH
	flags := os.O_RDWR
	if exclusive {
		how = syscall.LOCK_EX
		flags |= os.O_CREATE
	}
	f, err := os.OpenFile(s.lockPath(), flags, 0o600)
	if err != nil {
		if !exclusive && errors.Is(err, os.ErrNotExist) {
			return nil
		}
		return err
	}
	if err := syscall.Flock(int(f.Fd()), how|syscall.LOCK_NB); err != nil {
		f.Close()
		if errors.Is(err, syscall.EWOULDBLOCK) {
			return ErrLocked
		}
		return err
	}
	s.lock = f
	return nil
}

// Unlock releases the state lock.
func (s *Store) Unlock() {
	if s.lock != nil {
		_ = syscall.Flock(int(s.lock.Fd()), syscall.LOCK_UN)
		s.lock.Close()
		s.lock = nil
	}
}

// Load reads the state. A missing file gives an empty state.
func (s *Store) Load() (*State, error) {
	b, err := os.ReadFile(s.StatePath())
	if errors.Is(err, os.ErrNotExist) {
		return newState(), nil
	}
	if err != nil {
		return nil, err
	}
	var st State
	if err := json.Unmarshal(b, &st); err != nil {
		return nil, fmt.Errorf("state file %s is damaged: %w", s.StatePath(), err)
	}
	if st.Version > Version {
		return nil, fmt.Errorf("state file version %d is newer than this pvpn (%d)", st.Version, Version)
	}
	if st.Version < 1 {
		return nil, fmt.Errorf("state file has no valid version")
	}
	if st.Groups == nil {
		st.Groups = map[string]*Group{}
	}
	if st.Interfaces == nil {
		st.Interfaces = map[string]*Interface{}
	}
	return &st, nil
}

// Save writes the state atomically: temp file, fsync, rename, directory fsync.
func (s *Store) Save(st *State) error {
	st.Version = Version
	b, err := json.MarshalIndent(st, "", "  ")
	if err != nil {
		return err
	}
	return WriteFileAtomic(s.StatePath(), append(b, '\n'), 0o600)
}

// WriteFileAtomic replaces path with data. Readers see the old or the new file, never a mix.
func WriteFileAtomic(path string, data []byte, mode os.FileMode) error {
	dir := filepath.Dir(path)
	tmp, err := os.CreateTemp(dir, "."+filepath.Base(path)+".*.tmp")
	if err != nil {
		return err
	}
	name := tmp.Name()
	defer os.Remove(name) // no-op after a good rename
	if err := tmp.Chmod(mode); err != nil {
		tmp.Close()
		return err
	}
	if _, err := tmp.Write(data); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Sync(); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	if err := os.Rename(name, path); err != nil {
		return err
	}
	return SyncDir(dir)
}

// SyncDir flushes a directory entry change to disk.
func SyncDir(dir string) error {
	d, err := os.Open(dir)
	if err != nil {
		return err
	}
	defer d.Close()
	return d.Sync()
}
