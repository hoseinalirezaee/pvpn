package proton

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"time"

	"pvpn/internal/state"
)

// Session is the saved login. Its JSON field names match the earlier protonauth tool,
// so an old session file still works.
type Session struct {
	UID          string    `json:"uid"`
	AccessToken  string    `json:"access_token"`
	RefreshToken string    `json:"refresh_token"`
	Scopes       []string  `json:"scopes"`
	AppVersion   string    `json:"app_version"`
	SavedAt      time.Time `json:"saved_at"`
	RefreshedAt  time.Time `json:"refreshed_at,omitzero"`
}

// LoadSession reads a session file. A missing file gives ErrLoginRequired.
func LoadSession(path string) (*Session, error) {
	b, err := os.ReadFile(path)
	if errors.Is(err, os.ErrNotExist) {
		return nil, fmt.Errorf("%w (no session file)", ErrLoginRequired)
	}
	if err != nil {
		return nil, err
	}
	var s Session
	if err := json.Unmarshal(b, &s); err != nil {
		return nil, fmt.Errorf("%w (session file is damaged: %v)", ErrLoginRequired, err)
	}
	if s.UID == "" || s.AccessToken == "" || s.RefreshToken == "" {
		return nil, fmt.Errorf("%w (session file is incomplete)", ErrLoginRequired)
	}
	return &s, nil
}

// SaveSession writes the session with mode 0600, atomically.
func SaveSession(path string, s *Session) error {
	b, err := json.MarshalIndent(s, "", "  ")
	if err != nil {
		return err
	}
	return state.WriteFileAtomic(path, append(b, '\n'), 0o600)
}

// RemoveSession deletes the session file.
func RemoveSession(path string) error {
	if err := os.Remove(path); err != nil && !errors.Is(err, os.ErrNotExist) {
		return err
	}
	return nil
}
