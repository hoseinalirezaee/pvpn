package proton

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestLoginOK(t *testing.T) {
	f := newFake(t, "alice", "s3cret")
	c := f.client()
	s, err := c.Login(context.Background(), "alice", []byte("s3cret"), nil)
	if err != nil {
		t.Fatal(err)
	}
	if s.UID != "uid-1" || s.AccessToken != "AT-1" || s.RefreshToken != "RT-1" || len(s.Scopes) != 2 {
		t.Fatalf("session: %+v", s)
	}
	info, err := c.Info(context.Background())
	if err != nil || info.MaxTier != 2 || info.MaxConnect != 11 {
		t.Fatalf("info: %+v %v", info, err)
	}
}

func TestLoginWrongPassword(t *testing.T) {
	f := newFake(t, "alice", "s3cret")
	_, err := f.client().Login(context.Background(), "alice", []byte("wrong"), nil)
	var ae *APIError
	if !errors.As(err, &ae) || ae.Code != 8002 {
		t.Fatalf("want API error 8002, got %v", err)
	}
}

func TestLoginRejectsBadServerProof(t *testing.T) {
	f := newFake(t, "alice", "s3cret")
	f.badProof = true
	c := f.client()
	_, err := c.Login(context.Background(), "alice", []byte("s3cret"), nil)
	if err == nil || !strings.Contains(err.Error(), "server proof") {
		t.Fatalf("want server proof error, got %v", err)
	}
	if c.Sess != nil {
		t.Fatal("client keeps a session after a bad server proof")
	}
}

func TestLoginTOTP(t *testing.T) {
	f := newFake(t, "alice", "s3cret")
	f.twoFA, f.totpCode = 1, "123456"
	asked := 0
	s, err := f.client().Login(context.Background(), "alice", []byte("s3cret"), func() (string, error) { asked++; return "123456", nil })
	if err != nil || s == nil || asked != 1 {
		t.Fatalf("login with TOTP: %v asked=%d", err, asked)
	}
	// Wrong code: the session must be logged out.
	f2 := newFake(t, "alice", "s3cret")
	f2.twoFA, f2.totpCode = 1, "123456"
	_, err = f2.client().Login(context.Background(), "alice", []byte("s3cret"), func() (string, error) { return "000000", nil })
	if err == nil || f2.loggedOut != 1 {
		t.Fatalf("want error and logout, got err=%v loggedOut=%d", err, f2.loggedOut)
	}
}

func TestLoginFIDO2OnlyAndNoCallback(t *testing.T) {
	f := newFake(t, "alice", "s3cret")
	f.twoFA = 2
	_, err := f.client().Login(context.Background(), "alice", []byte("s3cret"), func() (string, error) { return "1", nil })
	if !errors.Is(err, ErrUnsupported2FA) || f.loggedOut != 1 {
		t.Fatalf("fido2: err=%v loggedOut=%d", err, f.loggedOut)
	}
	f = newFake(t, "alice", "s3cret")
	f.twoFA = 1
	_, err = f.client().Login(context.Background(), "alice", []byte("s3cret"), nil)
	if err == nil || f.loggedOut != 1 {
		t.Fatalf("no callback: err=%v loggedOut=%d", err, f.loggedOut)
	}
}

func TestRefreshOn401SavesTokens(t *testing.T) {
	f := newFake(t, "alice", "x")
	path := filepath.Join(t.TempDir(), "session.json")
	s := f.session()
	if err := SaveSession(path, s); err != nil {
		t.Fatal(err)
	}
	f.accessTok = "AT-expired-now-new" // the API now refuses the saved access token
	c := f.client()
	c.Sess, c.SessPath = s, path
	if _, err := c.Info(context.Background()); err != nil {
		t.Fatal(err)
	}
	if c.Refreshed != 1 || f.refreshes != 1 {
		t.Fatalf("refresh count: client=%d api=%d", c.Refreshed, f.refreshes)
	}
	saved, err := LoadSession(path)
	if err != nil || saved.RefreshToken != "RT-2" || saved.AccessToken != "AT-2" {
		t.Fatalf("saved session not updated: %+v %v", saved, err)
	}
	fi, _ := os.Stat(path)
	if fi.Mode().Perm() != 0o600 {
		t.Fatalf("session mode %o", fi.Mode().Perm())
	}
}

func TestRefreshRefusedMeansLoginRequired(t *testing.T) {
	f := newFake(t, "alice", "x")
	s := f.session()
	f.accessTok = "other"
	f.refreshFail = true
	c := f.client()
	c.Sess, c.SessPath = s, filepath.Join(t.TempDir(), "s.json")
	_, err := c.Info(context.Background())
	if !errors.Is(err, ErrLoginRequired) {
		t.Fatalf("want ErrLoginRequired, got %v", err)
	}
	if _, serr := os.Stat(c.SessPath); serr == nil {
		t.Fatal("a failed refresh must not write the session file")
	}
}

func TestNoRefreshModeNeverRefreshes(t *testing.T) {
	f := newFake(t, "alice", "x")
	s := f.session()
	f.accessTok = "other"
	c := f.client()
	c.Sess, c.SessPath, c.NoRefresh = s, filepath.Join(t.TempDir(), "s.json"), true
	_, err := c.Info(context.Background())
	if !errors.Is(err, ErrLoginRequired) {
		t.Fatalf("want ErrLoginRequired, got %v", err)
	}
	if f.refreshes != 0 || c.Refreshed != 0 || s.RefreshToken != "RT-1" {
		t.Fatalf("dry run consumed the refresh token: api=%d client=%d token=%s", f.refreshes, c.Refreshed, s.RefreshToken)
	}
	if _, serr := os.Stat(c.SessPath); serr == nil {
		t.Fatal("no-refresh mode wrote the session file")
	}
}

func TestNoSessionMeansLoginRequired(t *testing.T) {
	c := newFake(t, "a", "b").client()
	if _, err := c.Info(context.Background()); !errors.Is(err, ErrLoginRequired) {
		t.Fatalf("got %v", err)
	}
	if _, err := LoadSession(filepath.Join(t.TempDir(), "none.json")); !errors.Is(err, ErrLoginRequired) {
		t.Fatalf("got %v", err)
	}
}

func TestGetRetriesOn503(t *testing.T) {
	f := newFake(t, "alice", "x")
	f.fail503 = 2
	c := f.client()
	c.Sess = f.session()
	if _, err := c.Info(context.Background()); err != nil {
		t.Fatalf("should recover after two 503: %v", err)
	}
	f.fail503 = 10
	if _, err := c.Info(context.Background()); err == nil {
		t.Fatal("should fail after the retry budget")
	}
}

func TestLogicalsDecodeAndQuery(t *testing.T) {
	f := newFake(t, "alice", "x")
	c := f.client()
	c.Sess = f.session()
	ls, err := c.Logicals(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if len(ls) != 2 {
		t.Fatalf("got %d logicals (IPv6 query flag missing?)", len(ls))
	}
	de := ls[0]
	if de.Name != "DE#1" || de.Features != 28 || de.Load != 40 || de.City != "Frankfurt" || len(de.Servers) != 1 {
		t.Fatalf("logical: %+v", de)
	}
	p := de.Servers[0]
	if p.EntryIPv6 != "2001:db8::10" || p.Label != "3" || p.X25519PublicKey != "PUB" || p.Domain != "node-de-1.protonvpn.net" {
		t.Fatalf("physical: %+v", p)
	}
	if ls[1].City != "" {
		t.Fatalf("null city should decode as empty: %q", ls[1].City)
	}
}

func TestCertLifecycle(t *testing.T) {
	f := newFake(t, "alice", "x")
	c := f.client()
	c.Sess = f.session()
	cred, err := NewCredential()
	if err != nil {
		t.Fatal(err)
	}
	cert, err := c.CreateCert(context.Background(), CertRequest{DeviceName: "pvpn-a-1234", Label: "3", PeerName: "DE#1", PeerIP: "1.2.3.4", PeerPubKey: "PUB", EdPubKey: cred.EdPublic})
	if err != nil || cert.Serial != "SN1" || cert.Expiration != 2000000000 {
		t.Fatalf("create: %+v %v", cert, err)
	}
	b := f.lastCertBody
	feats := b["Features"].(map[string]any)
	if b["Mode"] != "persistent" || b["DeviceName"] != "pvpn-a-1234" || feats["Bouncing"] != "3" || feats["peerName"] != "DE#1" || feats["peerIp"] != "1.2.3.4" || feats["peerPublicKey"] != "PUB" || feats["platform"] != "Linux" {
		t.Fatalf("request body: %+v", b)
	}
	list, err := c.ListCerts(context.Background())
	if err != nil || len(list) != 1 || list[0].Serial != "SN1" || list[0].DeviceName != "pvpn-a-1234" {
		t.Fatalf("list: %+v %v", list, err)
	}
	if err := c.DeleteCert(context.Background(), "SN1"); err != nil {
		t.Fatal(err)
	}
	if err := c.DeleteCert(context.Background(), "SN1"); err != nil { // already gone
		t.Fatalf("second delete: %v", err)
	}
	if err := c.DeleteCert(context.Background(), ""); err == nil {
		t.Fatal("empty serial must fail")
	}
}

func TestListCertsPaginates(t *testing.T) {
	f := newFake(t, "alice", "x")
	c := f.client()
	c.Sess = f.session()
	for i := 0; i < 230; i++ {
		f.certSeq++
		s := fmt.Sprintf("SN%03d", f.certSeq)
		f.certs[s] = map[string]any{"SerialNumber": s, "DeviceName": "d", "Mode": "persistent"}
	}
	list, err := c.ListCerts(context.Background())
	if err != nil || len(list) != 230 {
		t.Fatalf("got %d certs, err %v", len(list), err)
	}
}

func TestCredential(t *testing.T) {
	a, err := NewCredential()
	if err != nil {
		t.Fatal(err)
	}
	b, _ := NewCredential()
	if a.WGPrivate == b.WGPrivate || a.WGPublic == b.WGPublic {
		t.Fatal("credentials repeat")
	}
	pub, err := PublicFromPrivate(a.WGPrivate)
	if err != nil || pub != a.WGPublic {
		t.Fatalf("public key mismatch: %v %v", pub, err)
	}
	if len(a.EdPublic) != 32 {
		t.Fatalf("ed25519 public key length %d", len(a.EdPublic))
	}
	if _, err := PublicFromPrivate("###"); err == nil {
		t.Fatal("bad key must fail")
	}
}

func TestSessionFileModeAndAtomic(t *testing.T) {
	path := filepath.Join(t.TempDir(), "d", "session.json")
	_ = os.MkdirAll(filepath.Dir(path), 0o700)
	if err := SaveSession(path, &Session{UID: "u", AccessToken: "a", RefreshToken: "r"}); err != nil {
		t.Fatal(err)
	}
	fi, _ := os.Stat(path)
	if fi.Mode().Perm() != 0o600 {
		t.Fatalf("mode %o", fi.Mode().Perm())
	}
	_ = os.WriteFile(path, []byte(`{"uid":"u"}`), 0o600)
	if _, err := LoadSession(path); !errors.Is(err, ErrLoginRequired) {
		t.Fatalf("incomplete session: %v", err)
	}
	if err := RemoveSession(path); err != nil {
		t.Fatal(err)
	}
	if err := RemoveSession(path); err != nil {
		t.Fatalf("second remove: %v", err)
	}
}

func TestRateLimitErrorMentionsRetryAfter(t *testing.T) {
	f := newFake(t, "alice", "x")
	f.rateLimitCerts = true
	c := f.client()
	c.Sess = f.session()
	_, err := c.CreateCert(context.Background(), CertRequest{DeviceName: "d", EdPubKey: make([]byte, 32)})
	var ae *APIError
	if !errors.As(err, &ae) || ae.HTTP != 429 || ae.Code != 2028 || ae.RetryAfter.Seconds() != 90 {
		t.Fatalf("got %#v", err)
	}
	if !strings.Contains(err.Error(), "retry after 1m30s") {
		t.Fatalf("message: %v", err)
	}
}
