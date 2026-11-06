package proton

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	srp "github.com/ProtonMail/go-srp"
)

// fakeAPI is a small Proton API double. It runs the real SRP server code.
type fakeAPI struct {
	t        *testing.T
	srv      *httptest.Server
	modulus  string
	user     string
	salt     []byte
	verifier []byte

	mu             sync.Mutex
	twoFA          int // value of 2FA.Enabled in the /auth answer
	totpCode       string
	badProof       bool
	accessTok      string // the access token the API accepts
	refreshTok     string // the refresh token the API accepts
	refreshFail    bool
	refreshes      int
	fail503        int // number of GET requests to fail with 503 first
	rateLimitCerts bool
	loggedOut      int
	srpSrv         *srp.Server

	certs        map[string]map[string]any // serial -> cert
	certSeq      int
	lastCertBody map[string]any
}

func newFake(t *testing.T, user, pass string) *fakeAPI {
	t.Helper()
	mod, err := os.ReadFile("testdata/modulus.asc")
	if err != nil {
		t.Fatal(err)
	}
	f := &fakeAPI{t: t, modulus: string(mod), user: user, salt: []byte("0123456789"), accessTok: "AT-1", refreshTok: "RT-1", certs: map[string]map[string]any{}}
	a, err := srp.NewAuthForVerifier([]byte(pass), f.modulus, f.salt)
	if err != nil {
		t.Fatal(err)
	}
	f.verifier, err = a.GenerateVerifier(2048)
	if err != nil {
		t.Fatal(err)
	}
	f.srv = httptest.NewServer(http.HandlerFunc(f.handle))
	t.Cleanup(f.srv.Close)
	return f
}

func (f *fakeAPI) client() *Client {
	return &Client{BaseURL: f.srv.URL, HTTP: f.srv.Client(), Sleep: func(d time.Duration) {}}
}

func (f *fakeAPI) session() *Session {
	return &Session{UID: "uid-1", AccessToken: f.accessTok, RefreshToken: f.refreshTok, AppVersion: appVersion}
}

func reply(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}

func ok(extra map[string]any) map[string]any {
	m := map[string]any{"Code": 1000}
	for k, v := range extra {
		m[k] = v
	}
	return m
}

func (f *fakeAPI) authorized(r *http.Request) bool {
	return r.Header.Get("Authorization") == "Bearer "+f.accessTok && r.Header.Get("x-pm-uid") == "uid-1"
}

func (f *fakeAPI) handle(w http.ResponseWriter, r *http.Request) {
	f.mu.Lock()
	defer f.mu.Unlock()
	var body map[string]any
	if r.Body != nil {
		_ = json.NewDecoder(r.Body).Decode(&body)
	}
	if r.Header.Get("x-pm-appversion") == "" || r.Header.Get("User-Agent") == "" {
		reply(w, 400, map[string]any{"Code": 5003, "Error": "missing headers"})
		return
	}
	needAuth := func() bool {
		if !f.authorized(r) {
			reply(w, 401, map[string]any{"Code": 401, "Error": "Invalid access token"})
			return false
		}
		return true
	}
	switch r.Method + " " + r.URL.Path {
	case "POST /auth/info":
		if body["Username"] != f.user {
			reply(w, 422, map[string]any{"Code": 8002, "Error": "bad user"})
			return
		}
		s, err := srp.NewServerFromSigned(f.modulus, f.verifier, 2048)
		if err != nil {
			f.t.Error(err)
			return
		}
		f.srpSrv = s
		eph, _ := s.GenerateChallenge()
		reply(w, 200, ok(map[string]any{
			"Modulus": f.modulus, "ServerEphemeral": base64.StdEncoding.EncodeToString(eph),
			"Salt": base64.StdEncoding.EncodeToString(f.salt), "SRPSession": "srp-1", "Version": 4,
		}))
	case "POST /auth":
		ce, _ := base64.StdEncoding.DecodeString(body["ClientEphemeral"].(string))
		cp, _ := base64.StdEncoding.DecodeString(body["ClientProof"].(string))
		if f.srpSrv == nil {
			reply(w, 422, map[string]any{"Code": 8002, "Error": "no srp session"})
			return
		}
		sp, err := f.srpSrv.VerifyProofs(ce, cp)
		if err != nil {
			reply(w, 422, map[string]any{"Code": 8002, "Error": "Incorrect login credentials"})
			return
		}
		if f.badProof {
			sp[0] ^= 0xff
		}
		reply(w, 200, ok(map[string]any{
			"UID": "uid-1", "AccessToken": f.accessTok, "RefreshToken": f.refreshTok,
			"Scopes": []string{"self", "vpn"}, "ServerProof": base64.StdEncoding.EncodeToString(sp),
			"2FA": map[string]any{"Enabled": f.twoFA},
		}))
	case "POST /auth/2fa":
		if !needAuth() {
			return
		}
		if body["TwoFactorCode"] != f.totpCode {
			reply(w, 422, map[string]any{"Code": 8002, "Error": "Incorrect 2FA code"})
			return
		}
		reply(w, 200, ok(nil))
	case "POST /auth/refresh":
		if f.refreshFail || body["RefreshToken"] != f.refreshTok || body["GrantType"] != "refresh_token" {
			reply(w, 400, map[string]any{"Code": 10013, "Error": "Invalid refresh token"})
			return
		}
		f.refreshes++
		f.accessTok = "AT-" + strconv.Itoa(f.refreshes+1)
		f.refreshTok = "RT-" + strconv.Itoa(f.refreshes+1)
		reply(w, 200, ok(map[string]any{"AccessToken": f.accessTok, "RefreshToken": f.refreshTok, "Scopes": []string{"self", "vpn"}}))
	case "DELETE /auth":
		if !needAuth() {
			return
		}
		f.loggedOut++
		reply(w, 200, ok(nil))
	case "GET /vpn/v2":
		if f.fail503 > 0 {
			f.fail503--
			reply(w, 503, map[string]any{"Code": 0, "Error": "busy"})
			return
		}
		if !needAuth() {
			return
		}
		reply(w, 200, ok(map[string]any{"VPN": map[string]any{"PlanName": "vpn2024", "MaxTier": 2, "MaxConnect": 11, "Status": 1}}))
	case "GET /vpn/v1/logicals":
		if !needAuth() {
			return
		}
		if r.URL.Query().Get("WithIpV6") != "1" {
			reply(w, 200, ok(map[string]any{"LogicalServers": []any{}}))
			return
		}
		reply(w, 200, ok(map[string]any{"LogicalServers": []any{
			map[string]any{"ID": "L1", "Name": "DE#1", "EntryCountry": "DE", "ExitCountry": "DE", "City": "Frankfurt", "Tier": 2, "Features": 28, "Status": 1, "Load": 40,
				"Servers": []any{map[string]any{"ID": "S1", "EntryIP": "1.2.3.4", "EntryIPv6": "2001:db8::10", "ExitIP": "1.2.3.4", "Domain": "node-de-1.protonvpn.net", "Label": "3", "X25519PublicKey": "PUB", "Status": 1}}},
			map[string]any{"ID": "L2", "Name": "NL#1", "EntryCountry": "NL", "ExitCountry": "NL", "City": nil, "Tier": 0, "Features": 0, "Status": 0, "Load": 5, "Servers": []any{}},
		}}))
	case "POST /vpn/v1/certificate":
		if !needAuth() {
			return
		}
		if f.rateLimitCerts {
			w.Header().Set("Retry-After", "90")
			reply(w, 429, map[string]any{"Code": 2028, "Error": "Too many certificates generated. Please try again later"})
			return
		}
		f.lastCertBody = body
		f.certSeq++
		serial := fmt.Sprintf("SN%d", f.certSeq)
		f.certs[serial] = map[string]any{"SerialNumber": serial, "DeviceName": body["DeviceName"], "Mode": "persistent", "ExpirationTime": 2000000000, "RefreshTime": 1900000000}
		reply(w, 200, ok(map[string]any{"SerialNumber": serial, "ExpirationTime": 2000000000, "RefreshTime": 1900000000, "Mode": "persistent"}))
	case "DELETE /vpn/v1/certificate":
		if !needAuth() {
			return
		}
		serial, _ := body["SerialNumber"].(string)
		n := 0
		if _, ok := f.certs[serial]; ok {
			delete(f.certs, serial)
			n = 1
		}
		reply(w, 200, ok(map[string]any{"Count": n}))
	case "GET /vpn/v1/certificate/all":
		if !needAuth() {
			return
		}
		limit, _ := strconv.Atoi(r.URL.Query().Get("Limit"))
		offset, _ := strconv.Atoi(r.URL.Query().Get("Offset"))
		var serials []string
		for s := range f.certs {
			serials = append(serials, s)
		}
		sortStrings(serials)
		var page []any
		for i := offset; i < len(serials) && i < offset+limit; i++ {
			page = append(page, f.certs[serials[i]])
		}
		reply(w, 200, ok(map[string]any{"Certificates": page, "Total": len(serials)}))
	default:
		reply(w, 404, map[string]any{"Code": 2000, "Error": "not found: " + strings.TrimSpace(r.Method+" "+r.URL.Path)})
	}
}

func sortStrings(s []string) {
	for i := 1; i < len(s); i++ {
		for j := i; j > 0 && s[j-1] > s[j]; j-- {
			s[j-1], s[j] = s[j], s[j-1]
		}
	}
}
