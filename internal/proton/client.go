// Package proton is a small client for the Proton VPN API.
// It covers login (SRP), token refresh, server lists, and persistent certificates.
package proton

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strconv"
	"time"
)

const (
	DefaultBaseURL = "https://vpn-api.proton.me"
	appVersion     = "linux-vpn-cli@6.1.1+x86-64"
	userAgent      = "ProtonVPN/6.1.1 (Linux; ubuntu/22.04)"

	maxSmallBody = 4 << 20
	maxBigBody   = 128 << 20
)

// ErrLoginRequired means the saved session cannot be used. The user must run `pvpn login`.
var ErrLoginRequired = errors.New("login required: run `pvpn login`")

// APIError is an error answer from the API.
type APIError struct {
	HTTP    int
	Code    int
	Message string
	Details string
	// RetryAfter is the wait that the server asks for (header Retry-After), if any.
	RetryAfter time.Duration
}

func (e *APIError) Error() string {
	s := fmt.Sprintf("proton API error: http=%d code=%d %q", e.HTTP, e.Code, e.Message)
	if e.Details != "" {
		s += " details=" + e.Details
	}
	if e.HTTP == http.StatusTooManyRequests {
		s += " (Proton limits how fast this account can do this"
		if e.RetryAfter > 0 {
			s += "; retry after " + e.RetryAfter.Round(time.Second).String()
		} else {
			s += "; wait and run the command again"
		}
		s += ")"
	}
	return s
}

// Client talks to the API with one session.
type Client struct {
	BaseURL   string
	HTTP      *http.Client
	Sess      *Session
	SessPath  string
	NoRefresh bool // never refresh tokens (dry run): a 401 gives ErrLoginRequired

	// Sleep is replaced in tests.
	Sleep func(time.Duration)
	// SaveFn saves the session after a refresh. It defaults to SaveSession(SessPath, s).
	SaveFn func(*Session) error
	// Refreshed counts token refreshes (for tests and messages).
	Refreshed int

	retryAfter time.Duration // Retry-After of the last answer
}

// New returns a client for the real API.
func New(sess *Session, sessPath string) *Client {
	return &Client{BaseURL: DefaultBaseURL, HTTP: &http.Client{}, Sess: sess, SessPath: sessPath}
}

type envelope struct {
	Code    int             `json:"Code"`
	Error   string          `json:"Error"`
	Details json.RawMessage `json:"Details"`
}

// raw sends one request and returns the status and body.
func (c *Client) raw(ctx context.Context, method, path string, body any, withSession bool, limit int64) (int, []byte, error) {
	var rdr io.Reader
	if body != nil {
		b, err := json.Marshal(body)
		if err != nil {
			return 0, nil, err
		}
		rdr = bytes.NewReader(b)
	}
	req, err := http.NewRequestWithContext(ctx, method, c.BaseURL+path, rdr)
	if err != nil {
		return 0, nil, err
	}
	req.Header.Set("x-pm-appversion", appVersion)
	req.Header.Set("User-Agent", userAgent)
	req.Header.Set("Accept", "application/json")
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	if withSession {
		if c.Sess == nil {
			return 0, nil, ErrLoginRequired
		}
		req.Header.Set("x-pm-uid", c.Sess.UID)
		req.Header.Set("Authorization", "Bearer "+c.Sess.AccessToken)
	}
	h := c.HTTP
	if h == nil {
		h = http.DefaultClient
	}
	resp, err := h.Do(req)
	if err != nil {
		return 0, nil, err
	}
	defer resp.Body.Close()
	c.retryAfter = 0
	if v := resp.Header.Get("Retry-After"); v != "" {
		if n, err := strconv.Atoi(v); err == nil && n > 0 {
			c.retryAfter = time.Duration(n) * time.Second
		}
	}
	b, err := io.ReadAll(io.LimitReader(resp.Body, limit+1))
	if err != nil {
		return resp.StatusCode, nil, err
	}
	if int64(len(b)) > limit {
		return resp.StatusCode, nil, fmt.Errorf("response from %s is larger than %d bytes", path, limit)
	}
	return resp.StatusCode, b, nil
}

// decode checks the envelope and decodes the body into out (out may be nil).
func decode(status int, b []byte, out any) error {
	var env envelope
	if err := json.Unmarshal(b, &env); err != nil {
		return fmt.Errorf("non-JSON answer (http %d, %d bytes)", status, len(b))
	}
	if env.Code != 1000 {
		e := &APIError{HTTP: status, Code: env.Code, Message: env.Error}
		if len(env.Details) > 0 && string(env.Details) != "null" && string(env.Details) != "{}" {
			e.Details = string(env.Details)
		}
		return e
	}
	if out != nil {
		if err := json.Unmarshal(b, out); err != nil {
			return fmt.Errorf("bad answer format: %w", err)
		}
	}
	return nil
}

func (c *Client) sleep(d time.Duration) {
	if c.Sleep != nil {
		c.Sleep(d)
		return
	}
	time.Sleep(d)
}

// call sends an unauthenticated request.
func (c *Client) call(ctx context.Context, method, path string, body, out any) error {
	st, b, err := c.raw(ctx, method, path, body, false, maxSmallBody)
	if err != nil {
		return err
	}
	return decode(st, b, out)
}

// authed sends a request with the session. On HTTP 401 it refreshes the tokens once and tries again.
// GET requests also retry on network errors, HTTP 429, and HTTP 5xx.
func (c *Client) authed(ctx context.Context, method, path string, body, out any, limit int64) error {
	if c.Sess == nil {
		return ErrLoginRequired
	}
	refreshed := false
	attempts := 1
	if method == http.MethodGet {
		attempts = 4
	}
	var lastErr error
	for tries := 0; tries < attempts; {
		if tries > 0 {
			c.sleep(time.Duration(1<<uint(tries-1)) * time.Second)
		}
		st, b, err := c.raw(ctx, method, path, body, true, limit)
		if err != nil {
			if ctx.Err() != nil {
				return ctx.Err()
			}
			lastErr = err
			tries++
			continue
		}
		if st == http.StatusUnauthorized && !refreshed {
			if c.NoRefresh {
				return fmt.Errorf("%w (the access token expired; a dry run does not refresh tokens)", ErrLoginRequired)
			}
			if err := c.Refresh(ctx); err != nil {
				return err
			}
			refreshed = true
			continue // a refresh does not use up an attempt
		}
		if st == http.StatusTooManyRequests || st >= 500 {
			lastErr = decode(st, b, nil)
			if lastErr == nil {
				lastErr = fmt.Errorf("http %d", st)
			}
			var ae *APIError
			if errors.As(lastErr, &ae) {
				ae.RetryAfter = c.retryAfter
			}
			tries++
			continue
		}
		err = decode(st, b, out)
		var ae *APIError
		if errors.As(err, &ae) {
			ae.RetryAfter = c.retryAfter
		}
		return err
	}
	return lastErr
}

// Refresh gets new tokens with the refresh token and saves the session.
// An answer from the API that refuses the refresh gives ErrLoginRequired.
func (c *Client) Refresh(ctx context.Context) error {
	if c.Sess == nil {
		return ErrLoginRequired
	}
	if c.NoRefresh {
		return fmt.Errorf("%w (refresh not allowed in this mode)", ErrLoginRequired)
	}
	var r struct {
		envelope
		AccessToken  string   `json:"AccessToken"`
		RefreshToken string   `json:"RefreshToken"`
		Scopes       []string `json:"Scopes"`
	}
	st, b, err := c.raw(ctx, "POST", "/auth/refresh", map[string]any{
		"ResponseType": "token",
		"GrantType":    "refresh_token",
		"RefreshToken": c.Sess.RefreshToken,
		"RedirectURI":  "http://protonmail.ch",
	}, true, maxSmallBody)
	if err != nil {
		return fmt.Errorf("token refresh failed: %w", err)
	}
	if err := decode(st, b, &r); err != nil {
		var ae *APIError
		if errors.As(err, &ae) {
			return fmt.Errorf("%w (refresh refused: %v)", ErrLoginRequired, err)
		}
		return fmt.Errorf("token refresh failed: %w", err)
	}
	if r.AccessToken == "" || r.RefreshToken == "" {
		return fmt.Errorf("%w (refresh answer has no tokens)", ErrLoginRequired)
	}
	c.Sess.AccessToken, c.Sess.RefreshToken = r.AccessToken, r.RefreshToken
	if len(r.Scopes) > 0 {
		c.Sess.Scopes = r.Scopes
	}
	c.Sess.RefreshedAt = time.Now().UTC()
	c.Refreshed++
	save := c.SaveFn
	if save == nil {
		save = func(s *Session) error { return SaveSession(c.SessPath, s) }
	}
	if err := save(c.Sess); err != nil {
		return fmt.Errorf("save refreshed session: %w", err)
	}
	return nil
}

// Logout revokes the session on the server. HTTP 401 counts as success (already gone).
func (c *Client) Logout(ctx context.Context) error {
	if c.Sess == nil {
		return ErrLoginRequired
	}
	st, b, err := c.raw(ctx, "DELETE", "/auth", nil, true, maxSmallBody)
	if err != nil {
		return err
	}
	if st == http.StatusUnauthorized {
		return nil
	}
	return decode(st, b, nil)
}

// VPNInfo is the account part of GET /vpn/v2.
type VPNInfo struct {
	PlanName   string
	MaxTier    int
	MaxConnect int
	Status     int
}

// Info reads the account VPN info.
func (c *Client) Info(ctx context.Context) (VPNInfo, error) {
	var r struct {
		VPN VPNInfo `json:"VPN"`
	}
	if err := c.authed(ctx, "GET", "/vpn/v2", nil, &r, maxSmallBody); err != nil {
		return VPNInfo{}, err
	}
	return r.VPN, nil
}

// Physical is one machine behind a logical server.
type Physical struct {
	ID              string `json:"ID"`
	EntryIP         string `json:"EntryIP"`
	EntryIPv6       string `json:"EntryIPv6"`
	ExitIP          string `json:"ExitIP"`
	Domain          string `json:"Domain"`
	Label           string `json:"Label"`
	X25519PublicKey string `json:"X25519PublicKey"`
	Status          int    `json:"Status"`
	ServicesDown    int    `json:"ServicesDown"`
}

// Logical is a named server such as DE#520.
type Logical struct {
	ID           string     `json:"ID"`
	Name         string     `json:"Name"`
	EntryCountry string     `json:"EntryCountry"`
	ExitCountry  string     `json:"ExitCountry"`
	City         string     `json:"City"`
	Tier         int        `json:"Tier"`
	Features     int        `json:"Features"`
	Status       int        `json:"Status"`
	Load         int        `json:"Load"`
	Servers      []Physical `json:"Servers"`
}

// Logicals lists all servers with their IPv6 entry addresses.
func (c *Client) Logicals(ctx context.Context) ([]Logical, error) {
	ctx, cancel := context.WithTimeout(ctx, 2*time.Minute)
	defer cancel()
	var r struct {
		LogicalServers []Logical `json:"LogicalServers"`
	}
	q := url.Values{"WithIpV6": {"1"}, "SecureCoreFilter": {"all"}, "WithState": {"true"}}
	if err := c.authed(ctx, "GET", "/vpn/v1/logicals?"+q.Encode(), nil, &r, maxBigBody); err != nil {
		return nil, err
	}
	return r.LogicalServers, nil
}

// CertRequest asks for a persistent certificate.
type CertRequest struct {
	DeviceName string
	Label      string // physical server Label (the "Bouncing" feature)
	PeerName   string // logical server name
	PeerIP     string
	PeerPubKey string
	EdPubKey   []byte // Ed25519 public key
}

// Cert is a certificate answer.
type Cert struct {
	Serial     string
	Expiration int64
	Refresh    int64
}

// CreateCert registers the client public key and gets a persistent certificate.
func (c *Client) CreateCert(ctx context.Context, rq CertRequest) (*Cert, error) {
	feats := map[string]any{"platform": "Linux"}
	if rq.Label != "" {
		feats["Bouncing"] = rq.Label
	}
	if rq.PeerName != "" {
		feats["peerName"] = rq.PeerName
	}
	if rq.PeerIP != "" {
		feats["peerIp"] = rq.PeerIP
	}
	if rq.PeerPubKey != "" {
		feats["peerPublicKey"] = rq.PeerPubKey
	}
	var r struct {
		SerialNumber   string `json:"SerialNumber"`
		ExpirationTime int64  `json:"ExpirationTime"`
		RefreshTime    int64  `json:"RefreshTime"`
	}
	err := c.authed(ctx, "POST", "/vpn/v1/certificate", map[string]any{
		"ClientPublicKey": b64(rq.EdPubKey),
		"Mode":            "persistent",
		"DeviceName":      rq.DeviceName,
		"Features":        feats,
	}, &r, maxSmallBody)
	if err != nil {
		return nil, err
	}
	if r.SerialNumber == "" {
		return nil, errors.New("certificate answer has no serial number")
	}
	return &Cert{Serial: r.SerialNumber, Expiration: r.ExpirationTime, Refresh: r.RefreshTime}, nil
}

// DeleteCert revokes a certificate by serial number. A serial that is already gone is not an error.
func (c *Client) DeleteCert(ctx context.Context, serial string) error {
	if serial == "" {
		return errors.New("empty certificate serial")
	}
	return c.authed(ctx, "DELETE", "/vpn/v1/certificate", map[string]any{"SerialNumber": serial}, nil, maxSmallBody)
}

// CertInfo is one entry of the certificate list.
type CertInfo struct {
	Serial     string
	DeviceName string
	Mode       string
	Expiration int64
	Refresh    int64
}

// ListCerts lists the persistent certificates of the account.
func (c *Client) ListCerts(ctx context.Context) ([]CertInfo, error) {
	const page = 100
	var all []CertInfo
	seen := map[string]bool{}
	for offset := 0; ; offset += page {
		var r struct {
			Certificates []struct {
				SerialNumber   string `json:"SerialNumber"`
				DeviceName     string `json:"DeviceName"`
				Mode           string `json:"Mode"`
				ExpirationTime int64  `json:"ExpirationTime"`
				RefreshTime    int64  `json:"RefreshTime"`
			} `json:"Certificates"`
			Total int `json:"Total"`
		}
		path := "/vpn/v1/certificate/all?Mode=persistent&Limit=" + strconv.Itoa(page) + "&Offset=" + strconv.Itoa(offset)
		if err := c.authed(ctx, "GET", path, nil, &r, maxBigBody); err != nil {
			return nil, err
		}
		added := 0
		for _, x := range r.Certificates {
			if seen[x.SerialNumber] {
				continue
			}
			seen[x.SerialNumber] = true
			added++
			all = append(all, CertInfo{x.SerialNumber, x.DeviceName, x.Mode, x.ExpirationTime, x.RefreshTime})
		}
		if added == 0 || len(r.Certificates) < page || (r.Total > 0 && len(all) >= r.Total) {
			return all, nil
		}
	}
}
