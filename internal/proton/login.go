package proton

import (
	"context"
	"crypto/subtle"
	"encoding/base64"
	"errors"
	"fmt"
	"time"

	srp "github.com/ProtonMail/go-srp"
)

// ErrUnsupported2FA means the account needs a second factor this tool cannot answer.
var ErrUnsupported2FA = errors.New("this account needs a security key (FIDO2); only TOTP is supported")

// Login runs the SRP login. It verifies the server proof.
// askTOTP is called only when the account has TOTP enabled.
// The caller saves the returned session. On any error after the API created a session,
// Login logs that session out so no orphan stays.
func (c *Client) Login(ctx context.Context, user string, pass []byte, askTOTP func() (string, error)) (*Session, error) {
	var info struct {
		Modulus         string `json:"Modulus"`
		ServerEphemeral string `json:"ServerEphemeral"`
		Salt            string `json:"Salt"`
		SRPSession      string `json:"SRPSession"`
		Version         int    `json:"Version"`
	}
	if err := c.call(ctx, "POST", "/auth/info", map[string]any{"Username": user}, &info); err != nil {
		return nil, fmt.Errorf("login (auth/info): %w", err)
	}
	a, err := srp.NewAuth(info.Version, user, pass, info.Salt, info.Modulus, info.ServerEphemeral)
	if err != nil {
		return nil, fmt.Errorf("login (srp): %w", err)
	}
	proofs, err := a.GenerateProofs(2048)
	if err != nil {
		return nil, fmt.Errorf("login (srp proofs): %w", err)
	}
	var res struct {
		UID          string   `json:"UID"`
		AccessToken  string   `json:"AccessToken"`
		RefreshToken string   `json:"RefreshToken"`
		Scopes       []string `json:"Scopes"`
		ServerProof  string   `json:"ServerProof"`
		TwoFA        struct {
			Enabled int `json:"Enabled"`
		} `json:"2FA"`
	}
	if err := c.call(ctx, "POST", "/auth", map[string]any{
		"Username":        user,
		"ClientEphemeral": base64.StdEncoding.EncodeToString(proofs.ClientEphemeral),
		"ClientProof":     base64.StdEncoding.EncodeToString(proofs.ClientProof),
		"SRPSession":      info.SRPSession,
	}, &res); err != nil {
		return nil, fmt.Errorf("login (auth): %w", err)
	}
	sp, _ := base64.StdEncoding.DecodeString(res.ServerProof)
	if subtle.ConstantTimeCompare(sp, proofs.ExpectedServerProof) != 1 {
		// The server did not prove it knows the password verifier. Do not trust the session.
		return nil, errors.New("login: server proof does not match; the answer is not trusted")
	}
	s := &Session{
		UID: res.UID, AccessToken: res.AccessToken, RefreshToken: res.RefreshToken,
		Scopes: res.Scopes, AppVersion: appVersion, SavedAt: time.Now().UTC(),
	}
	if s.UID == "" || s.AccessToken == "" || s.RefreshToken == "" {
		return nil, errors.New("login: answer has no session tokens")
	}
	c.Sess = s
	fail := func(err error) (*Session, error) {
		lctx, cancel := context.WithTimeout(context.WithoutCancel(ctx), 15*time.Second)
		defer cancel()
		_ = c.Logout(lctx)
		c.Sess = nil
		return nil, err
	}
	if en := res.TwoFA.Enabled; en != 0 {
		if en&1 == 0 {
			return fail(ErrUnsupported2FA)
		}
		if askTOTP == nil {
			return fail(errors.New("login: the account needs a TOTP code"))
		}
		code, err := askTOTP()
		if err != nil {
			return fail(err)
		}
		if err := c.authed(ctx, "POST", "/auth/2fa", map[string]any{"TwoFactorCode": code}, nil, maxSmallBody); err != nil {
			return fail(fmt.Errorf("login (2fa): %w", err))
		}
	}
	return s, nil
}
