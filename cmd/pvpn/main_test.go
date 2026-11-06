package main

import (
	"bytes"
	"strings"
	"testing"
)

func runCLI(args ...string) (int, string, string) {
	var out, errb bytes.Buffer
	code := run(args, strings.NewReader(""), &out, &errb)
	return code, out.String(), errb.String()
}

func TestUsageAndVersion(t *testing.T) {
	if code, out, _ := runCLI(); code != exitUsage || !strings.Contains(out, "Usage: pvpn") {
		t.Errorf("no args: %d %q", code, out)
	}
	if code, out, _ := runCLI("--help"); code != exitOK || !strings.Contains(out, "reconcile") {
		t.Errorf("help: %d", code)
	}
	if code, out, _ := runCLI("version"); code != exitOK || !strings.HasPrefix(out, "pvpn ") {
		t.Errorf("version: %d %q", code, out)
	}
}

func TestUnknownCommandAndFlags(t *testing.T) {
	if code, _, errb := runCLI("frobnicate"); code != exitUsage || !strings.Contains(errb, "unknown command") {
		t.Errorf("unknown command: %d %q", code, errb)
	}
	if code, _, _ := runCLI("reconcile", "--no-such-flag"); code != exitUsage {
		t.Errorf("bad flag: %d", code)
	}
	if code, _, errb := runCLI("status", "extra"); code != exitUsage || !strings.Contains(errb, "unexpected argument") {
		t.Errorf("extra argument: %d %q", code, errb)
	}
	if code, _, _ := runCLI("login", "--dry-run"); code != exitUsage {
		t.Errorf("--dry-run belongs to reconcile only: %d", code)
	}
}

func TestRotateSelectorsExclude(t *testing.T) {
	code, _, errb := runCLI("rotate", "--group", "a", "--interface", "b")
	if code != exitUsage || !strings.Contains(errb, "cannot be used together") {
		t.Errorf("got %d %q", code, errb)
	}
}

func TestFeaturesText(t *testing.T) {
	if features(0) != "-" || features(4|16) != "p2p" || features(1|2|4) != "secure_core,tor,p2p" {
		t.Errorf("features: %q %q %q", features(0), features(4|16), features(7))
	}
}
