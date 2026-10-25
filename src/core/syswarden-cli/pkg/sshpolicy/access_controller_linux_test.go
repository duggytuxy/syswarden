//go:build linux

package sshpolicy

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"os"
	"os/exec"
	"strings"
	"testing"
	"time"
)

func TestSSHControllerExportedProbe(t *testing.T) {
	for _, scenario := range []string{"success", "schema", "unknown-field", "duplicate-field", "newline", "wrong-request", "wrong-challenge", "wrong-controller", "missing-route", "extra-route", "wrong-key", "revoked"} {
		t.Run(scenario, func(t *testing.T) {
			target := newSSHProbeFixture(t, "success")
			jump := newSSHProbeFixture(t, "bastion", target.peer.Address)
			request, credentials := syntheticAccessRequest(t, target, jump)
			public, key := receiptController(t)
			challenge, err := newSSHAccessChallenge(request, digestBytes(request), public, time.Now(), 3*time.Minute)
			if err != nil {
				t.Fatal(err)
			}
			document := ControllerAccessCredentials{Schema: 1, SigningSeed: key.Seed()}
			defer clear(key)
			defer clearControllerCredentials(&document)
			for _, credential := range credentials {
				document.Routes = append(document.Routes, ControllerAccessCredential{credential.ContextID, bytes.Clone(credential.Target), bytes.Clone(credential.Jump)})
			}
			requestSHA, challengeSHA := digestBytes(request), digestBytes(challenge)
			switch scenario {
			case "schema":
				document.Schema++
			case "wrong-request":
				requestSHA = strings.Repeat("f", 64)
			case "wrong-challenge":
				challengeSHA = strings.Repeat("f", 64)
			case "wrong-controller":
				document.SigningSeed[0] ^= 1
			case "missing-route":
				document.Routes = document.Routes[:1]
			case "extra-route":
				document.Routes = append(document.Routes, document.Routes[0])
			case "wrong-key":
				document.Routes[1].Target = []byte("not an identity")
			}
			secret, err := json.Marshal(document)
			if err != nil {
				t.Fatal(err)
			}
			defer clear(secret)
			switch scenario {
			case "unknown-field":
				secret = append(secret[:len(secret)-1], []byte(`,"other":1}`)...)
			case "duplicate-field":
				secret = append(secret[:len(secret)-1], []byte(`,"schema":1}`)...)
			case "newline":
				secret = append(secret, '\n')
			}
			receipt, err := ProbeAccessChallenge(t.Context(), request, challenge, requestSHA, challengeSHA, secret, func() error {
				if scenario == "revoked" {
					return ErrInventoryChanged
				}
				return nil
			})
			if scenario != "success" {
				if err == nil || len(receipt) != 0 || target.signatures.Load() != 0 || jump.signatures.Load() != 0 {
					t.Fatal("invalid controller input authenticated or signed", err)
				}
				return
			}
			if err != nil {
				t.Fatal(err)
			}
			assessment, err := verifySSHAccessReceipt(sshAccessReceiptInput{request, challenge, receipt, challengeSHA, public}, time.Now())
			if err != nil || !assessment.RecoveryRequired || assessment.ContextsObserved != 2 || target.signatures.Load() != 2 || jump.signatures.Load() != 1 {
				t.Fatal("fresh route evidence failed", err)
			}
			if bytes.Contains(receipt, key) || bytes.Contains(receipt, []byte("PRIVATE KEY")) {
				t.Fatal("secret in receipt")
			}
		})
	}
}

// The helper is a separate process and receives synthetic credentials only over
// its inherited pipe. This proves process separation, not independent ownership
// of an operator's controller or qualification of a remote administration team.
func TestSSHControllerProcessHelper(t *testing.T) {
	if os.Getenv("SYSWARDEN_TEST_ACCESS_CONTROLLER_CHILD") != "1" {
		return
	}
	wire, err := io.ReadAll(io.LimitReader(os.Stdin, 2<<20))
	if err != nil {
		os.Exit(2)
	}
	var input controllerProcessInput
	if err := json.Unmarshal(wire, &input); err != nil {
		os.Exit(2)
	}
	clear(wire)
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	receipt, err := ProbeAccessChallenge(ctx, input.Request, input.Challenge, input.RequestSHA, input.ChallengeSHA, input.Secret, func() error { return ctx.Err() })
	clear(input.Secret)
	if err != nil {
		os.Exit(3)
	}
	if _, err := os.Stdout.Write(receipt); err != nil {
		os.Exit(4)
	}
	os.Exit(0)
}

type controllerProcessInput struct {
	Request, Challenge       []byte
	Secret                   []byte // #nosec G117 -- synthetic test credentials intentionally travel only over the child stdin pipe.
	RequestSHA, ChallengeSHA string
}

func TestSSHControllerSeparateProcess(t *testing.T) {
	target := newSSHProbeFixture(t, "success")
	jump := newSSHProbeFixture(t, "bastion", target.peer.Address)
	request, credentials := syntheticAccessRequest(t, target, jump)
	public, key := receiptController(t)
	defer clear(key)
	challenge, err := newSSHAccessChallenge(request, digestBytes(request), public, time.Now(), 3*time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	document := ControllerAccessCredentials{Schema: 1, SigningSeed: key.Seed()}
	for _, credential := range credentials {
		document.Routes = append(document.Routes, ControllerAccessCredential{credential.ContextID, bytes.Clone(credential.Target), bytes.Clone(credential.Jump)})
	}
	defer clearControllerCredentials(&document)
	secret, err := json.Marshal(document)
	if err != nil {
		t.Fatal(err)
	}
	defer clear(secret)
	// #nosec G117 -- marshals synthetic test keys only into the bounded child stdin pipe, never logs or files.
	input, err := json.Marshal(controllerProcessInput{request, challenge, secret, digestBytes(request), digestBytes(challenge)})
	if err != nil {
		t.Fatal(err)
	}
	defer clear(input)
	executable, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(t.Context(), 40*time.Second)
	defer cancel()
	// #nosec G204 -- executes this test binary with fixed helper flags and only synthetic input.
	child := exec.CommandContext(ctx, executable, "-test.run=^TestSSHControllerProcessHelper$")
	child.Env = []string{"SYSWARDEN_TEST_ACCESS_CONTROLLER_CHILD=1", "GOMAXPROCS=2"}
	child.Stdin = bytes.NewReader(input)
	var output, stderr bytes.Buffer
	child.Stdout = &output
	child.Stderr = &stderr
	child.WaitDelay = time.Second
	if err := child.Run(); err != nil {
		t.Fatal("separate controller refused", err)
	}
	assessment, err := verifySSHAccessReceipt(sshAccessReceiptInput{request, challenge, output.Bytes(), digestBytes(challenge), public}, time.Now())
	if err != nil || assessment.ContextsObserved != 2 || !assessment.RecoveryRequired || stderr.Len() != 0 {
		t.Fatal("separate controller evidence failed", err)
	}
	if bytes.Contains(output.Bytes(), key) || bytes.Contains(output.Bytes(), secret) {
		t.Fatal("controller leaked credentials")
	}
}
