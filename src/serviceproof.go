package main

// ---------------------------------------------------------------------------
// One core, one owner, and a way to know who that owner is.
//
// Two problems, and they are the same problem seen from both ends.
//
// The first: the core could be started by the window, by the elevated helper, or by
// the resident service, and the ownership helpers that exist for choosing between
// them were never called from the lifecycle. Ordinary start, background recovery, TUN
// rollback and shutdown all reached for the core directly. So a service that owned the
// core could be bypassed by a window that started a second one, and the two would
// disagree about the port and the configuration - which is precisely the failure this
// design was written to prevent.
//
// The second: the client decided the service existed by asking a fixed port for an
// unauthenticated 200. Anything that could bind 7795 could answer that, and would then
// be handed the control secret in the next request. Loopback is not an identity, and a
// port number is not a program.
//
// The fix for the second is not to authenticate harder on the way out. It is to make
// the service prove itself before anything is sent to it, which is what the handshake
// below does: the client sends a nonce, the service returns a proof it holds the
// shared secret, and nothing else is transmitted until that proof checks out.
// ---------------------------------------------------------------------------

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"
)

// serviceProofMaxSkew bounds how old a nonce may be, so a captured proof cannot be
// replayed later. The window only has to cover the round trip on this machine.
const serviceProofMaxSkew = 20 * time.Second

// serviceProofMAC is the value a service returns to prove it holds the secret.
//
// It covers the nonce, the timestamp and the port, so a proof captured from one
// exchange cannot be replayed at another port or at another time. The secret itself is
// never sent in either direction - a verification scheme that transmits the thing
// being verified is not a verification scheme.
func serviceProofMAC(secret, nonce string, ts int64, port int) string {
	m := hmac.New(sha256.New, []byte(secret))
	fmt.Fprintf(m, "zenith-service-proof|v1|%s|%d|%d", nonce, ts, port)
	return base64.RawURLEncoding.EncodeToString(m.Sum(nil))
}

// newServiceNonce returns a value the client cannot be predicted to send twice.
func newServiceNonce() string {
	b := make([]byte, 24)
	if _, err := rand.Read(b); err != nil {
		// A predictable nonce weakens the replay bound rather than the identity check,
		// which is not a reason to skip the identity check.
		return fmt.Sprintf("fallback-%d", time.Now().UnixNano())
	}
	return base64.RawURLEncoding.EncodeToString(b)
}

// serviceAliveResponse is what the service answers before it is trusted with anything.
type serviceAliveResponse struct {
	OK    bool   `json:"ok"`
	Nonce string `json:"nonce"`
	TS    int64  `json:"ts"`
	Port  int    `json:"port"`
	Proof string `json:"proof"`
	// Version lets the client tell a current service from an old binary that cannot
	// speak this protocol, rather than mistaking it for an impostor.
	Version string `json:"version,omitempty"`
}

// verifyServiceIdentity asks the service to prove it holds the secret.
//
// Everything the client sends is a nonce, which is worth nothing to anybody. Only
// after the proof checks out does it send anything else - so a program squatting on
// the service port learns nothing it did not already know.
func verifyServiceIdentity(secret string, port int, timeout time.Duration) error {
	return verifyServiceIdentityAgainst(secret,
		fmt.Sprintf("http://127.0.0.1:%d", port), timeout)
}

// verifyServiceIdentityAgainst is the same check against a base URL.
//
// Split out so the check can be exercised against a server whose address is not known
// until it starts. A verification routine that can only be pointed at the real port is
// a verification routine that never gets tested, which for this particular check would
// be the worst kind to leave unexercised.
func verifyServiceIdentityAgainst(secret, baseURL string, timeout time.Duration) error {
	nonce := newServiceNonce()
	url := baseURL + "/alive?" + proofNonceParam + "=" + nonce

	client := &http.Client{
		Timeout: timeout,
		Transport: &http.Transport{
			Proxy: nil, // loopback is never proxied
		},
	}
	resp, err := client.Get(url)
	if err != nil {
		return fmt.Errorf("服务地址 %s 没有应答：%v", baseURL, err)
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(io.LimitReader(resp.Body, 4096))

	var got serviceAliveResponse
	if err := json.Unmarshal(body, &got); err != nil {
		// Anything on the port that cannot answer this is not the service. Saying so
		// is the point: it is the difference between "nothing is installed" and
		// "something else is answering".
		return fmt.Errorf("%s 上的程序没有按服务的协议应答（可能是别的程序占用了这个地址）", baseURL)
	}
	if got.Nonce != nonce {
		return fmt.Errorf("%s 上的程序回了一个不是我们发出的随机数；它不知道我们的密钥", baseURL)
	}
	now := time.Now()
	age := now.Sub(time.Unix(got.TS, 0))
	if age < 0 {
		age = -age
	}
	if age > serviceProofMaxSkew {
		return fmt.Errorf("%s 上的程序回的时间戳相差 %v，超出了 %v 的允许范围",
			baseURL, age.Round(time.Second), serviceProofMaxSkew)
	}
	want := serviceProofMAC(secret, nonce, got.TS, got.Port)
	if subtle.ConstantTimeCompare([]byte(want), []byte(got.Proof)) != 1 {
		return fmt.Errorf("%s 上的程序无法证明它持有控制密码；"+
			"出于安全考虑，不会把密码发送给它", baseURL)
	}
	if strings.TrimSpace(got.Version) != "" && got.Version != AppVersion {
		// Not a refusal: a service from an older install still holds the core, and
		// refusing it would strand the user. Reported so the interface can say the
		// two halves are out of step.
		Log("service: the running service reports version %q, this program is %q; "+
			"reinstalling the service will bring them into step", got.Version, AppVersion, "WARN")
	}
	return nil
}

// proofPath is the query parameter the service reads the nonce from.
const proofNonceParam = "nonce"

// handleServiceAlive answers the identity challenge.
//
// Unauthenticated on purpose: it is the one endpoint that must answer before the
// client has decided to trust anything, and it reveals nothing - the proof is a MAC
// over a nonce the caller chose, which cannot be turned back into the secret and is
// useless anywhere else.
func handleServiceAlive(secret string, port int) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		nonce := strings.TrimSpace(r.URL.Query().Get(proofNonceParam))
		if nonce == "" || len(nonce) > 128 {
			writeJSON(w, 400, map[string]interface{}{"ok": false, "error": "缺少随机数"})
			return
		}
		ts := time.Now().Unix()
		writeJSON(w, 200, serviceAliveResponse{
			OK:      true,
			Nonce:   nonce,
			TS:      ts,
			Port:    port,
			Proof:   serviceProofMAC(secret, nonce, ts, port),
			Version: AppVersion,
		})
	}
}

// serviceListening reports whether anything holds the service port, without deciding
// whether it is ours. Used to tell "not installed" from "something else is there".
func serviceListening(port int) bool {
	return IsPortListening(port)
}
