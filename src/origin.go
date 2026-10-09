package main

// ---------------------------------------------------------------------------
// Who is allowed to reach the interface.
//
// The token is a defence against a malicious web page, and it works for that: a
// page on another origin cannot read the token, and cannot send it. Two things it
// does not do, and the review is right to name both.
//
// First, it cannot distinguish one local process from another. Any process on this
// machine that can open a loopback connection can fetch the page and read the token
// out of it. That is not a bug to fix by choosing a better token - HTTP has no way
// to authenticate a process identity, and anything that claimed to would be
// guessing. The honest statement is that the interface is protected against web
// origins and not against local processes, and the README says so.
//
// Second, the page served the token to anybody who asked, including a browser
// that had been talked into asking by a page on another site. A navigation from a
// hostile page to http://127.0.0.1:<port>/ carries the hostile page's Origin, and
// the response carried our token into a document that page could then read.
//
// What this file adds is the distinction that is available: where a request came
// from, as the browser reports it. Fetch Metadata is sent by every current browser
// and cannot be set by a page, so a cross-site attempt is identified and refused
// while an ordinary navigation to our own interface is allowed through.
//
// Requests with no metadata at all - curl, a script, another local program - are
// allowed, because they are the case that cannot be distinguished and refusing them
// would break the command-line diagnostics this program documents. That is stated
// rather than papered over.
// ---------------------------------------------------------------------------

import (
	"net"
	"net/http"
	"net/url"
	"strings"
)

// requestOriginClass says where a request came from, as far as the browser reports.
type requestOriginClass int

const (
	// originUnknown means the client sent no Fetch Metadata. A non-browser client,
	// or an older one.
	originUnknown requestOriginClass = iota
	// originOurs means the browser says this is our own page, or a navigation the
	// user started.
	originOurs
	// originForeign means a page on another origin caused this request.
	originForeign
)

// classifyRequestOrigin decides which of the three this is.
//
// The signals, in order of how much they can be trusted:
//
//   - Sec-Fetch-Site is set by the browser and a page cannot forge it. "cross-site"
//     is a foreign page; "same-origin" is ours; "none" is a navigation the user
//     started, which is what opening the window is.
//   - Origin is set on cross-origin requests and on same-origin non-GET requests. A
//     foreign Origin is decisive; ours is fine.
//   - Neither header means a non-browser client. Reported as unknown rather than
//     guessed at.
func classifyRequestOrigin(r *http.Request, expectHost string) requestOriginClass {
	if r.Header.Get("Origin") != "" && !originIsOurs(r.Header.Get("Origin"), expectHost) {
		return originForeign
	}
	switch strings.ToLower(strings.TrimSpace(r.Header.Get("Sec-Fetch-Site"))) {
	case "cross-site", "same-site":
		// "same-site" is another port on 127.0.0.1. Different application, same
		// site, which is exactly the case a token in the page must not be handed to.
		return originForeign
	case "same-origin", "none":
		return originOurs
	case "":
		if r.Header.Get("Origin") != "" {
			return originOurs
		}
		return originUnknown
	default:
		// An unrecognised value is not a reason to trust the request.
		return originForeign
	}
}

// originIsOurs compares an Origin header against the host this server is listening
// on.
//
// The comparison is exact on scheme, host and port. The previous check accepted any
// loopback origin, so a page served from another loopback port - a different
// application on this machine, or something the user is running locally - was
// treated as ours.
func originIsOurs(origin, expectHost string) bool {
	u, err := url.Parse(origin)
	if err != nil || u.Host == "" {
		return false
	}
	if !strings.EqualFold(u.Scheme, "http") {
		// This server is http only; an https origin cannot be it.
		return false
	}
	return sameHostPort(u.Host, expectHost)
}

// sameHostPort compares two host:port pairs.
//
// Two things are deliberate here.
//
// Loopback names are equivalent: a node client may spell the interface as
// `localhost` or as `127.0.0.1`, and both are the same server. Comparing the literal
// text would refuse one of them.
//
// A missing port does NOT adopt the other side's. `http://127.0.0.1` means port 80,
// not this server's port, so treating it as a match would accept an origin that is
// not ours. A request that arrives without a port - which a browser does not do, but
// a local client might - is normalised to the scheme default.
func sameHostPort(a, b string) bool {
	ah, ap := splitHostPortLoose(a)
	bh, bp := splitHostPortLoose(b)
	if !loopbackNames(ah, bh) {
		return false
	}
	if ap == "" {
		ap = "80"
	}
	if bp == "" {
		bp = "80"
	}
	return ap == bp
}

// loopbackNames reports whether two host names refer to the same loopback address.
func loopbackNames(a, b string) bool {
	if strings.EqualFold(a, b) {
		return true
	}
	// The set a browser will produce for this server.
	isLoop := func(h string) bool {
		if strings.EqualFold(h, "localhost") {
			return true
		}
		if ip := net.ParseIP(h); ip != nil {
			return ip.IsLoopback()
		}
		return false
	}
	return isLoop(a) && isLoop(b)
}

func splitHostPortLoose(hp string) (host, port string) {
	if h, p, err := net.SplitHostPort(hp); err == nil {
		return strings.Trim(h, "[]"), p
	}
	return strings.Trim(hp, "[]"), ""
}

// allowInterfaceRequest refuses a request that a foreign page caused.
//
// It answers through the same JSON shape as the rest of the API so a refusal is
// legible, and it is deliberately usable as a plain boolean by the callers that
// only need to know whether to continue.
func interfaceRequestAllowed(r *http.Request, expectHost string) bool {
	return classifyRequestOrigin(r, expectHost) != originForeign
}

// expectHostFor is the host:port this server answers on, used as the reference for
// origin comparisons.
func expectHostFor(port int) string {
	return "127.0.0.1:" + itoa(port)
}
