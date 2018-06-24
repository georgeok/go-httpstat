// Package httpstat traces HTTP latency infomation (DNSLookup, TCP Connection and so on) on any golang HTTP request.
// It uses `httptrace` package. Just create `go-httpstat` powered `context.Context` and give it your `http.Request` (no big code modification is required).
package httpstat

import (
	"bytes"
	"fmt"
	"io"
	"strings"
	"time"
	"net/http/httptrace"
	"crypto/tls"
	"context"
)

// Result stores httpstat info.
//  |
//  |--NameLookup
//  |--|--Connect
//  |--|--|--APPCONNECT
//  |--|--|--|--PreTransfer
//  |--|--|--|--|--StartTransfer
//  |--|--|--|--|--|--total
//  |--|--|--|--|--|--REDIRECT
type Result struct {
	// The followings are timeline of request
	NameLookup    time.Duration
	Connect       time.Duration
	PreTransfer   time.Duration
	StartTransfer time.Duration
	total         time.Duration

	localAddr    string
	remoteAddr   string
	start        time.Time // the zero time for the request
	transferDone time.Time // need to be provided from outside
}

// WithHTTPStat is a wrapper of httptrace.WithClientTrace. It records the
// time of each httptrace hooks.
func WithHTTPStat(ctx context.Context, r *Result) context.Context {
	var (
		dnsStart    time.Time
		dnsDone     time.Time
		tcpStart    time.Time
		tcpDone     time.Time
		tlsDone     time.Time
		serverStart time.Time
		serverDone  time.Time

		// isTLS is true when connection seems to use TLS
		isTLS bool
		// isReused is true when connection is reused (keep-alive)
		isReused bool
	)

	return httptrace.WithClientTrace(ctx, &httptrace.ClientTrace{
		DNSStart: func(i httptrace.DNSStartInfo) {
			dnsStart = time.Now()
			if r.start.IsZero() {
				r.start = dnsStart
			}
		},

		DNSDone: func(i httptrace.DNSDoneInfo) {
			dnsDone = time.Now()
			r.NameLookup += dnsDone.Sub(dnsStart)
		},

		ConnectStart: func(_, _ string) {
			tcpStart = time.Now()

			// When connecting to IP (When no DNS lookup)
			if dnsStart.IsZero() {
				dnsStart = tcpStart
				dnsDone = tcpStart
			}

			if r.start.IsZero() {
				r.start = tcpStart
			}
		},

		ConnectDone: func(network, addr string, err error) {
			tcpDone = time.Now()
			r.Connect += tcpDone.Sub(dnsStart)
		},

		TLSHandshakeStart: func() {
			isTLS = true
		},

		TLSHandshakeDone: func(_ tls.ConnectionState, _ error) {
			tlsDone = time.Now()
			r.PreTransfer += tlsDone.Sub(dnsStart)
		},

		GotConn: func(i httptrace.GotConnInfo) {
			// Handle when keep alive is used and connection is reused.
			// DNSStart(Done) and ConnectStart(Done) is skipped
			gotC := time.Now()
			if i.Reused {
				isReused = true
				if dnsStart.IsZero() {
					dnsStart = gotC
					dnsDone = gotC
				}

				if r.start.IsZero() {
					r.start = gotC
				}
			}
			if i.Conn.LocalAddr() != nil {
				r.localAddr = strings.Split(i.Conn.LocalAddr().String(), ":")[0]
			}
			if i.Conn.RemoteAddr() != nil {
				r.remoteAddr = strings.Split(i.Conn.RemoteAddr().String(), ":")[0]
			}
		},

		WroteRequest: func(info httptrace.WroteRequestInfo) {
			serverStart = time.Now()

			// When client doesn't use DialContext or using old (before go1.7) `net`
			// pakcage, DNS/TCP/TLS hook is not called.
			if dnsStart.IsZero() && tcpStart.IsZero() {
				now := serverStart

				dnsStart = now
				dnsDone = now
				tcpStart = now
				tcpDone = now
			}

			// When connection is re-used, DNS/TCP/TLS hook is not called.
			if isReused {
				now := serverStart

				dnsStart = now
				dnsDone = now
				tcpStart = now
				tcpDone = now
				tlsDone = now
			}

			if isTLS {
				return
			}

			r.PreTransfer += r.Connect
		},

		GotFirstResponseByte: func() {
			serverDone = time.Now()
			r.StartTransfer += serverDone.Sub(dnsStart)
		},
	})

}

func (r *Result) durations() map[string]time.Duration {
	return map[string]time.Duration{
		"NameLookup":    r.NameLookup,
		"Connect":       r.Connect,
		"PreTransfer":   r.Connect,
		"StartTransfer": r.StartTransfer,
		"Total":         r.total,
	}
}

func (r *Result) LocalIp() string {
	return r.localAddr
}

func (r *Result) RemoteIP() string {
	return r.remoteAddr
}

// Format formats stats result.
func (r Result) Format(s fmt.State, verb rune) {
	var buf bytes.Buffer
	fmt.Fprintf(&buf, "Name Lookup:    %4d ms\n",
		int(r.NameLookup/time.Millisecond))
	fmt.Fprintf(&buf, "Connect:        %4d ms\n",
		int(r.Connect/time.Millisecond))
	fmt.Fprintf(&buf, "Pre Transfer:   %4d ms\n",
		int(r.PreTransfer/time.Millisecond))
	fmt.Fprintf(&buf, "Start Transfer: %4d ms\n",
		int(r.StartTransfer/time.Millisecond))

	if r.total > 0 {
		fmt.Fprintf(&buf, "Total:          %4d ms\n",
			int(r.total/time.Millisecond))
	} else {
		fmt.Fprintf(&buf, "Total:          %4s ms\n", "-")
	}
	io.WriteString(s, buf.String())
	return
}

// End sets the time when reading response is done.
// This must be called after reading response body.
func (r *Result) End(t time.Time) {
	r.transferDone = t
	// This means result is empty (it does nothing).
	// Skip setting value(contentTransfer and total will be zero).
	if r.start.IsZero() {
		return
	}
	r.total = r.transferDone.Sub(r.start)
}

// Total returns the duration of total http request.
// It is from dns lookup start time to the given time. The
// time must be time after read body (go-httpstat can not detect that time).
func (r *Result) Total(t time.Time) time.Duration {
	if r.total == 0 {
		return t.Sub(r.start)
	} else {
		return r.total
	}

}
