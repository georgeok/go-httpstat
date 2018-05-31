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

	// The following are duration for each phase
	DNSLookup        time.Duration
	TCPConnection    time.Duration
	TLSHandshake     time.Duration
	ServerProcessing time.Duration
	contentTransfer  time.Duration

	localAddr  string
	remoteAddr string

	dnsStart      time.Time
	dnsDone       time.Time
	tcpStart      time.Time
	tcpDone       time.Time
	tlsStart      time.Time
	tlsDone       time.Time
	serverStart   time.Time
	serverDone    time.Time
	transferStart time.Time
	transferDone  time.Time // need to be provided from outside

	// isTLS is true when connection seems to use TLS
	isTLS bool

	// isReused is true when connection is reused (keep-alive)
	isReused bool
}

// WithHTTPStat is a wrapper of httptrace.WithClientTrace. It records the
// time of each httptrace hooks.
func WithHTTPStat(ctx context.Context, r *Result) context.Context {
	return httptrace.WithClientTrace(ctx, &httptrace.ClientTrace{
		DNSStart: func(i httptrace.DNSStartInfo) {
			r.dnsStart = time.Now()
		},

		DNSDone: func(i httptrace.DNSDoneInfo) {
			r.dnsDone = time.Now()

			r.DNSLookup = r.dnsDone.Sub(r.dnsStart)
			r.NameLookup = r.DNSLookup
		},

		ConnectStart: func(_, _ string) {
			r.tcpStart = time.Now()

			// When connecting to IP (When no DNS lookup)
			if r.dnsStart.IsZero() {
				r.dnsStart = r.tcpStart
				r.dnsDone = r.tcpStart
			}
		},

		ConnectDone: func(network, addr string, err error) {
			r.tcpDone = time.Now()

			r.TCPConnection = r.tcpDone.Sub(r.tcpStart)
			r.Connect = r.tcpDone.Sub(r.dnsStart)
		},

		TLSHandshakeStart: func() {
			r.isTLS = true
			r.tlsStart = time.Now()
		},

		TLSHandshakeDone: func(_ tls.ConnectionState, _ error) {
			r.tlsDone = time.Now()

			r.TLSHandshake = r.tlsDone.Sub(r.tlsStart)
			r.PreTransfer = r.tlsDone.Sub(r.dnsStart)
		},

		GotConn: func(i httptrace.GotConnInfo) {
			// Handle when keep alive is used and connection is reused.
			// DNSStart(Done) and ConnectStart(Done) is skipped
			if i.Reused {
				r.isReused = true
			}
			r.localAddr = strings.Split(i.Conn.LocalAddr().String(), ":")[0]
			r.remoteAddr = strings.Split(i.Conn.RemoteAddr().String(), ":")[0]
		},

		WroteRequest: func(info httptrace.WroteRequestInfo) {
			r.serverStart = time.Now()

			// When client doesn't use DialContext or using old (before go1.7) `net`
			// pakcage, DNS/TCP/TLS hook is not called.
			if r.dnsStart.IsZero() && r.tcpStart.IsZero() {
				now := r.serverStart

				r.dnsStart = now
				r.dnsDone = now
				r.tcpStart = now
				r.tcpDone = now
			}

			// When connection is re-used, DNS/TCP/TLS hook is not called.
			if r.isReused {
				now := r.serverStart

				r.dnsStart = now
				r.dnsDone = now
				r.tcpStart = now
				r.tcpDone = now
				r.tlsStart = now
				r.tlsDone = now
			}

			if r.isTLS {
				return
			}

			r.TLSHandshake = r.tcpDone.Sub(r.tcpDone)
			r.PreTransfer = r.Connect
		},

		GotFirstResponseByte: func() {
			r.serverDone = time.Now()

			r.ServerProcessing = r.serverDone.Sub(r.serverStart)
			r.StartTransfer = r.serverDone.Sub(r.dnsStart)

			r.transferStart = r.serverDone
		},
	})

}

func (r *Result) durations() map[string]time.Duration {
	return map[string]time.Duration{
		"DNSLookup":        r.DNSLookup,
		"TCPConnection":    r.TCPConnection,
		"TLSHandshake":     r.TLSHandshake,
		"ServerProcessing": r.ServerProcessing,
		"ContentTransfer":  r.contentTransfer,

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
	return r.localAddr
}

// Format formats stats result.
func (r Result) Format(s fmt.State, verb rune) {
	var buf bytes.Buffer
	fmt.Fprintf(&buf, "DNS lookup:        %4d ms\n",
		int(r.DNSLookup/time.Millisecond))
	fmt.Fprintf(&buf, "TCP connection:    %4d ms\n",
		int(r.TCPConnection/time.Millisecond))
	fmt.Fprintf(&buf, "TLS handshake:     %4d ms\n",
		int(r.TLSHandshake/time.Millisecond))
	fmt.Fprintf(&buf, "Server processing: %4d ms\n",
		int(r.ServerProcessing/time.Millisecond))

	if r.total > 0 {
		fmt.Fprintf(&buf, "Content transfer:  %4d ms\n\n",
			int(r.contentTransfer/time.Millisecond))
	} else {
		fmt.Fprintf(&buf, "Content transfer:  %4s ms\n\n", "-")
	}

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
	if r.dnsStart.IsZero() {
		return
	}

	r.contentTransfer = r.transferDone.Sub(r.transferStart)
	r.total = r.transferDone.Sub(r.dnsStart)
}

// ContentTransfer returns the duration of content transfer time.
// It is from first response byte to the given time. The time must
// be time after read body (go-httpstat can not detect that time).
func (r *Result) ContentTransfer(t time.Time) time.Duration {
	return t.Sub(r.serverDone)
}

// Total returns the duration of total http request.
// It is from dns lookup start time to the given time. The
// time must be time after read body (go-httpstat can not detect that time).
func (r *Result) Total(t time.Time) time.Duration {
	return t.Sub(r.dnsStart)
}
