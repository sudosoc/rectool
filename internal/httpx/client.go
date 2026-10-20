// Package httpx provides the hardened HTTP client used by every module:
// tuned timeouts and connection reuse, per-request User-Agent rotation,
// browser-like header spoofing, retry with jittered backoff, and HTTP/SOCKS5
// proxy rotation.
package httpx

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"io"
	"math/rand/v2"
	"net"
	"net/http"
	"net/url"
	"strings"
	"sync/atomic"
	"time"
)

// Options configures a Client. Zero values select sensible defaults.
type Options struct {
	Timeout      time.Duration // whole-request timeout (default 12s)
	DialTimeout  time.Duration // TCP/TLS connect timeout (default 6s)
	Retries      int           // extra attempts on network error / 429 / 502-504 (default 1)
	MaxBodyBytes int64         // response body cap (default 512 KiB)
	MaxRedirects int           // redirects followed when enabled (default 8)
	MaxDials     int           // simultaneous connection attempts incl. DNS lookups (default 96)
	MaxInFlight  int           // simultaneous requests across all modules (default 110)
	Proxies      []string      // http://, https://, socks5:// or socks5h:// ; rotated round-robin
	InsecureTLS  bool          // skip certificate verification (off by default)
}

func (o *Options) defaults() {
	if o.Timeout <= 0 {
		o.Timeout = 12 * time.Second
	}
	if o.DialTimeout <= 0 {
		o.DialTimeout = 6 * time.Second
	}
	if o.Retries < 0 {
		o.Retries = 0
	}
	if o.MaxBodyBytes <= 0 {
		o.MaxBodyBytes = 512 << 10
	}
	if o.MaxRedirects <= 0 {
		o.MaxRedirects = 8
	}
	if o.MaxDials <= 0 {
		o.MaxDials = 96
	}
	if o.MaxInFlight <= 0 {
		o.MaxInFlight = 110
	}
}

// Request describes one HTTP call.
type Request struct {
	Method     string // default GET
	URL        string
	Headers    map[string]string // override the spoofed defaults
	Body       string
	NoRedirect bool          // return the first response instead of following redirects
	Timeout    time.Duration // per-call override of the client timeout (0 = client default)
	MaxBody    int64         // per-call override of the response size cap (0 = client default)
}

// Response is the (body-capped) result of a Request.
type Response struct {
	StatusCode int
	Header     http.Header
	Body       []byte
	FinalURL   string
	Elapsed    time.Duration
}

// Client is safe for concurrent use.
type Client struct {
	opts     Options
	slots    chan struct{} // limits requests in flight; waiting here does not count against a request's timeout
	follow   *http.Client
	noFollow *http.Client
}

// New builds a Client. It returns an error for malformed proxy URLs.
func New(o Options) (*Client, error) {
	o.defaults()

	proxies, err := parseProxies(o.Proxies)
	if err != nil {
		return nil, err
	}

	tr := &http.Transport{
		DialContext:           limitedDial(&net.Dialer{Timeout: o.DialTimeout, KeepAlive: 30 * time.Second}, o.MaxDials),
		TLSHandshakeTimeout:   o.DialTimeout,
		ExpectContinueTimeout: time.Second,
		IdleConnTimeout:       30 * time.Second,
		MaxIdleConns:          2048,
		MaxIdleConnsPerHost:   8,
		ForceAttemptHTTP2:     true,
		TLSClientConfig:       &tls.Config{MinVersion: tls.VersionTLS12, InsecureSkipVerify: o.InsecureTLS}, //nolint:gosec // opt-in flag
	}
	if len(proxies) > 0 {
		var n atomic.Uint64
		tr.Proxy = func(*http.Request) (*url.URL, error) {
			return proxies[(n.Add(1)-1)%uint64(len(proxies))], nil
		}
	}

	maxRedir := o.MaxRedirects
	return &Client{
		opts:  o,
		slots: make(chan struct{}, o.MaxInFlight),
		follow: &http.Client{
			Transport: tr,
			CheckRedirect: func(_ *http.Request, via []*http.Request) error {
				if len(via) >= maxRedir {
					return errors.New("too many redirects")
				}
				return nil
			},
		},
		noFollow: &http.Client{
			Transport:     tr,
			CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse },
		},
	}, nil
}

func parseProxies(raw []string) ([]*url.URL, error) {
	var out []*url.URL
	for _, p := range raw {
		p = strings.TrimSpace(p)
		if p == "" {
			continue
		}
		u, err := url.Parse(p)
		if err != nil || u.Host == "" {
			return nil, fmt.Errorf("invalid proxy %q", p)
		}
		switch u.Scheme {
		case "http", "https", "socks5", "socks5h":
		default:
			return nil, fmt.Errorf("unsupported proxy scheme %q (use http, https, socks5, socks5h)", u.Scheme)
		}
		out = append(out, u)
	}
	return out, nil
}

// Do executes req, retrying transient failures. A non-nil Response is
// returned even for 4xx/5xx statuses; err is only for transport failures.
func (c *Client) Do(ctx context.Context, req Request) (*Response, error) {
	select {
	case c.slots <- struct{}{}:
		defer func() { <-c.slots }()
	case <-ctx.Done():
		return nil, ctx.Err()
	}
	for attempt := 0; ; attempt++ {
		resp, err := c.once(ctx, req)

		retryable := err != nil ||
			resp.StatusCode == http.StatusTooManyRequests ||
			(resp.StatusCode >= 502 && resp.StatusCode <= 504)
		if !retryable || attempt >= c.opts.Retries {
			return resp, err
		}
		if ctx.Err() != nil {
			return nil, ctx.Err()
		}

		backoff := time.Duration(1<<attempt)*400*time.Millisecond +
			time.Duration(rand.Int64N(int64(300*time.Millisecond)))
		t := time.NewTimer(backoff)
		select {
		case <-ctx.Done():
			t.Stop()
			return nil, ctx.Err()
		case <-t.C:
		}
	}
}

func (c *Client) once(ctx context.Context, r Request) (*Response, error) {
	method := r.Method
	if method == "" {
		method = http.MethodGet
	}
	var body io.Reader
	if r.Body != "" {
		body = strings.NewReader(r.Body)
	}
	// The deadline lives on the context (not http.Client.Timeout) so a single
	// request can ask for longer than the client default.
	timeout := r.Timeout
	if timeout <= 0 {
		timeout = c.opts.Timeout
	}
	ctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	hr, err := http.NewRequestWithContext(ctx, method, r.URL, body)
	if err != nil {
		return nil, err
	}
	spoofHeaders(hr.Header)
	for k, v := range r.Headers {
		hr.Header.Set(k, v)
	}

	hc := c.follow
	if r.NoRedirect {
		hc = c.noFollow
	}

	start := time.Now()
	resp, err := hc.Do(hr)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	limit := c.opts.MaxBodyBytes
	if r.MaxBody > 0 {
		limit = r.MaxBody
	}
	data, err := io.ReadAll(io.LimitReader(resp.Body, limit))
	if err != nil {
		return nil, err
	}
	return &Response{
		StatusCode: resp.StatusCode,
		Header:     resp.Header,
		Body:       data,
		FinalURL:   resp.Request.URL.String(),
		Elapsed:    time.Since(start),
	}, nil
}

// spoofHeaders sets a browser-like navigation header set with a fresh
// User-Agent. Accept-Encoding is deliberately left unset so Go negotiates and
// transparently decodes gzip itself.
func spoofHeaders(h http.Header) {
	h.Set("User-Agent", RandomUserAgent())
	h.Set("Accept", "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8")
	h.Set("Accept-Language", randomAcceptLanguage())
	h.Set("Upgrade-Insecure-Requests", "1")
	h.Set("Sec-Fetch-Dest", "document")
	h.Set("Sec-Fetch-Mode", "navigate")
	h.Set("Sec-Fetch-Site", "none")
	h.Set("Sec-Fetch-User", "?1")
	h.Set("DNT", "1")
}

// limitedDial caps concurrent connection attempts. Hundreds of simultaneous
// DNS lookups overwhelm many local resolvers and show up as bogus
// "no such host" errors; queueing the dials keeps results trustworthy.
func limitedDial(d *net.Dialer, max int) func(ctx context.Context, network, addr string) (net.Conn, error) {
	sem := make(chan struct{}, max)
	return func(ctx context.Context, network, addr string) (net.Conn, error) {
		select {
		case sem <- struct{}{}:
			defer func() { <-sem }()
		case <-ctx.Done():
			return nil, ctx.Err()
		}
		return d.DialContext(ctx, network, addr)
	}
}
