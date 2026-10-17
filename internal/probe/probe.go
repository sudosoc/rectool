// Package probe contains the active-but-ordinary checks shared by the domain
// and IP modules: fetch a site the way a browser would, and read the TLS
// certificate a server presents.
package probe

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/hex"
	"net"
	"net/http"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/sudosoc/rectool/internal/extract"
	"github.com/sudosoc/rectool/internal/httpx"
)

// Web is the result of fetching a site's front page.
type Web struct {
	URL      string // what was requested
	FinalURL string // after redirects
	Status   int
	Header   http.Header
	Body     string
	Meta     extract.Meta
}

// FetchWeb requests https://host/ and falls back to http://. host may be a
// name or an IP literal.
func FetchWeb(ctx context.Context, c *httpx.Client, host string) (*Web, error) {
	var lastErr error
	for _, scheme := range []string{"https", "http"} {
		u := scheme + "://" + host + "/"
		resp, err := c.Do(ctx, httpx.Request{URL: u, Timeout: 15 * time.Second})
		if err != nil {
			lastErr = err
			continue
		}
		body := string(resp.Body)
		return &Web{URL: u, FinalURL: resp.FinalURL, Status: resp.StatusCode, Header: resp.Header,
			Body: body, Meta: extract.ParseMeta(body)}, nil
	}
	return nil, lastErr
}

// SecurityHeaders reports which common hardening headers are present or absent.
func SecurityHeaders(h http.Header, https bool) (present, missing []string) {
	check := []string{"Strict-Transport-Security", "Content-Security-Policy", "X-Frame-Options",
		"X-Content-Type-Options", "Referrer-Policy", "Permissions-Policy"}
	for _, name := range check {
		if name == "Strict-Transport-Security" && !https {
			continue
		}
		if h.Get(name) != "" {
			present = append(present, name)
		} else {
			missing = append(missing, name)
		}
	}
	return present, missing
}

// Cert is the leaf certificate a server presented.
type Cert struct {
	Subject    string
	Issuer     string
	NotBefore  time.Time
	NotAfter   time.Time
	SANs       []string
	Serial     string
	SigAlg     string
	TLSVersion string
	SelfSigned bool
}

// FetchCert connects to host:port, performs a TLS handshake without
// verifying the chain (we want to *read* whatever is presented) and returns
// the leaf certificate. SNI is sent when host is a name.
func FetchCert(ctx context.Context, host string, port int) (*Cert, error) {
	d := tls.Dialer{
		NetDialer: &net.Dialer{Timeout: 8 * time.Second},
		Config:    &tls.Config{InsecureSkipVerify: true, MinVersion: tls.VersionTLS10}, //nolint:gosec // inspection only
	}
	if net.ParseIP(host) == nil {
		d.Config.ServerName = host
	}
	ctx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()
	conn, err := d.DialContext(ctx, "tcp", net.JoinHostPort(host, strconv.Itoa(port)))
	if err != nil {
		return nil, err
	}
	defer conn.Close()
	st := conn.(*tls.Conn).ConnectionState()
	if len(st.PeerCertificates) == 0 {
		return nil, context.DeadlineExceeded
	}
	return certInfo(st.PeerCertificates[0], st.Version), nil
}

func certInfo(c *x509.Certificate, ver uint16) *Cert {
	sans := append([]string(nil), c.DNSNames...)
	for _, ip := range c.IPAddresses {
		sans = append(sans, ip.String())
	}
	sort.Strings(sans)
	return &Cert{
		Subject: c.Subject.CommonName, Issuer: strings.TrimSpace(c.Issuer.CommonName + " " + strings.Join(c.Issuer.Organization, " ")),
		NotBefore: c.NotBefore, NotAfter: c.NotAfter, SANs: sans,
		Serial: hex.EncodeToString(c.SerialNumber.Bytes()), SigAlg: c.SignatureAlgorithm.String(),
		TLSVersion: tls.VersionName(ver), SelfSigned: c.Subject.String() == c.Issuer.String(),
	}
}
