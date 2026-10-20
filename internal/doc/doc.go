// Package doc downloads a document (PDF or HTML page) safely and returns its
// text. Used to read CVs / resumes found on the web.
package doc

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/ledongthuc/pdf"

	"github.com/sudosoc/rectool/internal/extract"
	"github.com/sudosoc/rectool/internal/httpx"
	"github.com/sudosoc/rectool/internal/media"
)

const (
	maxBytes = 3 << 20
	maxPages = 8
	maxText  = 200 << 10
)

// FetchText downloads rawURL (public hosts only) and returns its text. PDFs
// are text-extracted (first pages only); HTML is reduced to visible text.
func FetchText(ctx context.Context, c *httpx.Client, rawURL string) (string, error) {
	if err := media.CheckURL(ctx, rawURL); err != nil {
		return "", err
	}
	resp, err := c.Do(ctx, httpx.Request{URL: rawURL, Timeout: 30 * time.Second, MaxBody: maxBytes + 1,
		Headers: map[string]string{"Accept": "application/pdf,text/html;q=0.9,*/*;q=0.5"}})
	if err != nil {
		return "", err
	}
	if resp.StatusCode != 200 {
		return "", fmt.Errorf("HTTP %d", resp.StatusCode)
	}
	if len(resp.Body) > maxBytes {
		return "", errors.New("document too large")
	}
	if bytes.HasPrefix(resp.Body, []byte("%PDF")) {
		return pdfText(resp.Body)
	}
	if ct := strings.ToLower(resp.Header.Get("Content-Type")); strings.Contains(ct, "html") || strings.Contains(ct, "text/") {
		return clip(extract.Text(string(resp.Body))), nil
	}
	return "", errors.New("unsupported document type")
}

// pdfText extracts text from the first pages. The PDF library can panic on
// malformed files, which must never take a scan down.
func pdfText(data []byte) (out string, err error) {
	defer func() {
		if r := recover(); r != nil {
			out, err = "", fmt.Errorf("unreadable PDF: %v", r)
		}
	}()
	r, err := pdf.NewReader(bytes.NewReader(data), int64(len(data)))
	if err != nil {
		return "", err
	}
	var sb strings.Builder
	for i := 1; i <= r.NumPage() && i <= maxPages; i++ {
		p := r.Page(i)
		if p.V.IsNull() {
			continue
		}
		t, perr := p.GetPlainText(nil)
		if perr != nil {
			continue
		}
		sb.WriteString(t)
		sb.WriteByte('\n')
		if sb.Len() > maxText {
			break
		}
	}
	if strings.TrimSpace(sb.String()) == "" {
		return "", errors.New("no extractable text (scanned image?)")
	}
	return clip(sb.String()), nil
}

func clip(s string) string {
	if len(s) > maxText {
		return s[:maxText]
	}
	return s
}
