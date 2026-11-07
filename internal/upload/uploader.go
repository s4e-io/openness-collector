package upload

import (
	"bytes"
	"compress/gzip"
	"context"
	"fmt"
	"io"
	"math/rand"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/s4e-io/openness-collector/internal/version"
)

type Options struct {
	APIURL         string
	APIKey         string
	Timeout        time.Duration
	MaxRetries     int
	IdempotencyKey string
	AllowInsecure  bool
	// Gzip forces gzip Content-Encoding even if the on-disk file is plain JSON.
	Gzip bool
}

type Receipt struct {
	StatusCode int
	Body       string
}

func ValidateURL(apiURL string, allowInsecure bool) error {
	if apiURL == "" {
		return fmt.Errorf("api url required")
	}
	u, err := url.Parse(apiURL)
	if err == nil && u.Host != "" && u.User == nil &&
		(u.Scheme == "https" || allowInsecure && u.Scheme == "http") {
		return nil
	}
	return fmt.Errorf("upload URL must be https:// (pass AllowInsecure / --allow-insecure-upload for http://)")
}

func UploadFile(ctx context.Context, path string, opts Options) (*Receipt, error) {
	if err := ValidateURL(opts.APIURL, opts.AllowInsecure); err != nil {
		return nil, err
	}
	if strings.TrimSpace(opts.APIKey) == "" {
		return nil, fmt.Errorf("api token required (run: openness-collector login)")
	}
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}

	alreadyGzip := strings.HasSuffix(strings.ToLower(path), ".gz") ||
		strings.EqualFold(filepath.Ext(path), ".gz")
	contentType := "application/json"
	contentEncoding := ""
	body := data

	if alreadyGzip {
		contentEncoding = "gzip"
		contentType = "application/json"
	} else if opts.Gzip {
		var buf bytes.Buffer
		zw := gzip.NewWriter(&buf)
		if _, err := zw.Write(data); err != nil {
			return nil, err
		}
		if err := zw.Close(); err != nil {
			return nil, err
		}
		body = buf.Bytes()
		contentEncoding = "gzip"
	}

	timeout := opts.Timeout
	if timeout <= 0 {
		timeout = 60 * time.Second
	}
	retries := opts.MaxRetries
	if retries <= 0 {
		retries = 3
	}
	// Never forward either token header to a redirect target. In particular,
	// Go only strips Authorization on cross-host redirects, not X-Openness-Token.
	client := &http.Client{Timeout: timeout, CheckRedirect: func(*http.Request, []*http.Request) error {
		return http.ErrUseLastResponse
	}}
	ua := "openness/" + version.SemVer()
	var lastErr error
	for attempt := 0; attempt <= retries; attempt++ {
		if attempt > 0 {
			backoff := time.Duration(1<<uint(attempt-1)) * time.Second
			jitter := time.Duration(rand.Intn(500)) * time.Millisecond
			select {
			case <-ctx.Done():
				return nil, ctx.Err()
			case <-time.After(backoff + jitter):
			}
		}
		req, err := http.NewRequestWithContext(ctx, http.MethodPost, opts.APIURL, bytes.NewReader(body))
		if err != nil {
			return nil, err
		}
		req.Header.Set("Content-Type", contentType)
		req.Header.Set("User-Agent", ua)
		// S4E public APIs commonly expect JSON body "token"; also send Bearer for simple gateways.
		req.Header.Set("Authorization", "Bearer "+opts.APIKey)
		req.Header.Set("X-Openness-Token", opts.APIKey)
		if contentEncoding != "" {
			req.Header.Set("Content-Encoding", contentEncoding)
		}
		if opts.IdempotencyKey != "" {
			req.Header.Set("Idempotency-Key", opts.IdempotencyKey)
		}
		resp, err := client.Do(req)
		if err != nil {
			lastErr = err
			continue
		}
		respBody, _ := io.ReadAll(io.LimitReader(resp.Body, 64*1024))
		_ = resp.Body.Close()
		if resp.StatusCode >= 200 && resp.StatusCode < 300 {
			return &Receipt{StatusCode: resp.StatusCode, Body: string(respBody)}, nil
		}
		if resp.StatusCode >= 500 || resp.StatusCode == 429 {
			lastErr = fmt.Errorf("upload status %d: %s", resp.StatusCode, string(respBody))
			continue
		}
		return nil, fmt.Errorf("upload failed status %d: %s", resp.StatusCode, string(respBody))
	}
	return nil, lastErr
}
