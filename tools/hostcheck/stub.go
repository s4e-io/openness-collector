package main

import (
	"bytes"
	"compress/gzip"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
)

// stub is a local stand-in for the S4E token check and ingest endpoints.
type stub struct {
	srv     *httptest.Server
	mu      sync.Mutex
	uploads []upload
	checks  []string
}

type upload struct {
	header http.Header
	raw    []byte
	body   []byte // after Content-Encoding is undone
	err    string
}

// Tokens starting with this prefix are rejected by the check endpoint.
const badTokenPrefix = "bad-"

func newStub() *stub {
	s := &stub{}
	mux := http.NewServeMux()
	mux.HandleFunc("/check", func(w http.ResponseWriter, r *http.Request) {
		var req struct {
			Token string `json:"token"`
		}
		_ = json.NewDecoder(io.LimitReader(r.Body, 1<<20)).Decode(&req)
		s.mu.Lock()
		s.checks = append(s.checks, req.Token)
		s.mu.Unlock()
		w.Header().Set("Content-Type", "application/json")
		// The real API answers HTTP 200 with the status in the JSON body.
		if strings.HasPrefix(req.Token, badTokenPrefix) {
			_, _ = w.Write([]byte(`{"code":401,"message":"token rejected by stub","error":true}`))
			return
		}
		_, _ = w.Write([]byte(`{"code":200,"message":"ok"}`))
	})
	mux.HandleFunc("/ingest", func(w http.ResponseWriter, r *http.Request) {
		raw, _ := io.ReadAll(io.LimitReader(r.Body, 512<<20))
		u := upload{header: r.Header.Clone(), raw: raw, body: raw}
		if strings.EqualFold(r.Header.Get("Content-Encoding"), "gzip") {
			zr, err := gzip.NewReader(bytes.NewReader(raw))
			if err != nil {
				u.err = err.Error()
			} else {
				u.body, err = io.ReadAll(zr)
				if err != nil {
					u.err = err.Error()
				}
			}
		}
		s.mu.Lock()
		s.uploads = append(s.uploads, u)
		s.mu.Unlock()
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"ok":true}`))
	})
	s.srv = httptest.NewServer(mux)
	return s
}

func (s *stub) URL(path string) string { return s.srv.URL + path }

func (s *stub) Close() { s.srv.Close() }

// takeUploads returns and clears the recorded uploads.
func (s *stub) takeUploads() []upload {
	s.mu.Lock()
	defer s.mu.Unlock()
	out := s.uploads
	s.uploads = nil
	return out
}
