package upload_test

import (
	"context"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/s4e-io/openness-collector/internal/upload"
)

type redirectTransport func(*http.Request) (*http.Response, error)

func (f redirectTransport) RoundTrip(r *http.Request) (*http.Response, error) { return f(r) }

func TestValidateURLRequiresHTTPS(t *testing.T) {
	if err := upload.ValidateURL("http://example.com/upload", false); err == nil {
		t.Fatal("expected http reject without allowInsecure")
	}
	if err := upload.ValidateURL("https://example.com/upload", false); err != nil {
		t.Fatal(err)
	}
	if err := upload.ValidateURL("http://127.0.0.1/upload", true); err != nil {
		t.Fatal(err)
	}
	if err := upload.ValidateURL("", false); err == nil || !strings.Contains(err.Error(), "required") {
		t.Fatalf("expected required error, got %v", err)
	}
}

func TestUploadDoesNotForwardTokenOnRedirect(t *testing.T) {
	var leaked bool
	old := http.DefaultTransport
	http.DefaultTransport = redirectTransport(func(r *http.Request) (*http.Response, error) {
		if r.URL.Host == "target.example" {
			leaked = r.Header.Get("Authorization") != "" || r.Header.Get("X-Openness-Token") != ""
			return &http.Response{StatusCode: http.StatusOK, Body: io.NopCloser(strings.NewReader("")), Header: make(http.Header)}, nil
		}
		return &http.Response{StatusCode: http.StatusTemporaryRedirect, Body: io.NopCloser(strings.NewReader("")),
			Header: http.Header{"Location": {"https://target.example/upload"}}}, nil
	})
	t.Cleanup(func() { http.DefaultTransport = old })
	path := filepath.Join(t.TempDir(), "evidence.json")
	if err := os.WriteFile(path, []byte(`{}`), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := upload.UploadFile(context.Background(), path, upload.Options{
		APIURL: "https://source.example/upload", APIKey: "secret", MaxRetries: 1,
	}); err == nil {
		t.Fatal("expected redirect to fail")
	}
	if leaked {
		t.Fatal("token reached redirect target")
	}
}
