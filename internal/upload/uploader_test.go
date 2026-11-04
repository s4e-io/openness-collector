package upload_test

import (
	"strings"
	"testing"

	"github.com/s4e-io/openness-collector/internal/upload"
)

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
