package main

import (
	"errors"
	"net/http"
	"os"
	"os/exec"
	"strings"
	"testing"

	opensearchpkg "github.com/define42/opensearchgateway/internal/opensearch"
)

func TestMainFailurePathExitsNonZero(t *testing.T) {
	if os.Getenv("OPENSEARCHGATEWAY_CALL_MAIN") == "1" {
		main()
		return
	}

	cmd := exec.Command(os.Args[0], "-test.run=TestMainFailurePathExitsNonZero")
	cmd.Env = append(os.Environ(),
		"OPENSEARCHGATEWAY_CALL_MAIN=1",
		"OPENSEARCH_URL=://bad",
	)

	output, err := cmd.CombinedOutput()
	if err == nil {
		t.Fatal("expected main() subprocess to exit with an error")
	}

	var exitErr *exec.ExitError
	if !errors.As(err, &exitErr) {
		t.Fatalf("expected exit error, got %v", err)
	}
	if exitErr.ExitCode() == 0 {
		t.Fatalf("expected non-zero exit code, got %d", exitErr.ExitCode())
	}
	if !strings.Contains(string(output), "error:") {
		t.Fatalf("expected fatal error output, got %q", string(output))
	}
}

func TestClientMarkEnsuredHelpers(t *testing.T) {
	client := newClient(Config{HTTPClient: http.DefaultClient})

	client.MarkTenantEnsured("orders")
	if _, ok := client.ensuredTenants.Load("orders"); !ok {
		t.Fatal("expected tenant cache to contain orders")
	}

	key := "orders/" + opensearchpkg.BuildDataViewID("orders")
	client.MarkDataViewEnsured(key)
	if _, ok := client.ensuredDataViews.Load(key); !ok {
		t.Fatal("expected data-view cache to contain orders data view")
	}
}
