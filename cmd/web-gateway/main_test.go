package main

import (
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestHandlerServesHealthStaticSPAAndAPI(t *testing.T) {
	root := t.TempDir()
	if err := os.Mkdir(filepath.Join(root, "assets"), 0o700); err != nil {
		t.Fatal(err)
	}
	for name, content := range map[string]string{
		"index.html":        "<main>BinaryScan</main>",
		"assets/app.js":     "console.log('ready')",
		"assets/app.js.map": "map",
	} {
		if err := os.WriteFile(filepath.Join(root, filepath.FromSlash(name)), []byte(content), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	upstream := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		writer.Header().Set("Content-Type", "application/json")
		_, _ = writer.Write([]byte(`{"path":"` + request.URL.Path + `"}`))
	}))
	defer upstream.Close()
	upstreamURL, err := url.Parse(upstream.URL)
	if err != nil {
		t.Fatal(err)
	}
	handler, err := newHandler(root, upstreamURL)
	if err != nil {
		t.Fatal(err)
	}

	assertResponse(t, handler, http.MethodGet, "/healthz", http.StatusOK, "ok")
	assertResponse(t, handler, http.MethodGet, "/assets/app.js", http.StatusOK, "console.log")
	assertResponse(t, handler, http.MethodGet, "/tasks/fixture", http.StatusOK, "BinaryScan")
	assertResponse(t, handler, http.MethodGet, "/api/v1/version", http.StatusOK, `"path":"/api/v1/version"`)
	assertResponse(t, handler, http.MethodGet, "/assets/missing.js", http.StatusNotFound, "404")
	assertResponse(t, handler, http.MethodPost, "/tasks/fixture", http.StatusMethodNotAllowed, "method not allowed")
}

func assertResponse(
	t *testing.T,
	handler http.Handler,
	method string,
	path string,
	status int,
	contains string,
) {
	t.Helper()
	request := httptest.NewRequest(method, path, nil)
	response := httptest.NewRecorder()
	handler.ServeHTTP(response, request)
	result := response.Result()
	defer result.Body.Close()
	body, err := io.ReadAll(result.Body)
	if err != nil {
		t.Fatal(err)
	}
	if result.StatusCode != status || !strings.Contains(string(body), contains) {
		t.Fatalf("%s %s returned %d %q", method, path, result.StatusCode, body)
	}
}
