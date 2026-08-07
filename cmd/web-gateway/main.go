package main

import (
	"context"
	"errors"
	"log/slog"
	"net"
	"net/http"
	"net/http/httputil"
	"net/url"
	"os"
	"os/signal"
	"path"
	"path/filepath"
	"strings"
	"syscall"
	"time"
)

const (
	defaultAddress  = ":8080"
	defaultRoot     = "/opt/binaryscan/web"
	defaultUpstream = "http://127.0.0.1:8081"
)

func main() {
	if err := run(); err != nil {
		slog.Error("web gateway stopped", "error", err)
		os.Exit(1)
	}
}

func run() error {
	address := environment("BINARYSCAN_GATEWAY_ADDR", defaultAddress)
	root := environment("BINARYSCAN_WEB_ROOT", defaultRoot)
	upstream, err := url.Parse(environment("BINARYSCAN_API_UPSTREAM", defaultUpstream))
	if err != nil || upstream.Scheme != "http" || upstream.Host == "" || upstream.Path != "" {
		return errors.New("BINARYSCAN_API_UPSTREAM must be an HTTP origin without a path")
	}
	root, err = filepath.Abs(root)
	if err != nil || filepath.Clean(root) != root {
		return errors.New("BINARYSCAN_WEB_ROOT must be a canonical absolute path")
	}
	if info, err := os.Stat(filepath.Join(root, "index.html")); err != nil || !info.Mode().IsRegular() {
		return errors.New("web bundle index.html is unavailable")
	}

	handler, err := newHandler(root, upstream)
	if err != nil {
		return err
	}
	server := &http.Server{
		Addr:              address,
		Handler:           handler,
		ReadHeaderTimeout: 10 * time.Second,
		IdleTimeout:       60 * time.Second,
		MaxHeaderBytes:    1 << 20,
	}
	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()

	errorsChannel := make(chan error, 1)
	go func() {
		errorsChannel <- server.ListenAndServe()
	}()
	select {
	case serveErr := <-errorsChannel:
		if !errors.Is(serveErr, http.ErrServerClosed) {
			return serveErr
		}
		return nil
	case <-ctx.Done():
	}

	shutdown, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	if err := server.Shutdown(shutdown); err != nil {
		_ = server.Close()
		return err
	}
	return nil
}

func newHandler(root string, upstream *url.URL) (http.Handler, error) {
	if upstream == nil {
		return nil, errors.New("API upstream is required")
	}
	proxy := httputil.NewSingleHostReverseProxy(upstream)
	proxy.FlushInterval = -1
	proxy.Transport = &http.Transport{
		Proxy:               nil,
		DialContext:         (&net.Dialer{Timeout: 5 * time.Second, KeepAlive: 30 * time.Second}).DialContext,
		ForceAttemptHTTP2:   false,
		MaxIdleConns:        32,
		IdleConnTimeout:     90 * time.Second,
		TLSHandshakeTimeout: 5 * time.Second,
	}
	proxy.ErrorHandler = func(writer http.ResponseWriter, request *http.Request, err error) {
		http.Error(writer, "API unavailable", http.StatusBadGateway)
	}
	files := http.FileServer(http.Dir(root))

	return http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		writer.Header().Set("X-Content-Type-Options", "nosniff")
		writer.Header().Set("X-Frame-Options", "DENY")
		writer.Header().Set("Referrer-Policy", "no-referrer")
		clean := path.Clean("/" + request.URL.Path)
		switch {
		case clean == "/healthz":
			writer.Header().Set("Cache-Control", "no-store")
			writer.WriteHeader(http.StatusOK)
			_, _ = writer.Write([]byte("ok\n"))
			return
		case clean == "/api" || strings.HasPrefix(clean, "/api/"):
			proxy.ServeHTTP(writer, request)
			return
		case request.Method != http.MethodGet && request.Method != http.MethodHead:
			http.Error(writer, "method not allowed", http.StatusMethodNotAllowed)
			return
		}

		relative := strings.TrimPrefix(clean, "/")
		candidate := filepath.Join(root, filepath.FromSlash(relative))
		if relative != "" {
			if info, err := os.Stat(candidate); err == nil && info.Mode().IsRegular() {
				if strings.HasPrefix(clean, "/assets/") {
					writer.Header().Set("Cache-Control", "public, max-age=31536000, immutable")
				}
				request.URL.Path = clean
				files.ServeHTTP(writer, request)
				return
			}
		}
		if strings.HasPrefix(clean, "/assets/") {
			http.NotFound(writer, request)
			return
		}
		writer.Header().Set("Cache-Control", "no-cache")
		http.ServeFile(writer, request, filepath.Join(root, "index.html"))
	}), nil
}

func environment(name string, fallback string) string {
	if value := strings.TrimSpace(os.Getenv(name)); value != "" {
		return value
	}
	return fallback
}
