package healthcheck

import (
	"context"
	"fmt"
	"net"
	"net/http"
	"time"
)

type Database interface {
	PingContext(context.Context) error
}

func CheckDatabase(ctx context.Context, database Database, timeout time.Duration) error {
	checkCtx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	if err := database.PingContext(checkCtx); err != nil {
		return fmt.Errorf("database is not ready: %w", err)
	}
	return nil
}

func CheckAPI(ctx context.Context, listenAddress string, timeout time.Duration) error {
	_, port, err := net.SplitHostPort(listenAddress)
	if err != nil {
		return fmt.Errorf("parse API listen address: %w", err)
	}
	url := "http://" + net.JoinHostPort("127.0.0.1", port) + "/api/v1/health/ready"
	checkCtx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	request, err := http.NewRequestWithContext(checkCtx, http.MethodGet, url, nil)
	if err != nil {
		return fmt.Errorf("create API health request: %w", err)
	}
	client := &http.Client{
		Timeout: timeout,
		CheckRedirect: func(*http.Request, []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}
	response, err := client.Do(request)
	if err != nil {
		return fmt.Errorf("call API readiness endpoint: %w", err)
	}
	defer response.Body.Close()
	if response.StatusCode != http.StatusOK {
		return fmt.Errorf("API readiness endpoint returned HTTP %d", response.StatusCode)
	}
	return nil
}
