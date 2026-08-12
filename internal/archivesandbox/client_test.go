package archivesandbox

import (
	"context"
	"errors"
	"net"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestExchangeClosesUnresponsiveConnectionWhenContextIsCancelled(t *testing.T) {
	root, err := os.MkdirTemp("/tmp", "binaryscan-archive-client-")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(root) })
	input := filepath.Join(root, "input")
	output := filepath.Join(root, "output")
	for _, directory := range []string{input, output} {
		if err := os.Mkdir(directory, 0o700); err != nil {
			t.Fatal(err)
		}
	}
	socket := filepath.Join(root, "archive.sock")
	listener, err := net.ListenUnix("unix", &net.UnixAddr{Name: socket, Net: "unix"})
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()
	accepted := make(chan struct{})
	go func() {
		connection, acceptErr := listener.AcceptUnix()
		if acceptErr != nil {
			return
		}
		defer connection.Close()
		close(accepted)
		var request Request
		_ = readFrame(connection, &request)
		var ignored [1]byte
		_, _ = connection.Read(ignored[:])
	}()

	client, err := NewClient(ClientConfig{
		SocketPath: socket, InputRoot: input, OutputRoot: output,
		Timeout: time.Minute,
	})
	if err != nil {
		t.Fatal(err)
	}
	defer client.Close()
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() {
		_, _, exchangeErr := client.exchange(ctx, Request{
			SchemaVersion: SchemaVersion,
			RequestID:     "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
			Operation:     OperationPing,
		})
		done <- exchangeErr
	}()
	select {
	case <-accepted:
		cancel()
	case <-time.After(time.Second):
		t.Fatal("client did not connect")
	}
	select {
	case err := <-done:
		if !errors.Is(err, context.Canceled) {
			t.Fatalf("exchange() error = %v, want context cancellation", err)
		}
	case <-time.After(time.Second):
		t.Fatal("exchange remained blocked after cancellation")
	}
}
