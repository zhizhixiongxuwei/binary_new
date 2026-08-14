package main

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"os"
	"os/exec"
	"os/signal"
	"syscall"
	"time"
)

const shutdownTimeout = 30 * time.Second

type commandSpec struct {
	name string
	args []string
}

type childProcess struct {
	spec commandSpec
	cmd  *exec.Cmd
}

type childResult struct {
	name string
	err  error
}

func main() {
	if err := run(os.Args[1:]); err != nil {
		_, _ = fmt.Fprintf(os.Stderr, "binaryscan-supervisor: %v\n", err)
		os.Exit(1)
	}
}

func run(args []string) error {
	if len(args) == 2 && args[0] == "healthcheck" {
		return healthcheck(args[1])
	}
	if len(args) != 1 {
		return errors.New("usage: binaryscan-supervisor app|scanner|healthcheck app|scanner")
	}

	var commands []commandSpec
	switch args[0] {
	case "app":
		if err := runOnce(commandSpec{
			name: "/usr/local/bin/binaryscan-maintenance",
			args: []string{"migrate"},
		}); err != nil {
			return fmt.Errorf("apply database migrations: %w", err)
		}
		commands = []commandSpec{
			{name: "/usr/local/bin/binaryscan-api"},
			{name: "/usr/local/bin/binaryscan-maintenance", args: []string{"run"}},
			{name: "/usr/local/bin/binaryscan-web-gateway"},
		}
	case "scanner":
		commands = scannerCommands()
	default:
		return fmt.Errorf("unknown service %q", args[0])
	}
	return supervise(commands)
}

func healthcheck(service string) error {
	switch service {
	case "app":
		if err := runOnce(commandSpec{
			name: "/usr/local/bin/binaryscan-maintenance",
			args: []string{"healthcheck"},
		}); err != nil {
			return err
		}
		client := &http.Client{Timeout: 3 * time.Second}
		response, err := client.Get("http://127.0.0.1:8080/healthz")
		if err != nil {
			return fmt.Errorf("check app HTTP endpoint: %w", err)
		}
		defer response.Body.Close()
		if response.StatusCode != http.StatusOK {
			return fmt.Errorf("app HTTP endpoint returned %s", response.Status)
		}
		return nil
	case "scanner":
		for _, role := range scannerWorkerKinds() {
			if err := runOnce(commandSpec{
				name: "/usr/local/bin/binaryscan-worker",
				args: []string{"healthcheck", "--role", role},
			}); err != nil {
				return fmt.Errorf("%s worker is unhealthy: %w", role, err)
			}
		}
		return nil
	default:
		return fmt.Errorf("unknown healthcheck service %q", service)
	}
}

func scannerCommands() []commandSpec {
	roles := scannerWorkerKinds()
	commands := make([]commandSpec, 0, len(roles)+1)
	commands = append(commands, commandSpec{
		name: "/usr/local/bin/binaryscan-archive-sandbox",
	})
	for _, role := range roles {
		commands = append(commands, commandSpec{
			name: "/usr/local/bin/binaryscan-worker",
			args: []string{"--kind=" + role},
		})
	}
	return commands
}

func scannerWorkerKinds() []string {
	return []string{"scan", "image", "trivy", "c_analysis", "java_analysis", "python_analysis", "archive_import"}
}

func runOnce(spec commandSpec) error {
	command := exec.Command(spec.name, spec.args...)
	command.Stdout = os.Stdout
	command.Stderr = os.Stderr
	command.Stdin = os.Stdin
	return command.Run()
}

func supervise(specs []commandSpec) error {
	if len(specs) == 0 {
		return errors.New("no child processes configured")
	}
	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()

	results := make(chan childResult, len(specs))
	children := make([]*childProcess, 0, len(specs))
	for _, spec := range specs {
		child := &childProcess{
			spec: spec,
			cmd:  exec.Command(spec.name, spec.args...),
		}
		child.cmd.Stdout = os.Stdout
		child.cmd.Stderr = os.Stderr
		if err := child.cmd.Start(); err != nil {
			terminate(children)
			return fmt.Errorf("start %s: %w", spec.name, err)
		}
		children = append(children, child)
		go func(value *childProcess) {
			err := value.cmd.Wait()
			results <- childResult{name: value.spec.name, err: err}
		}(child)
	}

	var resultErr error
	remaining := len(children)
	select {
	case <-ctx.Done():
	case result := <-results:
		remaining--
		if result.err == nil {
			resultErr = fmt.Errorf("required child %s exited unexpectedly", result.name)
		} else {
			resultErr = fmt.Errorf("required child %s stopped: %w", result.name, result.err)
		}
	}

	terminate(children)
	deadline := time.NewTimer(shutdownTimeout)
	defer deadline.Stop()
	for remaining > 0 {
		select {
		case <-results:
			remaining--
		case <-deadline.C:
			for _, child := range children {
				if child.cmd.Process != nil {
					_ = child.cmd.Process.Kill()
				}
			}
			return errors.Join(resultErr, errors.New("child shutdown timed out"))
		}
	}
	return resultErr
}

func terminate(children []*childProcess) {
	for _, child := range children {
		if child.cmd.Process != nil {
			_ = child.cmd.Process.Signal(syscall.SIGTERM)
		}
	}
}
