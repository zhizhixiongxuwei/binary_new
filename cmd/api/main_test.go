package main

import "testing"

func TestAPIRejectsUnknownCommandBeforeLoadingConfiguration(t *testing.T) {
	if err := run([]string{"unknown"}); err == nil {
		t.Fatal("run() error = nil, want invalid command error")
	}
}
