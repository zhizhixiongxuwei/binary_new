package main

import (
	"reflect"
	"testing"
)

func TestScannerSupervisesAndHealthChecksEveryWorkerKind(t *testing.T) {
	wantKinds := []string{"scan", "image", "trivy", "c_analysis", "java_analysis", "python_analysis", "archive_import"}
	if got := scannerWorkerKinds(); !reflect.DeepEqual(got, wantKinds) {
		t.Fatalf("scanner worker kinds = %v, want %v", got, wantKinds)
	}
	wantCommands := []commandSpec{
		{name: "/usr/local/bin/binaryscan-archive-sandbox"},
		{name: "/usr/local/bin/binaryscan-worker", args: []string{"--kind=scan"}},
		{name: "/usr/local/bin/binaryscan-worker", args: []string{"--kind=image"}},
		{name: "/usr/local/bin/binaryscan-worker", args: []string{"--kind=trivy"}},
		{name: "/usr/local/bin/binaryscan-worker", args: []string{"--kind=c_analysis"}},
		{name: "/usr/local/bin/binaryscan-worker", args: []string{"--kind=java_analysis"}},
		{name: "/usr/local/bin/binaryscan-worker", args: []string{"--kind=python_analysis"}},
		{name: "/usr/local/bin/binaryscan-worker", args: []string{"--kind=archive_import"}},
	}
	if got := scannerCommands(); !reflect.DeepEqual(got, wantCommands) {
		t.Fatalf("scanner commands = %#v, want %#v", got, wantCommands)
	}
}
