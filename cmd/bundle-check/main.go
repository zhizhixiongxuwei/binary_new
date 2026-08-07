package main

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"os"

	"binaryscan/internal/trivydb"
)

func main() {
	root := flag.String("root", "/opt/trivy-cache", "fixed Trivy bundle root")
	flag.Parse()
	if flag.NArg() != 0 {
		fail(fmt.Errorf("unexpected positional arguments"))
	}
	resolver, err := trivydb.NewResolver(*root)
	if err != nil {
		fail(err)
	}
	snapshot, err := resolver.VerifyIntegrity(context.Background(), trivydb.JavaDBRequired)
	if err != nil {
		fail(err)
	}
	result := map[string]string{
		"bundle_id":             snapshot.Bundle.ID,
		"bundle_version":        snapshot.Bundle.Version,
		"content_sha256":        snapshot.Bundle.ContentSHA256,
		"trivy_db_version":      snapshot.Trivy.Version,
		"trivy_java_db_version": snapshot.Java.Version,
	}
	if err := json.NewEncoder(os.Stdout).Encode(result); err != nil {
		fail(err)
	}
}

func fail(err error) {
	_, _ = fmt.Fprintf(os.Stderr, "bundle-check: %v\n", err)
	os.Exit(1)
}
