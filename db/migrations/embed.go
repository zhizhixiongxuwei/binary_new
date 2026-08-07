package migrations

import "embed"

// FS contains the versioned MySQL migrations used by maintenance.
//
//go:embed *.sql
var FS embed.FS
