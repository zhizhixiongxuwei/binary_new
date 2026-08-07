// Package trivydb resolves the fixed dual-database Bundle embedded in the
// scanner image and constructs an immutable per-job cache view.
//
// Resolver.TrivyRoot directly contains bundle.json, db/versions, and
// java-db/versions. Database storage keys retain the leading "trivy/"
// component, which the resolver validates and strips exactly once.
//
// Resolution uses O_NOFOLLOW, requires sealed files and directories, validates
// the exact file set and sizes, and compares descriptor identities after cache
// links are published. VerifyIntegrity additionally hashes every declared file
// for build-time and acceptance checks. Runtime resolution has no network,
// upload, activation, rollback, mutable current-link, or application database
// dependency.
package trivydb
