# BinaryScan Java Checker

Internal Spring Boot 3.5.13 service for high-precision AST checks over a
decompiled Java source project. It runs on JDK 17 and pins
`javaparser-core:3.28.2`; Symbol Solver is intentionally not present.

## Build

```sh
mvn test
mvn -DskipTests package
```

The resulting Spring Boot fat jar is `target/java-checker.jar`.

## HTTP contract

`POST /internal/v1/analyses/{analysis_id}` accepts multipart parts:

- `metadata`: `application/json`, schema `java-analysis-input-v1`.
- `source`: `application/octet-stream`, the exact concatenation of file bytes.

`analysis_id` is a canonical UUID. Metadata files are sorted by UTF-8
`logical_path` and contain `result_id`, `logical_path`, `binary_name`, optional
`display_name`, `sha256`, `offset_bytes`, and `length_bytes`. `offset` and
`length` are accepted as compatibility aliases. Ranges must start at zero, be
contiguous, and cover the complete bundle. Every range is checked for SHA-256
and strict UTF-8.

`bundle_sha256` is SHA-256 over the source part. `input_sha256` uses this exact
UTF-8 framing, where `NUL` is byte `0x00`:

```text
java-analysis-input-v1\n
result_id NUL logical_path NUL binary_name NUL decimal_length NUL lowercase_sha256\n
```

The file line is repeated in sorted order. Offsets, display names,
`analysis_id`, and `bundle_sha256` are deliberately excluded.

Responses use schema `java-analysis-response-v1`, status `complete`, `partial`,
`failed`, or `cancelled`, and identity:

```json
{"product":"binaryscan-java-checker","version":"0.1.0","ruleset":"java-rules-v1"}
```

Coverage obeys `files_parsed + files_failed = files_total`,
`files_recovered <= files_parsed`, and `files_analyzed <= files_parsed`.
Findings carry file, callable, source range, and at most 1,024 UTF-8 bytes of
source context. `DELETE /internal/v1/analyses/{analysis_id}` is idempotent and
returns 204. Readiness and liveness are exposed through Spring Actuator.

## Fixed ruleset

| Rule ID | CWE | Severity |
|---|---:|---:|
| `java-weak-message-digest` | CWE-328 | MEDIUM |
| `java-weak-cipher` | CWE-327 | MEDIUM |
| `java-legacy-tls` | CWE-326 | MEDIUM |
| `java-hardcoded-crypto-key` | CWE-321 | HIGH |
| `java-trust-all-hostname-verifier` | CWE-295 | HIGH |
| `java-trust-all-x509-manager` | CWE-295 | HIGH |
| `java-xxe-enabled` | CWE-611 | HIGH |
| `java-unsafe-deserialization` | CWE-502 | HIGH |
| `java-sql-injection` | CWE-89 | HIGH |
| `java-command-injection` | CWE-78 | HIGH |
| `java-dynamic-code-execution` | CWE-94 | HIGH |
| `java-overly-permissive-file` | CWE-732 | MEDIUM |
| `java-insecure-cookie` | CWE-614 | MEDIUM |

SQL, command, and dynamic-code checks follow parameters, local declarations,
assignments, aliases, and string concatenation inside one callable. There is no
cross-class call graph or project classpath resolution.

## Isolation and limits

Spring owns HTTP and starts a short-lived worker JVM for each accepted analysis.
Timeout and DELETE first request normal termination, wait two seconds, then use
forcible process termination. One heavy analysis runs at a time. The single
analysis admission is reserved before the multipart source is copied into heap,
so busy requests receive 429 without a second large source allocation.

Defaults are 3,000 files, 128 MiB per bundle, 8 MiB per analyzed file, 10
minutes, 10,000 findings, 1,000 diagnostics, and a 32 MiB response. The runtime
image runs as UID/GID 10001, needs only a writable `/tmp` (suitable for tmpfs),
and supports a read-only root filesystem with no outbound network access.
The HTTP parent JVM is capped at 384 MiB. It removes inherited Java option
environment variables before starting each worker, whose heap is explicitly
capped at 1,024 MiB; deployment should therefore provide at least 1.5 GiB of
container memory (2 GiB recommended) and a bounded `/tmp` tmpfs.
