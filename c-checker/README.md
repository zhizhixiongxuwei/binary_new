# BinaryScan C Checker

Internal Spring Boot service that parses each supplied Ghidra pseudo-C
function with a pinned ANTLR4 C grammar and applies the fixed v1 ruleset.

Build and test:

```sh
mvn test
mvn -DskipTests package
```

The API is `POST /internal/v1/analyses/{analysis_id}` with multipart parts
named `metadata` and `source`. Cancellation is an idempotent `DELETE` to the
same path. Health probes are available at `/actuator/health/liveness` and
`/actuator/health/readiness`.
