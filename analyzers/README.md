# Analyzer adapters

BinaryScan keeps tool-specific code behind bounded adapters and places the
large executables in dedicated external images.

- `ghidra/ExportDecompiledFunctions.java` is the Ghidra exporter copied into
  the final `ghidra` image. The Go adapter validates invocation, version,
  runtime identity, output bounds, and every returned artifact.
- `internal/analyzers/trivy` invokes a fixed local Trivy executable with all
  update and network behavior disabled. Database identity comes from the
  immutable dual-database Bundle in the `scanner` image.
- `internal/bytecode` routes JVM archives and Android bytecode through the
  fixed Vineflower/CFR/JADX toolchain when present, with pure-Go bytecode/PYC
  fallback for supported formats.

No Dockerfile downloads tools. External images must already be loaded before
the source build begins, and every product build runs with `--network=none`.
The runtime uses argument arrays without a shell, sanitized environments,
bounded diagnostics, process-group termination, task-local workspaces, and
read-only tool layers.
