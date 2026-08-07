// Package bytecode defines the engine-neutral contract for managed-code
// decompilation and a pure-Go JVM bytecode-only fallback for CLASS and CLASS
// entries in JAR, WAR, and EAR archives. WAR and EAR traversal follows nested
// JAR, WAR, and EAR modules with one shared entry, expanded-byte, compression,
// and ten-level depth budget. Malformed nested modules become failed module
// indexes in a partial result, while a shared hard-limit violation aborts with
// ErrJVMArchiveLimit. Nested class payloads are streamed through private,
// unlinked workspace files rather than retained without bound in memory. The
// fallback never claims to reconstruct Java source. Third-party source
// decompilers such as Vineflower, CFR, JADX, and pycdc remain separate
// integrations. Engines must publish bounded metadata and actual artifacts
// that an independent validator verifies before a successful result is
// accepted.
package bytecode
