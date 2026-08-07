// Package imageextract defines the bounded orchestration contract for reading
// disk images and filesystems without attaching them to the host.
//
// Extractors receive only an io.ReaderAt-compatible, size-confined source. The
// package has no API for host mount operations, loop devices, writable block
// devices, executable paths, command strings, or shell evaluation. Native Go
// extractors should parse the supplied reader directly. A future adapter for a
// reviewed external read-only utility must use Runner, whose tool enum exposes
// only the separately dispatched mmls and fls capabilities and whose arguments
// remain an array from caller to backend.
//
// Engine owns result collection. It validates the entry graph and partition
// ranges while enforcing shared input-byte, cumulative-read, expanded-byte,
// extent, entry, partition, depth, and context limits. File content is exposed
// only as validated, non-overlapping source extents. An Extractor must return
// immediately after Sink reports an error and must observe the context supplied
// to Extract.
package imageextract
