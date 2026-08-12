# BinaryScan C Checker notices

The ANTLR C grammar in
`src/main/antlr4/com/binaryscan/cchecker/grammar/C.g4` is vendored from
`antlr/grammars-v4` commit `82740f3f1031d56a1141ffa48ac098aff6644f81`
(2025-04-13). The grammar's BSD license and copyright notice are retained
verbatim at the top of that file and in
`vendor/antlr-grammars-v4/LICENSE-C-GRAMMAR.txt`.

The grammar is compiled at build time and used entirely in-process. The
checker has no runtime license gate, telemetry, dependency download, or
other outbound network behavior.
