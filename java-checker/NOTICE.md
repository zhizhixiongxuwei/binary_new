# BinaryScan Java Checker notices

This component uses JavaParser Core 3.28.2 to parse Java source into an AST.
JavaParser is Copyright (C) Federico Tomassetti and JavaParser contributors
and is distributed under the Apache License, Version 2.0.

Spring Boot and its transitive runtime libraries retain their respective
upstream copyright and license terms. Maven's generated dependency metadata in
the application archive identifies the exact artifacts and versions.

The checker uses `javaparser-core` only. It does not include JavaParser Symbol
Solver, resolve a project classpath, download dependencies at runtime, perform
telemetry, enforce a runtime license gate, or make outbound network requests.
