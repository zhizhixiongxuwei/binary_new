package ghidra

import (
	"os"
	"strings"
	"testing"
)

func TestExportScriptMatchesGoIndexAndFailureContract(t *testing.T) {
	raw, err := os.ReadFile(
		"../../analyzers/ghidra/ExportDecompiledFunctions.java",
	)
	if err != nil {
		t.Fatal(err)
	}
	script := string(raw)
	required := []string{
		"INDEX_SCHEMA_VERSION = 3",
		"FUNCTION_TIMEOUT_SECONDS = 60",
		"args.length != 8",
		"getExternalEntryPointIterator()",
		"currentProgram.getMemory().getBlocks()",
		"getCalledFunctions(monitor)",
		`{\"schema_version\":`,
		`\"entry_points\":[`,
		`\"segments\":[`,
		`\"functions\":[`,
		`\"call_edges\":[`,
		`\"completeness\":\"`,
		`decompiled.partial ? "partial" : "complete"`,
		`\"candidate_function_count\":`,
		`\"decompiled_function_count\":`,
		"BINARYSCAN_GHIDRA_ERROR=",
		"unsupported_architecture",
		"unsupported_instruction",
		"decompile_incomplete",
		"script_limit",
		"StandardCopyOption.ATOMIC_MOVE",
		"Files.size(staging) > maxIndexBytes",
	}
	for _, value := range required {
		if !strings.Contains(script, value) {
			t.Errorf("export script is missing contract token %q", value)
		}
	}
	forbidden := []string{
		"Runtime.getRuntime().exec",
		"ProcessBuilder",
		"new FileOutputStream",
	}
	for _, value := range forbidden {
		if strings.Contains(script, value) {
			t.Errorf("export script contains forbidden process/path API %q", value)
		}
	}
}

func TestExportScriptKeepsBoundedCollectionsAsPartialResults(t *testing.T) {
	raw, err := os.ReadFile(
		"../../analyzers/ghidra/ExportDecompiledFunctions.java",
	)
	if err != nil {
		t.Fatal(err)
	}
	script := string(raw)
	for _, removedFailure := range []string{
		`fail("script_limit", "entry point limit exceeded")`,
		`fail("script_limit", "segment limit exceeded")`,
		`fail("script_limit", "call edge limit exceeded")`,
	} {
		if strings.Contains(script, removedFailure) {
			t.Errorf("export script still rejects a safely bounded result %q", removedFailure)
		}
	}
	for _, boundedPartial := range []string{
		"candidates.size() < maxFunctions",
		"source.length > maxOutputBytes - total",
		"summary.partial = partial || result.size() < candidateCount",
		"result.entries.size() >= limit",
		"retainedCallEdges.size() / 2",
		"decompiled.partial = decompiled.partial || entryPoints.partial",
		"printProgressIfNeeded(",
		"none of the discovered functions could be decompiled",
		`fail("script_limit", "index byte limit exceeded")`,
	} {
		if !strings.Contains(script, boundedPartial) {
			t.Errorf("export script is missing bounded partial behavior %q", boundedPartial)
		}
	}
}
