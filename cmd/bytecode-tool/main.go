package main

import (
	"fmt"
	"os"
	"path/filepath"
	"syscall"
)

const (
	javaExecutable = "/opt/java/openjdk/bin/java"
	vineflowerJar  = "/opt/bytecode-tools/vineflower/vineflower.jar"
	cfrJar         = "/opt/bytecode-tools/cfr/cfr.jar"
	jadxJar        = "/opt/bytecode-tools/jadx/lib/jadx-all.jar"
)

func main() {
	if len(os.Args) != 4 {
		fail("usage: binaryscan-bytecode-tool vineflower|cfr|jadx INPUT OUTPUT")
	}
	mode, input, output := os.Args[1], os.Args[2], os.Args[3]
	if !safeLocalPath(input) || !safeLocalPath(output) || input == output {
		fail("input and output must be distinct local paths")
	}
	inputInfo, err := os.Lstat(input)
	if err != nil || !inputInfo.Mode().IsRegular() || inputInfo.Mode()&os.ModeSymlink != 0 {
		fail("input is not a regular file")
	}
	outputInfo, err := os.Lstat(output)
	if err != nil || !outputInfo.IsDir() || outputInfo.Mode()&os.ModeSymlink != 0 {
		fail("output is not a directory")
	}

	arguments := []string{"java", "-Xms128m", "-Xmx3g", "-XX:MaxMetaspaceSize=512m", "-XX:+ExitOnOutOfMemoryError"}
	switch mode {
	case "vineflower":
		arguments = append(arguments,
			"-jar", vineflowerJar, "--silent", "--folder",
			input, output,
		)
	case "cfr":
		arguments = append(arguments,
			"-jar", cfrJar, input, "--outputdir", output, "--silent", "true",
		)
	case "jadx":
		arguments = append(arguments,
			"-cp", jadxJar, "jadx.cli.JadxCLI", "--output-dir", output,
			"--no-res", "--threads-count", "2", input,
		)
	default:
		fail("unsupported bytecode tool mode")
	}
	if err := syscall.Exec(javaExecutable, arguments, os.Environ()); err != nil {
		fail("execute Java runtime: " + err.Error())
	}
}

func safeLocalPath(value string) bool {
	return value != "" && value != "." && !filepath.IsAbs(value) &&
		filepath.Clean(value) == value && filepath.IsLocal(value)
}

func fail(message string) {
	_, _ = fmt.Fprintln(os.Stderr, message)
	os.Exit(2)
}
