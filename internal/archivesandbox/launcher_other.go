//go:build !linux

package archivesandbox

import (
	"errors"
	"os"
	"os/exec"
)

const toolLauncherMode = "__binaryscan_archive_tool_launcher_v1"

// MaybeRunToolLauncher is deliberately unavailable outside Linux. The local
// development server keeps the existing descriptor-based execution path, but
// production scanner images are Linux-only and always use launcher_linux.go.
func MaybeRunToolLauncher(arguments []string) (bool, error) {
	if len(arguments) < 2 || arguments[1] != toolLauncherMode {
		return false, nil
	}
	return true, errors.New("archive tool confinement requires Linux")
}

func (server *Server) buildToolCommand(
	identity executableIdentity,
	arguments []string,
	_ Request,
	input, output, run *os.File,
) (*exec.Cmd, func(), error) {
	command := exec.Command(identity.path, arguments...)
	command.ExtraFiles = []*os.File{input}
	if output != nil {
		command.ExtraFiles = append(command.ExtraFiles, output)
	}
	command.ExtraFiles = append(command.ExtraFiles, run)
	return command, func() {}, nil
}
