package extract

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"encoding/json"
	"os"
	"path"
	"strings"
	"testing"
)

func TestNamespaceCollisionEntriesAreRemappedAndRecursed(t *testing.T) {
	nestedZIP := zipFixture(t, []zipEntry{{
		name: "payload.txt",
		body: []byte("visible"),
	}})
	for _, archiveFormat := range []string{"zip", "tar", "cpio"} {
		for _, blockerType := range []string{NodeTypeFile, NodeTypeSymlink} {
			t.Run(archiveFormat+"/"+blockerType, func(t *testing.T) {
				inner := namespaceCollisionFixture(
					t,
					archiveFormat,
					blockerType,
					nestedZIP,
				)
				containerName := "container." + archiveFormat
				outer := zipFixture(t, []zipEntry{{
					name:  containerName,
					body:  inner,
					store: true,
				}})

				result := runExtract(t, outer, "zip", generousLimits())
				prefix := "/" + containerName
				container := findNode(t, result.Nodes, prefix)
				blocker := findNode(t, result.Nodes, prefix+"/a")
				collision := findNodeWithCode(
					t,
					result.Nodes,
					"namespace_collision",
				)

				if !result.Partial ||
					result.LimitCode != "" ||
					container.Format != archiveFormat ||
					blocker.NodeType != blockerType ||
					collision.ParentLocalID != container.LocalID ||
					collision.NodeType != NodeTypeFile ||
					collision.ExtractionStatus != StatusInvalidPath ||
					collision.Format != "zip" ||
					!strings.HasPrefix(
						collision.LogicalPath,
						prefix+"/__namespace_collision_entry_",
					) {
					t.Fatalf(
						"result=%+v container=%+v blocker=%+v collision=%+v",
						result,
						container,
						blocker,
						collision,
					)
				}

				var metadata map[string]any
				if err := json.Unmarshal(collision.MetadataJSON, &metadata); err != nil {
					t.Fatal(err)
				}
				if metadata["archive_path"] != "a/hidden.zip" ||
					metadata["duplicate_logical_path"] !=
						prefix+"/a/hidden.zip" ||
					metadata["namespace_collision_path"] != prefix+"/a" {
					t.Fatalf("collision metadata = %+v", metadata)
				}

				payload := findNode(
					t,
					result.Nodes,
					collision.LogicalPath+"/payload.txt",
				)
				if payload.ParentLocalID != collision.LocalID ||
					payload.ExtractionStatus != StatusExtracted {
					t.Fatalf(
						"collision=%+v payload=%+v",
						collision,
						payload,
					)
				}
				assertCleanWorkDirectory(t)
			})
		}
	}
}

func TestNamespaceCollisionNearMaxPrefixMovesToSafeAncestor(t *testing.T) {
	nestedZIP := zipFixture(t, []zipEntry{{
		name: "payload.txt",
		body: []byte("visible"),
	}})
	containerPath := nearMaxArchivePath("c")
	prefix := "/" + containerPath
	for _, archiveFormat := range []string{"zip", "tar", "cpio"} {
		t.Run(archiveFormat, func(t *testing.T) {
			inner := namespaceCollisionFixture(
				t,
				archiveFormat,
				NodeTypeFile,
				nestedZIP,
			)
			outer := zipFixture(t, []zipEntry{{
				name:  containerPath,
				body:  inner,
				store: true,
			}})

			result := runExtract(t, outer, "zip", generousLimits())
			container := findNode(t, result.Nodes, prefix)
			blocker := findNode(t, result.Nodes, prefix+"/a")
			collision := findNodeWithCode(
				t,
				result.Nodes,
				"namespace_collision",
			)
			parent := nodeWithLocalID(
				t,
				result.Nodes,
				collision.ParentLocalID,
			)
			payload := findNode(
				t,
				result.Nodes,
				collision.LogicalPath+"/payload.txt",
			)
			if !result.Partial ||
				result.LimitCode != "" ||
				container.Format != archiveFormat ||
				blocker.ParentLocalID != container.LocalID ||
				collision.ParentLocalID == container.LocalID ||
				len(collision.LogicalPath) > maxLogicalPathBytes ||
				collision.Depth != parent.Depth+1 ||
				!strings.HasPrefix(
					collision.LogicalPath,
					parent.LogicalPath+"/",
				) ||
				payload.ParentLocalID != collision.LocalID ||
				payload.Depth != collision.Depth+1 ||
				payload.ExtractionStatus != StatusExtracted {
				t.Fatalf(
					"result=%+v container=%+v blocker=%+v collision=%+v parent=%+v payload=%+v",
					result,
					container,
					blocker,
					collision,
					parent,
					payload,
				)
			}
			var metadata map[string]any
			if err := json.Unmarshal(
				collision.MetadataJSON,
				&metadata,
			); err != nil {
				t.Fatal(err)
			}
			if metadata["archive_container_path"] != prefix ||
				metadata["duplicate_logical_path"] !=
					prefix+"/a/hidden.zip" ||
				metadata["namespace_collision_path"] != prefix+"/a" {
				t.Fatalf("collision metadata = %+v", metadata)
			}
		})
	}
}

func TestReservedCollisionDirectoryCannotBeClaimed(t *testing.T) {
	nestedZIP := zipFixture(t, []zipEntry{{
		name: "payload.txt",
		body: []byte("visible"),
	}})
	const reservedName = "__namespace_collision_entry_2"
	data := zipFixture(t, []zipEntry{
		{name: "a", body: []byte("occupied")},
		{name: "a/b/", mode: os.ModeDir | 0o755},
		{name: reservedName + "/", mode: os.ModeDir | 0o755},
		{name: reservedName + "/hidden.zip", body: nestedZIP},
	})

	result := runExtract(t, data, "zip", generousLimits())
	collisions := make(map[string]Node)
	for _, node := range result.Nodes {
		if node.ErrorCode != "namespace_collision" {
			continue
		}
		var metadata map[string]any
		if err := json.Unmarshal(node.MetadataJSON, &metadata); err != nil {
			t.Fatal(err)
		}
		archivePath, _ := metadata["archive_path"].(string)
		collisions[archivePath] = node
	}
	original, originalOK := collisions["a/b/"]
	explicit, explicitOK := collisions[reservedName+"/"]
	child, childOK := collisions[reservedName+"/hidden.zip"]
	if !result.Partial ||
		len(collisions) != 3 ||
		!originalOK ||
		!explicitOK ||
		!childOK ||
		original.NodeType != NodeTypeDirectory ||
		explicit.NodeType != NodeTypeDirectory ||
		child.NodeType != NodeTypeFile ||
		child.Format != "zip" ||
		original.LogicalPath == explicit.LogicalPath ||
		original.LogicalPath == child.LogicalPath ||
		child.ParentLocalID == original.LocalID {
		t.Fatalf(
			"result=%+v collisions=%+v",
			result,
			collisions,
		)
	}
	var originalMetadata map[string]any
	if err := json.Unmarshal(
		original.MetadataJSON,
		&originalMetadata,
	); err != nil {
		t.Fatal(err)
	}
	if originalMetadata["archive_path"] != "a/b/" ||
		originalMetadata["namespace_collision_path"] != "/a" {
		t.Fatalf("original collision metadata = %+v", originalMetadata)
	}
	payload := findNode(
		t,
		result.Nodes,
		child.LogicalPath+"/payload.txt",
	)
	if payload.ParentLocalID != child.LocalID ||
		payload.ExtractionStatus != StatusExtracted {
		t.Fatalf("child=%+v payload=%+v", child, payload)
	}
}

func TestRejectedPathNearMaxPrefixUsesSafeDiagnosticParent(t *testing.T) {
	inner := zipFixture(t, []zipEntry{{
		name: "../escape",
		body: []byte("hidden"),
	}})
	containerPath := nearMaxArchivePath("c")
	prefix := "/" + containerPath
	outer := zipFixture(t, []zipEntry{{
		name:  containerPath,
		body:  inner,
		store: true,
	}})

	result := runExtract(t, outer, "zip", generousLimits())
	container := findNode(t, result.Nodes, prefix)
	rejected := findNodeWithCode(
		t,
		result.Nodes,
		"invalid_archive_path",
	)
	parent := nodeWithLocalID(t, result.Nodes, rejected.ParentLocalID)
	if !result.Partial ||
		result.LimitCode != "" ||
		rejected.ParentLocalID == container.LocalID ||
		len(rejected.LogicalPath) > maxLogicalPathBytes ||
		rejected.Depth != parent.Depth+1 ||
		!strings.HasPrefix(rejected.LogicalPath, parent.LogicalPath+"/") {
		t.Fatalf(
			"result=%+v container=%+v rejected=%+v parent=%+v",
			result,
			container,
			rejected,
			parent,
		)
	}
	var metadata map[string]any
	if err := json.Unmarshal(rejected.MetadataJSON, &metadata); err != nil {
		t.Fatal(err)
	}
	if metadata["archive_path"] != "../escape" ||
		metadata["archive_container_path"] != prefix {
		t.Fatalf("rejected metadata = %+v", metadata)
	}
}

func TestUnsafeArchivePathsAreQuarantinedAndRecursed(t *testing.T) {
	nestedZIP := zipFixture(t, []zipEntry{{
		name: "payload.txt",
		body: []byte("visible"),
	}})
	for _, archiveFormat := range []string{
		"zip",
		"tar",
		"cpio",
		"ar",
		"gzip",
	} {
		t.Run(archiveFormat, func(t *testing.T) {
			data := singleRegularArchiveFixture(
				t,
				archiveFormat,
				"../hidden.zip",
				nestedZIP,
			)
			result := runExtract(
				t,
				data,
				archiveFormat,
				generousLimits(),
			)
			assertQuarantinedNestedZIP(
				t,
				result,
				"../hidden.zip",
				"",
				"unsafe_archive_path",
			)
		})
	}
}

func TestLogicalPathOverflowIsQuarantinedAndRecursed(t *testing.T) {
	nestedZIP := zipFixture(t, []zipEntry{{
		name: "payload.txt",
		body: []byte("visible"),
	}})
	archivePath := exactMaxArchivePath()
	if len(archivePath) != maxLogicalPathBytes {
		t.Fatalf("fixture path length = %d", len(archivePath))
	}
	for _, archiveFormat := range []string{
		"zip",
		"tar",
		"cpio",
		"ar",
	} {
		t.Run(archiveFormat, func(t *testing.T) {
			data := singleRegularArchiveFixture(
				t,
				archiveFormat,
				archivePath,
				nestedZIP,
			)
			result := runExtract(
				t,
				data,
				archiveFormat,
				generousLimits(),
			)
			assertQuarantinedNestedZIP(
				t,
				result,
				archivePath,
				"",
				"logical_path_overflow",
			)
		})
	}
}

func TestLogicalPathOverflowUnderLongPrefixStillRecurses(t *testing.T) {
	nestedZIP := zipFixture(t, []zipEntry{{
		name: "payload.txt",
		body: []byte("visible"),
	}})
	containerPath := maxLogicalContainerPath()
	prefix := "/" + containerPath
	if len(prefix) != maxLogicalPathBytes {
		t.Fatalf("fixture prefix length = %d", len(prefix))
	}
	for _, archiveFormat := range []string{
		"zip",
		"tar",
		"cpio",
		"ar",
		"gzip",
	} {
		t.Run(archiveFormat, func(t *testing.T) {
			inner := singleRegularArchiveFixture(
				t,
				archiveFormat,
				"hidden.zip",
				nestedZIP,
			)
			outer := zipFixture(t, []zipEntry{{
				name:  containerPath,
				body:  inner,
				store: true,
			}})
			result := runExtract(t, outer, "zip", generousLimits())
			container := findNode(t, result.Nodes, prefix)
			if container.Format != archiveFormat {
				t.Fatalf(
					"container format = %q, want %q",
					container.Format,
					archiveFormat,
				)
			}
			assertQuarantinedNestedZIP(
				t,
				result,
				"hidden.zip",
				prefix,
				"logical_path_overflow",
			)
		})
	}
}

func TestQuarantinedNestedPayloadHonorsDepthAndNodeLimits(t *testing.T) {
	nestedZIP := zipFixture(t, []zipEntry{{
		name: "payload.txt",
		body: []byte("must-not-appear"),
	}})
	data := zipFixture(t, []zipEntry{{
		name: "../hidden.zip",
		body: nestedZIP,
	}})
	for _, test := range []struct {
		name       string
		limits     Limits
		limitCode  string
		nodeStatus string
	}{
		{
			name: "depth",
			limits: Limits{
				MaxExpandedBytes: 32 << 20,
				MaxNodes:         1000,
				MaxDepth:         1,
				MaxRatio:         100,
			},
			limitCode:  LimitMaxDepth,
			nodeStatus: StatusDepthLimited,
		},
		{
			name: "nodes",
			limits: Limits{
				MaxExpandedBytes: 32 << 20,
				MaxNodes:         1,
				MaxDepth:         10,
				MaxRatio:         100,
			},
			limitCode:  LimitMaxNodes,
			nodeStatus: StatusLimitExceeded,
		},
	} {
		t.Run(test.name, func(t *testing.T) {
			result := runExtract(t, data, "zip", test.limits)
			if !result.Partial ||
				result.LimitCode != test.limitCode ||
				len(result.Nodes) != 1 ||
				result.Nodes[0].ExtractionStatus != test.nodeStatus ||
				result.Nodes[0].ErrorCode != test.limitCode {
				t.Fatalf("result = %+v", result)
			}
			var metadata map[string]any
			if err := json.Unmarshal(
				result.Nodes[0].MetadataJSON,
				&metadata,
			); err != nil {
				t.Fatal(err)
			}
			if metadata["archive_path"] != "../hidden.zip" ||
				metadata["reason"] != "unsafe_archive_path" {
				t.Fatalf("metadata = %+v", metadata)
			}
		})
	}
}

func assertQuarantinedNestedZIP(
	t *testing.T,
	result Result,
	archivePath string,
	containerPath string,
	reason string,
) {
	t.Helper()
	quarantined := findNodeWithCode(
		t,
		result.Nodes,
		"invalid_archive_path",
	)
	payload := findNode(
		t,
		result.Nodes,
		quarantined.LogicalPath+"/payload.txt",
	)
	if !result.Partial ||
		result.LimitCode != "" ||
		quarantined.ExtractionStatus != StatusInvalidPath ||
		quarantined.NodeType != NodeTypeFile ||
		quarantined.Format != "zip" ||
		path.Clean(quarantined.LogicalPath) != quarantined.LogicalPath ||
		strings.Contains(quarantined.LogicalPath, "..") ||
		len(quarantined.LogicalPath) > maxLogicalPathBytes ||
		payload.ParentLocalID != quarantined.LocalID ||
		payload.ExtractionStatus != StatusExtracted {
		t.Fatalf(
			"result=%+v quarantined=%+v payload=%+v",
			result,
			quarantined,
			payload,
		)
	}
	var metadata map[string]any
	if err := json.Unmarshal(quarantined.MetadataJSON, &metadata); err != nil {
		t.Fatal(err)
	}
	if metadata["archive_path"] != archivePath ||
		metadata["archive_path_truncated"] != false ||
		metadata["reason"] != reason {
		t.Fatalf("quarantine metadata = %+v", metadata)
	}
	if containerPath == "" {
		if _, present := metadata["archive_container_path"]; present {
			t.Fatalf("unexpected container path metadata = %+v", metadata)
		}
	} else if metadata["archive_container_path"] != containerPath {
		t.Fatalf("quarantine metadata = %+v", metadata)
	}
}

func singleRegularArchiveFixture(
	t *testing.T,
	archiveFormat string,
	name string,
	body []byte,
) []byte {
	t.Helper()
	switch archiveFormat {
	case "zip":
		return zipFixture(t, []zipEntry{{name: name, body: body}})
	case "tar":
		var output bytes.Buffer
		writer := tar.NewWriter(&output)
		if err := writer.WriteHeader(&tar.Header{
			Name:     name,
			Typeflag: tar.TypeReg,
			Mode:     0o600,
			Size:     int64(len(body)),
		}); err != nil {
			t.Fatal(err)
		}
		if _, err := writer.Write(body); err != nil {
			t.Fatal(err)
		}
		if err := writer.Close(); err != nil {
			t.Fatal(err)
		}
		return append([]byte(nil), output.Bytes()...)
	case "cpio":
		return cpioArchiveFixture(t, "newc", []cpioFixtureEntry{{
			name: name,
			mode: cpioModeRegular | 0o600,
			body: body,
		}}, true)
	case "ar":
		return arArchiveFixture(t, []arFixtureEntry{
			arBSDEntry(name, body),
		})
	case "gzip":
		var output bytes.Buffer
		writer := gzip.NewWriter(&output)
		writer.Name = name
		if _, err := writer.Write(body); err != nil {
			t.Fatal(err)
		}
		if err := writer.Close(); err != nil {
			t.Fatal(err)
		}
		return append([]byte(nil), output.Bytes()...)
	default:
		t.Fatalf("unsupported fixture format %q", archiveFormat)
		return nil
	}
}

func exactMaxArchivePath() string {
	parts := make([]string, 9)
	for index := 0; index < 7; index++ {
		parts[index] = strings.Repeat("a", maxPathPartBytes)
	}
	parts[7] = strings.Repeat("b", maxPathPartBytes-1)
	parts[8] = "c"
	return strings.Join(parts, "/")
}

func maxLogicalContainerPath() string {
	parts := make([]string, 8)
	for index := range parts {
		parts[index] = strings.Repeat("c", maxPathPartBytes)
	}
	return strings.Join(parts, "/")
}

func TestQuarantineReparentingDoesNotResetScanDepth(t *testing.T) {
	parentParts := make([]string, 8)
	for index := range parentParts {
		parentParts[index] = strings.Repeat("p", 253)
	}
	parentParts[len(parentParts)-1] = strings.Repeat("p", 241)
	parentPath := strings.Join(parentParts, "/")
	containerPath := parentPath + "/aaaaaaa"
	if len("/"+parentPath) != 2020 ||
		len("/"+containerPath) != 2028 {
		t.Fatalf(
			"fixture lengths: parent=%d container=%d",
			len("/"+parentPath),
			len("/"+containerPath),
		)
	}

	nested := zipFixture(t, []zipEntry{{
		name: "bottom.txt",
		body: []byte("must-not-appear"),
	}})
	for range 15 {
		nested = arArchiveFixture(t, []arFixtureEntry{
			{rawName: "x/", body: []byte("occupied")},
			{rawName: "x/", body: nested},
		})
	}
	root := zipFixture(t, []zipEntry{{
		name:  containerPath,
		body:  nested,
		store: true,
	}})

	result := runExtract(t, root, "zip", generousLimits())
	depthLimited := 0
	for _, node := range result.Nodes {
		if node.DisplayName == "bottom.txt" {
			t.Fatalf("depth-limited payload became visible: %+v", result)
		}
		if node.ErrorCode == LimitMaxDepth {
			depthLimited++
			if node.ExtractionStatus != StatusDepthLimited ||
				node.Format != "ar" {
				t.Fatalf("depth-limited node = %+v", node)
			}
		}
	}
	if !result.Partial ||
		result.LimitCode != LimitMaxDepth ||
		depthLimited != 1 {
		t.Fatalf(
			"result=%+v depth_limited=%d",
			result,
			depthLimited,
		)
	}
}

func namespaceCollisionFixture(
	t *testing.T,
	archiveFormat string,
	blockerType string,
	nestedZIP []byte,
) []byte {
	t.Helper()
	switch archiveFormat {
	case "zip":
		blocker := zipEntry{name: "a", body: []byte("occupied")}
		if blockerType == NodeTypeSymlink {
			blocker.mode = os.ModeSymlink | 0o777
			blocker.body = []byte("target")
		}
		return zipFixture(t, []zipEntry{
			blocker,
			{name: "a/hidden.zip", body: nestedZIP},
		})
	case "tar":
		return tarNamespaceCollisionFixture(t, blockerType, nestedZIP)
	case "cpio":
		mode := cpioModeRegular | 0o600
		body := []byte("occupied")
		if blockerType == NodeTypeSymlink {
			mode = cpioModeSymlink | 0o777
			body = []byte("target")
		}
		return cpioArchiveFixture(t, "newc", []cpioFixtureEntry{
			{name: "a", mode: mode, body: body},
			{
				name: "a/hidden.zip",
				mode: cpioModeRegular | 0o600,
				body: nestedZIP,
			},
		}, true)
	default:
		t.Fatalf("unsupported fixture format %q", archiveFormat)
		return nil
	}
}

func tarNamespaceCollisionFixture(
	t *testing.T,
	blockerType string,
	nestedZIP []byte,
) []byte {
	t.Helper()
	var output bytes.Buffer
	writer := tar.NewWriter(&output)
	blocker := &tar.Header{
		Name:     "a",
		Typeflag: tar.TypeReg,
		Mode:     0o600,
		Size:     int64(len("occupied")),
	}
	blockerBody := []byte("occupied")
	if blockerType == NodeTypeSymlink {
		blocker.Typeflag = tar.TypeSymlink
		blocker.Mode = 0o777
		blocker.Size = 0
		blocker.Linkname = "target"
		blockerBody = nil
	}
	if err := writer.WriteHeader(blocker); err != nil {
		t.Fatal(err)
	}
	if _, err := writer.Write(blockerBody); err != nil {
		t.Fatal(err)
	}
	if err := writer.WriteHeader(&tar.Header{
		Name:     "a/hidden.zip",
		Typeflag: tar.TypeReg,
		Mode:     0o600,
		Size:     int64(len(nestedZIP)),
	}); err != nil {
		t.Fatal(err)
	}
	if _, err := writer.Write(nestedZIP); err != nil {
		t.Fatal(err)
	}
	if err := writer.Close(); err != nil {
		t.Fatal(err)
	}
	return append([]byte(nil), output.Bytes()...)
}

func nearMaxArchivePath(leaf string) string {
	parts := make([]string, 8)
	for index := range parts {
		parts[index] = strings.Repeat("d", 253)
	}
	return strings.Join(parts, "/") + "/" + leaf
}

func nodeWithLocalID(t *testing.T, nodes []Node, localID int) Node {
	t.Helper()
	for _, node := range nodes {
		if node.LocalID == localID {
			return node
		}
	}
	t.Fatalf("node with local ID %d not found in %+v", localID, nodes)
	return Node{}
}

func findNodeWithCode(t *testing.T, nodes []Node, code string) Node {
	t.Helper()
	var found *Node
	for index := range nodes {
		if nodes[index].ErrorCode != code {
			continue
		}
		if found != nil {
			t.Fatalf("multiple nodes with code %q: %+v", code, nodes)
		}
		found = &nodes[index]
	}
	if found == nil {
		t.Fatalf("node with code %q not found in %+v", code, nodes)
	}
	return *found
}
