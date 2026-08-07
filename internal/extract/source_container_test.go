package extract

import "testing"

func TestNestedEntriesRetainConcreteSourceContainer(t *testing.T) {
	innerTAR := regularNamesFixture(
		t,
		"tar",
		[]string{"layers/deep/file.bin", "../escape.bin"},
	)
	outerZIP := zipFixture(t, []zipEntry{{
		name: "folder/inner.tar", body: innerTAR, store: true,
	}})

	result := runExtract(t, outerZIP, "zip", generousLimits())
	outerDirectory := findNode(t, result.Nodes, "/folder")
	inner := findNode(t, result.Nodes, "/folder/inner.tar")
	layerDirectory := findNode(
		t, result.Nodes, "/folder/inner.tar/layers",
	)
	deepDirectory := findNode(
		t, result.Nodes, "/folder/inner.tar/layers/deep",
	)
	payload := findNode(
		t, result.Nodes, "/folder/inner.tar/layers/deep/file.bin",
	)
	rejected := findNodeWithCode(
		t, result.Nodes, "invalid_archive_path",
	)

	if outerDirectory.SourceContainerLocalID != 0 ||
		inner.SourceContainerLocalID != 0 ||
		inner.Format != "tar" {
		t.Fatalf(
			"outer directory=%+v inner=%+v",
			outerDirectory,
			inner,
		)
	}
	for _, node := range []Node{
		layerDirectory, deepDirectory, payload, rejected,
	} {
		if node.SourceContainerLocalID != inner.LocalID {
			t.Fatalf(
				"node %q source=%d, want inner archive %d",
				node.LogicalPath,
				node.SourceContainerLocalID,
				inner.LocalID,
			)
		}
	}
}
