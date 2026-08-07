package sampleexport

import (
	"io"
	"os"
)

const DownloadFilename = "binaryscan-sample.bin"

type BlobDescriptor struct {
	ID                  uint64
	TaskBlobID          uint64
	UploadBlobID        *uint64
	StorageKey          string
	SHA256              string
	SizeBytes           uint64
	State               string
	ReferenceCount      uint64
	UploadStatus        string
	UploadSHA256        string
	UploadDeclaredBytes uint64
}

type ReadSeekCloser interface {
	io.Reader
	io.Seeker
	io.Closer
}

type Download struct {
	Content   ReadSeekCloser
	SizeBytes uint64
	SHA256    string
	Filename  string
}

func closeFile(file *os.File) {
	if file != nil {
		_ = file.Close()
	}
}
