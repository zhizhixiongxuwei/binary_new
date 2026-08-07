package decompile

import (
	"context"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"

	"binaryscan/internal/bytecode"
	"binaryscan/internal/queue"

	"golang.org/x/sys/unix"
)

const (
	testCacheSourceTaskID = "823e4567-e89b-42d3-a456-426614174008"
	testCacheSourceRunID  = "923e4567-e89b-42d3-a456-426614174009"
	testCacheSourceResult = "a23e4567-e89b-42d3-a456-42661417400a"
)

func TestBytecodeProcessorReusesVerifiedCacheIntoPrivateResult(t *testing.T) {
	repositoryRoot, workRoot, _, lease := bytecodeProcessingFixture(t)
	source := []byte("public class Cached { void run() {} }\n")
	candidate := writeBytecodeCacheCandidate(t, repositoryRoot, source)
	repository := &fakeBytecodeRunRepository{
		cacheCandidate: candidate,
		cacheFound:     true,
	}
	analyzer := &fakeBytecodeAnalyzer{
		identity: bytecodeTestIdentity(),
		run: func(context.Context, bytecode.Request) (bytecode.Result, error) {
			t.Fatal("analyzer ran for a valid cache hit")
			return bytecode.Result{}, nil
		},
	}
	processor := newTestBytecodeProcessor(
		t, repository, analyzer, repositoryRoot, workRoot,
	)
	finish, err := processor.Process(context.Background(), lease)
	if err != nil || finish.Outcome != queue.OutcomeSucceeded {
		t.Fatalf("Process() = (%+v, %v)", finish, err)
	}
	if analyzer.calls != 0 || repository.cacheFindCalls != 1 ||
		repository.cachePublishCalls != 1 || repository.publishCalls != 0 ||
		len(repository.published) != 1 {
		t.Fatalf(
			"calls analyzer=%d find=%d cache-publish=%d publish=%d results=%d",
			analyzer.calls, repository.cacheFindCalls,
			repository.cachePublishCalls, repository.publishCalls,
			len(repository.published),
		)
	}
	published := repository.published[0]
	if published.ID == candidate.Results[0].ID ||
		published.StorageKey == candidate.Results[0].StorageKey ||
		published.SHA256 != candidate.Results[0].SHA256 ||
		published.SizeBytes != candidate.Results[0].SizeBytes {
		t.Fatalf("private cached result = %#v", published)
	}
	stored, readErr := os.ReadFile(filepath.Join(
		repositoryRoot, filepath.FromSlash(published.StorageKey),
	))
	if readErr != nil || string(stored) != string(source) {
		t.Fatalf("private cached source = %q, %v", stored, readErr)
	}
	if _, statErr := os.Stat(filepath.Join(
		repositoryRoot, filepath.FromSlash(candidate.Results[0].StorageKey),
	)); statErr != nil {
		t.Fatalf("source cache was moved or removed: %v", statErr)
	}
}

func TestBytecodeProcessorReplaysPublishedBytecodeOnlyOutcome(t *testing.T) {
	repositoryRoot, workRoot, _, lease := bytecodeProcessingFixture(t)
	repository := &fakeBytecodeRunRepository{beginErr: bytecodeAlreadyPublishedError{
		status: bytecode.StatusBytecodeOnly,
	}}
	analyzer := &fakeBytecodeAnalyzer{
		identity: bytecodeTestIdentity(),
		run: func(context.Context, bytecode.Request) (bytecode.Result, error) {
			t.Fatal("analyzer ran for an idempotent replay")
			return bytecode.Result{}, nil
		},
	}
	processor := newTestBytecodeProcessor(
		t, repository, analyzer, repositoryRoot, workRoot,
	)
	finish, err := processor.Process(context.Background(), lease)
	if err != nil || finish.Outcome != queue.OutcomePartialSucceeded ||
		analyzer.calls != 0 || repository.cacheFindCalls != 0 ||
		repository.publishCalls != 0 {
		t.Fatalf(
			"replay = (%+v, %v), analyzer=%d find=%d publish=%d",
			finish, err, analyzer.calls, repository.cacheFindCalls,
			repository.publishCalls,
		)
	}
}

func TestBytecodeProcessorFallsBackWhenCacheArtifactIsTampered(t *testing.T) {
	repositoryRoot, workRoot, _, lease := bytecodeProcessingFixture(t)
	candidate := writeBytecodeCacheCandidate(
		t, repositoryRoot, []byte("public class Cached {}\n"),
	)
	sourcePath := filepath.Join(
		repositoryRoot, filepath.FromSlash(candidate.Results[0].StorageKey),
	)
	if err := os.WriteFile(sourcePath, []byte("tampered\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	repository := &fakeBytecodeRunRepository{
		cacheCandidate: candidate,
		cacheFound:     true,
	}
	identity := bytecodeTestIdentity()
	analyzer := &fakeBytecodeAnalyzer{identity: identity}
	analyzer.run = func(
		_ context.Context,
		request bytecode.Request,
	) (bytecode.Result, error) {
		fresh := []byte("public class A {}\n")
		if err := os.WriteFile(
			filepath.Join(request.Workspace, "A.java"), fresh, 0o600,
		); err != nil {
			t.Fatal(err)
		}
		cacheKey, err := bytecode.CacheKey(
			request.Input.SHA256, request.Input.Format, identity.Engine,
			request.Arguments, request.Limits,
		)
		if err != nil {
			t.Fatal(err)
		}
		return completeBytecodeTestResult(request, identity, cacheKey, fresh), nil
	}
	processor := newTestBytecodeProcessor(
		t, repository, analyzer, repositoryRoot, workRoot,
	)
	finish, err := processor.Process(context.Background(), lease)
	if err != nil || finish.Outcome != queue.OutcomeSucceeded ||
		analyzer.calls != 1 || repository.cachePublishCalls != 0 ||
		repository.publishCalls != 1 {
		t.Fatalf(
			"fallback = (%+v, %v), analyzer=%d cache=%d publish=%d",
			finish, err, analyzer.calls, repository.cachePublishCalls,
			repository.publishCalls,
		)
	}
}

func TestBytecodeProcessorFallsBackAfterCacheCommitRace(t *testing.T) {
	repositoryRoot, workRoot, _, lease := bytecodeProcessingFixture(t)
	candidate := writeBytecodeCacheCandidate(
		t, repositoryRoot, []byte("public class Cached {}\n"),
	)
	repository := &fakeBytecodeRunRepository{
		cacheCandidate:  candidate,
		cacheFound:      true,
		cachePublishErr: errBytecodeCacheStale,
	}
	identity := bytecodeTestIdentity()
	analyzer := &fakeBytecodeAnalyzer{identity: identity}
	analyzer.run = func(
		_ context.Context,
		request bytecode.Request,
	) (bytecode.Result, error) {
		fresh := []byte("public class A {}\n")
		if err := os.WriteFile(
			filepath.Join(request.Workspace, "A.java"), fresh, 0o600,
		); err != nil {
			t.Fatal(err)
		}
		cacheKey, err := bytecode.CacheKey(
			request.Input.SHA256, request.Input.Format, identity.Engine,
			request.Arguments, request.Limits,
		)
		if err != nil {
			t.Fatal(err)
		}
		return completeBytecodeTestResult(request, identity, cacheKey, fresh), nil
	}
	processor := newTestBytecodeProcessor(
		t, repository, analyzer, repositoryRoot, workRoot,
	)
	finish, err := processor.Process(context.Background(), lease)
	if err != nil || finish.Outcome != queue.OutcomeSucceeded ||
		analyzer.calls != 1 || repository.cachePublishCalls != 1 ||
		repository.publishCalls != 1 {
		t.Fatalf(
			"commit-race fallback = (%+v, %v), analyzer=%d cache=%d publish=%d",
			finish, err, analyzer.calls, repository.cachePublishCalls,
			repository.publishCalls,
		)
	}
}

func TestBytecodeProcessorPreservesUnknownCacheCommitForRetry(t *testing.T) {
	repositoryRoot, workRoot, _, lease := bytecodeProcessingFixture(t)
	candidate := writeBytecodeCacheCandidate(
		t, repositoryRoot, []byte("public class Cached {}\n"),
	)
	repository := &fakeBytecodeRunRepository{
		cacheCandidate:  candidate,
		cacheFound:      true,
		cachePublishErr: errBytecodeCacheCommitUncertain,
	}
	analyzer := &fakeBytecodeAnalyzer{
		identity: bytecodeTestIdentity(),
		run: func(context.Context, bytecode.Request) (bytecode.Result, error) {
			t.Fatal("analyzer ran after an ambiguous cache commit")
			return bytecode.Result{}, nil
		},
	}
	processor := newTestBytecodeProcessor(
		t, repository, analyzer, repositoryRoot, workRoot,
	)
	finish, err := processor.Process(context.Background(), lease)
	if !errors.Is(err, errBytecodeCacheCommitUncertain) ||
		finish != (queue.FinishInput{}) || analyzer.calls != 0 ||
		repository.cachePublishCalls != 1 || repository.failCalls != 0 ||
		repository.publishCalls != 0 {
		t.Fatalf(
			"ambiguous cache commit = (%+v, %v), analyzer=%d cache=%d fail=%d publish=%d",
			finish, err, analyzer.calls, repository.cachePublishCalls,
			repository.failCalls, repository.publishCalls,
		)
	}
	resultID := bytecodeResultID(
		"623e4567-e89b-42d3-a456-426614174006",
		candidate.Results[0].SymbolKey,
	)
	privatePath := filepath.Join(
		repositoryRoot, "decompile", resultID, "source.java",
	)
	if stored, readErr := os.ReadFile(privatePath); readErr != nil ||
		string(stored) != "public class Cached {}\n" {
		t.Fatalf("ambiguous cache private copy = %q, %v", stored, readErr)
	}
}

func TestMaterializeBytecodeCacheSupportsConcurrentPrivateHits(t *testing.T) {
	repositoryRoot := t.TempDir()
	candidate := writeBytecodeCacheCandidate(
		t, repositoryRoot, []byte("public class Cached {}\n"),
	)
	processor := &BytecodeProcessor{config: BytecodeProcessorConfig{
		RepositoryRoot: repositoryRoot,
	}}
	runIDs := []string{
		"b23e4567-e89b-42d3-a456-42661417400b",
		"c23e4567-e89b-42d3-a456-42661417400c",
	}
	results := make([][]BytecodePublishedResult, len(runIDs))
	errorsByIndex := make([]error, len(runIDs))
	var wait sync.WaitGroup
	for index, runID := range runIDs {
		wait.Add(1)
		go func(index int, runID string) {
			defer wait.Done()
			values, _, err := processor.materializeBytecodeCache(
				context.Background(), runID, candidate, defaultJobLimits,
			)
			results[index], errorsByIndex[index] = values, err
		}(index, runID)
	}
	wait.Wait()
	for index, err := range errorsByIndex {
		if err != nil || len(results[index]) != 1 {
			t.Fatalf("hit %d = (%#v, %v)", index, results[index], err)
		}
	}
	if results[0][0].ID == results[1][0].ID ||
		results[0][0].StorageKey == results[1][0].StorageKey {
		t.Fatalf("concurrent hits shared identity: %#v", results)
	}
}

func TestMaterializeBytecodeCacheRejectsUnsafeSources(t *testing.T) {
	for _, test := range []struct {
		name   string
		mutate func(*testing.T, string, *BytecodeCacheCandidate)
	}{
		{
			name: "non utf8",
			mutate: func(t *testing.T, root string, value *BytecodeCacheCandidate) {
				content := []byte{0xff, 0xfe}
				writeCachedResultFile(t, root, value.Results[0].StorageKey, content)
				value.Results[0].SHA256 = digestBytes(content)
				value.Results[0].SizeBytes = uint64(len(content))
			},
		},
		{
			name: "symbolic link",
			mutate: func(t *testing.T, root string, value *BytecodeCacheCandidate) {
				target := filepath.Join(root, "outside.java")
				content := []byte("public class Outside {}\n")
				if err := os.WriteFile(target, content, 0o600); err != nil {
					t.Fatal(err)
				}
				path := filepath.Join(root, filepath.FromSlash(value.Results[0].StorageKey))
				if err := os.Remove(path); err != nil {
					t.Fatal(err)
				}
				if err := os.Symlink(target, path); err != nil {
					t.Fatal(err)
				}
				value.Results[0].SHA256 = digestBytes(content)
				value.Results[0].SizeBytes = uint64(len(content))
			},
		},
		{
			name: "hard link",
			mutate: func(t *testing.T, root string, value *BytecodeCacheCandidate) {
				filePath := filepath.Join(
					root, filepath.FromSlash(value.Results[0].StorageKey),
				)
				if err := os.Link(filePath, filePath+".alias"); err != nil {
					t.Fatal(err)
				}
			},
		},
		{
			name: "group readable file",
			mutate: func(t *testing.T, root string, value *BytecodeCacheCandidate) {
				filePath := filepath.Join(
					root, filepath.FromSlash(value.Results[0].StorageKey),
				)
				if err := os.Chmod(filePath, 0o640); err != nil {
					t.Fatal(err)
				}
			},
		},
		{
			name: "output limit",
			mutate: func(_ *testing.T, _ string, value *BytecodeCacheCandidate) {
				value.Results[0].SizeBytes = uint64(defaultJobLimits.MaxOutputBytes) + 1
			},
		},
	} {
		t.Run(test.name, func(t *testing.T) {
			repositoryRoot := t.TempDir()
			candidate := writeBytecodeCacheCandidate(
				t, repositoryRoot, []byte("public class Cached {}\n"),
			)
			test.mutate(t, repositoryRoot, &candidate)
			processor := &BytecodeProcessor{config: BytecodeProcessorConfig{
				RepositoryRoot: repositoryRoot,
			}}
			_, cleanup, err := processor.materializeBytecodeCache(
				context.Background(),
				"623e4567-e89b-42d3-a456-426614174006",
				candidate, defaultJobLimits,
			)
			cleanup()
			if !errors.Is(err, errBytecodeCacheInvalid) {
				t.Fatalf("materialize error = %v", err)
			}
		})
	}
}

func TestBytecodeCacheFileIdentityRejectsMetadataChanges(t *testing.T) {
	filePath := filepath.Join(t.TempDir(), "source.java")
	if err := os.WriteFile(filePath, []byte("class A {}\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	file, err := os.Open(filePath)
	if err != nil {
		t.Fatal(err)
	}
	defer file.Close()
	before, err := file.Stat()
	if err != nil {
		t.Fatal(err)
	}
	var beforeStat unix.Stat_t
	if err := unix.Fstat(int(file.Fd()), &beforeStat); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(filePath, 0o640); err != nil {
		t.Fatal(err)
	}
	after, err := file.Stat()
	if err != nil {
		t.Fatal(err)
	}
	var afterStat unix.Stat_t
	if err := unix.Fstat(int(file.Fd()), &afterStat); err != nil {
		t.Fatal(err)
	}
	if sameBytecodeCacheFileIdentity(before, beforeStat, after, afterStat) {
		t.Fatal("cache file identity accepted a permission change")
	}
}

func TestBytecodeReuseIdentityBindsInputEngineAndCanonicalParameters(
	t *testing.T,
) {
	_, _, payload, _ := bytecodeProcessingFixture(t)
	identity := bytecodeTestIdentity()
	parameters, err := bytecodeParameterCacheKey(payload, identity)
	if err != nil {
		t.Fatal(err)
	}
	baseline, err := bytecodeReuseIdentity(payload, identity, parameters)
	if err != nil || len(baseline) != 64 {
		t.Fatalf("reuse identity = %q, %v", baseline, err)
	}
	firstOptions, _ := canonicalOptions(json.RawMessage(`{"z":1,"a":{"y":2,"x":3}}`))
	secondOptions, _ := canonicalOptions(json.RawMessage(`{"a":{"x":3,"y":2},"z":1}`))
	firstPayload, secondPayload := payload, payload
	firstPayload.Options, secondPayload.Options = firstOptions, secondOptions
	firstParameters, _ := bytecodeParameterCacheKey(firstPayload, identity)
	secondParameters, _ := bytecodeParameterCacheKey(secondPayload, identity)
	firstReuse, _ := bytecodeReuseIdentity(firstPayload, identity, firstParameters)
	secondReuse, _ := bytecodeReuseIdentity(secondPayload, identity, secondParameters)
	if firstParameters != secondParameters || firstReuse != secondReuse {
		t.Fatalf(
			"canonical options changed cache identity: (%q,%q) / (%q,%q)",
			firstParameters, secondParameters, firstReuse, secondReuse,
		)
	}
	mutations := []func(*JobPayload, *BytecodeAnalyzerIdentity, *string){
		func(value *JobPayload, _ *BytecodeAnalyzerIdentity, _ *string) {
			value.Target.SHA256 = strings.Repeat("a", 64)
		},
		func(value *JobPayload, _ *BytecodeAnalyzerIdentity, _ *string) {
			value.Target.SizeBytes++
		},
		func(value *JobPayload, _ *BytecodeAnalyzerIdentity, _ *string) {
			value.Target.Format = "jar"
		},
		func(value *JobPayload, _ *BytecodeAnalyzerIdentity, _ *string) {
			value.Target.Architecture = "jvm"
		},
		func(_ *JobPayload, value *BytecodeAnalyzerIdentity, _ *string) {
			value.Engine.Version = "1.0.1"
		},
		func(_ *JobPayload, _ *BytecodeAnalyzerIdentity, value *string) {
			*value = strings.Repeat("b", 64)
		},
	}
	for index, mutate := range mutations {
		changedPayload, changedIdentity, changedParameters := payload, identity, parameters
		mutate(&changedPayload, &changedIdentity, &changedParameters)
		changed, changedErr := bytecodeReuseIdentity(
			changedPayload, changedIdentity, changedParameters,
		)
		if changedErr != nil || changed == baseline {
			t.Fatalf("mutation %d retained identity %q: %v", index, changed, changedErr)
		}
	}
}

func TestBytecodeCacheCandidateRejectsNonReusableResultSets(t *testing.T) {
	repositoryRoot := t.TempDir()
	baseline := writeBytecodeCacheCandidate(
		t, repositoryRoot, []byte("public class Cached {}\n"),
	)
	for _, status := range []bytecode.Status{
		bytecode.StatusPartial,
		bytecode.StatusUnsupported,
		bytecode.Status("failed"),
	} {
		candidate := baseline
		candidate.ResultStatus = status
		if validBytecodeCacheCandidate(candidate, defaultJobLimits) {
			t.Fatalf("cache accepted run status %q", status)
		}
	}
	failed := baseline
	failed.Results = append([]BytecodeCachedResult(nil), baseline.Results...)
	failed.Results[0].Status = "failed"
	if validBytecodeCacheCandidate(failed, defaultJobLimits) {
		t.Fatal("cache accepted failed result")
	}
}

func writeBytecodeCacheCandidate(
	t *testing.T,
	repositoryRoot string,
	content []byte,
) BytecodeCacheCandidate {
	t.Helper()
	storageKey := "decompile/" + testCacheSourceResult + "/source.java"
	writeCachedResultFile(t, repositoryRoot, storageKey, content)
	return BytecodeCacheCandidate{
		RunID: testCacheSourceRunID, TaskID: testCacheSourceTaskID,
		ResultStatus: bytecode.StatusComplete,
		Results: []BytecodeCachedResult{{
			ID: testCacheSourceResult, SymbolKey: "class:A", Language: "java",
			Status: "complete", StorageKey: storageKey,
			SHA256: digestBytes(content), SizeBytes: uint64(len(content)),
			Diagnostics: json.RawMessage(
				`{"symbol_kind":"class","display_name":"A","methods":[]}`,
			),
		}},
	}
}

func writeCachedResultFile(
	t *testing.T,
	repositoryRoot string,
	storageKey string,
	content []byte,
) {
	t.Helper()
	filePath := filepath.Join(repositoryRoot, filepath.FromSlash(storageKey))
	if err := os.MkdirAll(filepath.Dir(filePath), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filePath, content, 0o600); err != nil {
		t.Fatal(err)
	}
}
