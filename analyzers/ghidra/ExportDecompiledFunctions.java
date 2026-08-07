// Headless post-script. Arguments:
//   <index.json> <output-dir> <max-functions> <max-output-bytes>
//   <max-entry-points> <max-segments> <max-call-edges> <max-index-bytes>

import java.io.BufferedWriter;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.StandardCopyOption;
import java.security.MessageDigest;
import java.util.ArrayList;
import java.util.Comparator;
import java.util.HashSet;
import java.util.List;
import java.util.Set;

import ghidra.app.decompiler.DecompInterface;
import ghidra.app.decompiler.DecompileResults;
import ghidra.app.script.GhidraScript;
import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressIterator;
import ghidra.program.model.listing.Function;
import ghidra.program.model.mem.MemoryBlock;
import ghidra.program.model.symbol.Symbol;

public final class ExportDecompiledFunctions extends GhidraScript {
    private static final int INDEX_SCHEMA_VERSION = 3;
    private static final int FUNCTION_TIMEOUT_SECONDS = 60;
    private static final String ERROR_PREFIX = "BINARYSCAN_GHIDRA_ERROR=";
    private static final String PROGRESS_PREFIX = "BINARYSCAN_GHIDRA_PROGRESS=";

    private static final class EntryPointEntry {
        String address;
        String symbol;
    }

    private static final class SegmentEntry {
        String name;
        String start;
        String end;
        long size;
        String permissions;
        boolean initialized;
        boolean overlay;
    }

    private static final class FunctionEntry {
        Function function;
        String name;
        String address;
        long size;
        String file;
        String sha256;
        long sourceSize;
    }

    private static final class DecompileSummary {
        List<FunctionEntry> functions;
        int candidateCount;
        boolean partial;
    }

    private static final class BoundedSummary<T> {
        List<T> entries = new ArrayList<>();
        boolean partial;
    }

    private static final class CallEdgeEntry {
        String callerAddress;
        String calleeAddress;
        String calleeName;
        boolean external;
    }

    private static final class ClassifiedFailure extends Exception {
        ClassifiedFailure(String message) {
            super(message);
        }
    }

    @Override
    protected void run() throws Exception {
        String[] args = getScriptArgs();
        if (args.length != 8) {
            throw new IllegalArgumentException("expected exactly eight script arguments");
        }
        Path index = Path.of(args[0]).toAbsolutePath().normalize();
        Path output = Path.of(args[1]).toAbsolutePath().normalize();
        int maxFunctions = positiveInt(args[2], "max-functions");
        long maxOutputBytes = positiveLong(args[3], "max-output-bytes");
        int maxEntryPoints = positiveInt(args[4], "max-entry-points");
        int maxSegments = positiveInt(args[5], "max-segments");
        int maxCallEdges = positiveInt(args[6], "max-call-edges");
        long maxIndexBytes = positiveLong(args[7], "max-index-bytes");
        if (!index.getParent().equals(output)) {
            throw new IllegalArgumentException("index must be inside output directory");
        }
        Files.createDirectories(output);

        if (currentProgram.getLanguageID() == null) {
            fail("unsupported_architecture", "program language is unavailable");
        }
        BoundedSummary<EntryPointEntry> entryPoints =
            collectEntryPoints(maxEntryPoints);
        BoundedSummary<SegmentEntry> segments = collectSegments(maxSegments);
        DecompileSummary decompiled = decompileFunctions(
            output, maxFunctions, maxOutputBytes
        );
        BoundedSummary<CallEdgeEntry> callEdges = collectCallEdges(
            decompiled.functions, maxCallEdges
        );
        decompiled.partial = decompiled.partial || entryPoints.partial ||
            segments.partial || callEdges.partial;
        writeIndex(
            index, output, entryPoints.entries, segments.entries,
            decompiled, callEdges.entries,
            maxIndexBytes
        );
    }

    private BoundedSummary<EntryPointEntry> collectEntryPoints(int limit)
            throws Exception {
        BoundedSummary<EntryPointEntry> result = new BoundedSummary<>();
        AddressIterator iterator = currentProgram.getSymbolTable()
            .getExternalEntryPointIterator();
        while (iterator.hasNext()) {
            checkCancelled();
            if (result.entries.size() >= limit) {
                result.partial = true;
                break;
            }
            Address address = iterator.next();
            Symbol symbol = currentProgram.getSymbolTable().getPrimarySymbol(address);
            EntryPointEntry entry = new EntryPointEntry();
            entry.address = address.toString();
            entry.symbol = symbol == null ? "" : symbol.getName();
            result.entries.add(entry);
        }
        result.entries.sort(Comparator.comparing(item -> item.address));
        return result;
    }

    private BoundedSummary<SegmentEntry> collectSegments(int limit)
            throws Exception {
        BoundedSummary<SegmentEntry> result = new BoundedSummary<>();
        for (MemoryBlock block : currentProgram.getMemory().getBlocks()) {
            checkCancelled();
            if (result.entries.size() >= limit) {
                result.partial = true;
                break;
            }
            SegmentEntry entry = new SegmentEntry();
            entry.name = block.getName();
            entry.start = block.getStart().toString();
            entry.end = block.getEnd().toString();
            entry.size = block.getSize();
            entry.permissions = permissions(block);
            entry.initialized = block.isInitialized();
            entry.overlay = block.getStart().getAddressSpace().isOverlaySpace();
            result.entries.add(entry);
        }
        result.entries.sort(Comparator
            .comparing((SegmentEntry item) -> item.start)
            .thenComparing(item -> item.name));
        return result;
    }

    private DecompileSummary decompileFunctions(
            Path output, int maxFunctions, long maxOutputBytes) throws Exception {
        List<Function> candidates = new ArrayList<>();
        int candidateCount = 0;
        boolean partial = false;
        for (Function function :
                currentProgram.getFunctionManager().getFunctions(true)) {
            if (function.isExternal()) {
                continue;
            }
            candidateCount++;
            if (candidates.size() < maxFunctions) {
                candidates.add(function);
            } else {
                partial = true;
            }
        }
        candidates.sort(Comparator.comparing(
            function -> function.getEntryPoint().toString()
        ));
        if (!candidates.isEmpty()) {
            printProgress(0, candidates.size());
        }
        List<FunctionEntry> result = new ArrayList<>();
        int progressStep = Math.max(1, (candidates.size() + 19) / 20);
        int processed = 0;
        boolean unsupportedInstructionSeen = false;
        long total = 0;
        DecompInterface decompiler = new DecompInterface();
        if (!decompiler.openProgram(currentProgram)) {
            fail("unsupported_architecture", "cannot open program in decompiler");
        }
        try {
            for (Function function : candidates) {
                checkCancelled();
                DecompileResults decompiled = decompiler.decompileFunction(
                    function, FUNCTION_TIMEOUT_SECONDS, monitor
                );
                processed++;
                if (!decompiled.decompileCompleted() ||
                        decompiled.getDecompiledFunction() == null) {
                    partial = true;
                    unsupportedInstructionSeen = unsupportedInstructionSeen ||
                        isUnsupportedInstruction(decompiled.getErrorMessage());
                    printProgressIfNeeded(
                        processed, candidates.size(), progressStep
                    );
                    continue;
                }
                byte[] source = decompiled.getDecompiledFunction()
                    .getC().getBytes(StandardCharsets.UTF_8);
                if (source.length > maxOutputBytes - total) {
                    partial = true;
                    printProgressIfNeeded(
                        processed, candidates.size(), progressStep
                    );
                    break;
                }
                total += source.length;
                String file = String.format("f-%06d.c", result.size());
                Path destination = output.resolve(file).normalize();
                if (!destination.getParent().equals(output)) {
                    throw new IllegalStateException("invalid output path");
                }
                Files.write(destination, source);
                FunctionEntry entry = new FunctionEntry();
                entry.function = function;
                entry.name = function.getName();
                entry.address = function.getEntryPoint().toString();
                entry.size = function.getBody().getNumAddresses();
                entry.file = file;
                entry.sha256 = hex(
                    MessageDigest.getInstance("SHA-256").digest(source)
                );
                entry.sourceSize = source.length;
                result.add(entry);
                printProgressIfNeeded(
                    processed, candidates.size(), progressStep
                );
            }
        } finally {
            decompiler.dispose();
        }
        if (result.isEmpty() && candidateCount > 0) {
            fail(
                unsupportedInstructionSeen
                    ? "unsupported_instruction"
                    : "decompile_incomplete",
                "none of the discovered functions could be decompiled"
            );
        }
        DecompileSummary summary = new DecompileSummary();
        summary.functions = result;
        summary.candidateCount = candidateCount;
        summary.partial = partial || result.size() < candidateCount;
        return summary;
    }

    private void printProgress(int current, int total) {
        println(PROGRESS_PREFIX + current + "/" + total);
    }

    private void printProgressIfNeeded(
            int processed, int total, int step) {
        if (processed == 1 || processed == total || processed % step == 0) {
            printProgress(processed, total);
        }
    }

    private BoundedSummary<CallEdgeEntry> collectCallEdges(
            List<FunctionEntry> functions, int limit) throws Exception {
        BoundedSummary<CallEdgeEntry> result = new BoundedSummary<>();
        Set<String> seen = new HashSet<>();
        outer:
        for (FunctionEntry caller : functions) {
            checkCancelled();
            List<Function> callees = new ArrayList<>(
                caller.function.getCalledFunctions(monitor)
            );
            callees.sort(Comparator.comparing(
                function -> function.getEntryPoint().toString()
            ));
            for (Function callee : callees) {
                String calleeAddress = callee.getEntryPoint().toString();
                String key = caller.address + "\u0000" + calleeAddress;
                if (!seen.add(key)) {
                    continue;
                }
                if (result.entries.size() >= limit) {
                    result.partial = true;
                    break outer;
                }
                CallEdgeEntry edge = new CallEdgeEntry();
                edge.callerAddress = caller.address;
                edge.calleeAddress = calleeAddress;
                edge.calleeName = callee.getName();
                edge.external = callee.isExternal();
                result.entries.add(edge);
            }
        }
        result.entries.sort(Comparator
            .comparing((CallEdgeEntry item) -> item.callerAddress)
            .thenComparing(item -> item.calleeAddress));
        return result;
    }

    private void writeIndex(
            Path index,
            Path output,
            List<EntryPointEntry> entryPoints,
            List<SegmentEntry> segments,
            DecompileSummary decompiled,
            List<CallEdgeEntry> callEdges,
            long maxIndexBytes) throws Exception {
        Path staging = output.resolve(".index.json.tmp");
        List<CallEdgeEntry> retainedCallEdges = callEdges;
        writeIndexFile(
            staging, entryPoints, segments, decompiled, retainedCallEdges
        );
        while (Files.size(staging) > maxIndexBytes &&
                !retainedCallEdges.isEmpty()) {
            decompiled.partial = true;
            retainedCallEdges = retainedCallEdges.subList(
                0, retainedCallEdges.size() / 2
            );
            writeIndexFile(
                staging, entryPoints, segments, decompiled, retainedCallEdges
            );
        }
        if (Files.size(staging) > maxIndexBytes) {
            Files.deleteIfExists(staging);
            fail("script_limit", "index byte limit exceeded");
        }
        Files.move(
            staging, index, StandardCopyOption.ATOMIC_MOVE,
            StandardCopyOption.REPLACE_EXISTING
        );
    }

    private void writeIndexFile(
            Path staging,
            List<EntryPointEntry> entryPoints,
            List<SegmentEntry> segments,
            DecompileSummary decompiled,
            List<CallEdgeEntry> callEdges) throws Exception {
        List<FunctionEntry> functions = decompiled.functions;
        try (BufferedWriter writer = Files.newBufferedWriter(
                staging, StandardCharsets.UTF_8)) {
            writer.write("{\"schema_version\":");
            writer.write(Integer.toString(INDEX_SCHEMA_VERSION));
            writer.write(",\"format\":\"");
            writer.write(escape(currentProgram.getExecutableFormat()));
            writer.write("\",\"architecture\":\"");
            writer.write(escape(currentProgram.getLanguageID().toString()));
            writer.write("\",\"completeness\":\"");
            writer.write(decompiled.partial ? "partial" : "complete");
            writer.write("\"");
            writer.write(",\"candidate_function_count\":");
            writer.write(Integer.toString(decompiled.candidateCount));
            writer.write(",\"decompiled_function_count\":");
            writer.write(Integer.toString(functions.size()));
            writer.write(",\"entry_points\":[");
            for (int i = 0; i < entryPoints.size(); i++) {
                if (i != 0) writer.write(",");
                EntryPointEntry entry = entryPoints.get(i);
                writer.write("{\"address\":\"");
                writer.write(escape(entry.address));
                writer.write("\",\"symbol\":\"");
                writer.write(escape(entry.symbol));
                writer.write("\"}");
            }
            writer.write("],\"segments\":[");
            for (int i = 0; i < segments.size(); i++) {
                if (i != 0) writer.write(",");
                SegmentEntry entry = segments.get(i);
                writer.write("{\"name\":\"");
                writer.write(escape(entry.name));
                writer.write("\",\"start\":\"");
                writer.write(escape(entry.start));
                writer.write("\",\"end\":\"");
                writer.write(escape(entry.end));
                writer.write("\",\"size_bytes\":");
                writer.write(Long.toString(entry.size));
                writer.write(",\"permissions\":\"");
                writer.write(entry.permissions);
                writer.write("\",\"initialized\":");
                writer.write(Boolean.toString(entry.initialized));
                writer.write(",\"overlay\":");
                writer.write(Boolean.toString(entry.overlay));
                writer.write("}");
            }
            writer.write("],\"functions\":[");
            for (int i = 0; i < functions.size(); i++) {
                if (i != 0) writer.write(",");
                FunctionEntry entry = functions.get(i);
                writer.write("{\"name\":\"");
                writer.write(escape(entry.name));
                writer.write("\",\"address\":\"");
                writer.write(escape(entry.address));
                writer.write("\",\"size_bytes\":");
                writer.write(Long.toString(entry.size));
                writer.write(",\"source_file\":\"");
                writer.write(entry.file);
                writer.write("\",\"sha256\":\"");
                writer.write(entry.sha256);
                writer.write("\",\"source_size\":");
                writer.write(Long.toString(entry.sourceSize));
                writer.write("}");
            }
            writer.write("],\"call_edges\":[");
            for (int i = 0; i < callEdges.size(); i++) {
                if (i != 0) writer.write(",");
                CallEdgeEntry edge = callEdges.get(i);
                writer.write("{\"caller_address\":\"");
                writer.write(escape(edge.callerAddress));
                writer.write("\",\"callee_address\":\"");
                writer.write(escape(edge.calleeAddress));
                writer.write("\",\"callee_name\":\"");
                writer.write(escape(edge.calleeName));
                writer.write("\",\"external\":");
                writer.write(Boolean.toString(edge.external));
                writer.write("}");
            }
            writer.write("]}");
        }
    }

    private void checkCancelled() throws InterruptedException {
        if (monitor.isCancelled()) {
            throw new InterruptedException("export cancelled");
        }
    }

    private void fail(String code, String message) throws ClassifiedFailure {
        printerr(ERROR_PREFIX + code);
        throw new ClassifiedFailure(message);
    }

    private static boolean isUnsupportedInstruction(String value) {
        if (value == null) return false;
        String lower = value.toLowerCase(java.util.Locale.ROOT);
        return lower.contains("unsupported instruction") ||
            lower.contains("unimplemented instruction") ||
            lower.contains("unknown instruction") ||
            lower.contains("bad instruction");
    }

    private static int positiveInt(String value, String name) {
        int parsed = Integer.parseInt(value);
        if (parsed < 1) {
            throw new IllegalArgumentException(name + " must be positive");
        }
        return parsed;
    }

    private static long positiveLong(String value, String name) {
        long parsed = Long.parseLong(value);
        if (parsed < 1) {
            throw new IllegalArgumentException(name + " must be positive");
        }
        return parsed;
    }

    private static String permissions(MemoryBlock block) {
        return (block.isRead() ? "r" : "-") +
            (block.isWrite() ? "w" : "-") +
            (block.isExecute() ? "x" : "-");
    }

    private static String hex(byte[] value) {
        StringBuilder result = new StringBuilder(value.length * 2);
        for (byte item : value) {
            result.append(String.format("%02x", item & 0xff));
        }
        return result.toString();
    }

    private static String escape(String value) {
        StringBuilder result = new StringBuilder(value.length() + 16);
        for (int i = 0; i < value.length(); i++) {
            char c = value.charAt(i);
            switch (c) {
            case '"': result.append("\\\""); break;
            case '\\': result.append("\\\\"); break;
            case '\b': result.append("\\b"); break;
            case '\f': result.append("\\f"); break;
            case '\n': result.append("\\n"); break;
            case '\r': result.append("\\r"); break;
            case '\t': result.append("\\t"); break;
            default:
                if (c < 0x20) {
                    result.append(String.format("\\u%04x", (int)c));
                } else {
                    result.append(c);
                }
            }
        }
        return result.toString();
    }
}
