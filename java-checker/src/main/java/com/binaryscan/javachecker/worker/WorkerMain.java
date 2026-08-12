package com.binaryscan.javachecker.worker;

import java.io.OutputStream;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.StandardCopyOption;
import java.nio.file.StandardOpenOption;

import com.binaryscan.javachecker.api.AnalysisMetadata;
import com.binaryscan.javachecker.api.AnalysisResponse;
import com.binaryscan.javachecker.engine.AnalysisRunContext;
import com.binaryscan.javachecker.engine.JavaAnalyzer;
import com.binaryscan.javachecker.engine.JavaRuleEvaluator;
import com.binaryscan.javachecker.service.CheckerLimits;
import com.binaryscan.javachecker.service.ResponseFactory;
import com.binaryscan.javachecker.service.SourceValidator;
import com.binaryscan.javachecker.service.ValidatedRequest;
import com.fasterxml.jackson.databind.DeserializationFeature;
import com.fasterxml.jackson.databind.ObjectMapper;

public final class WorkerMain {
    private WorkerMain() {
    }

    public static void main(String[] args) throws Exception {
        if (args.length != 9) {
            throw new IllegalArgumentException(
                    "usage: WorkerMain metadata bundle output maxFile maxFindings maxDiagnostics "
                            + "maxSnippet maxSource maxResponse");
        }
        Path metadataPath = Path.of(args[0]);
        Path bundlePath = Path.of(args[1]);
        Path outputPath = Path.of(args[2]);
        CheckerLimits defaults = CheckerLimits.defaults();
        CheckerLimits limits = new CheckerLimits(
                Long.parseLong(args[7]),
                defaults.maxFiles(),
                Long.parseLong(args[3]),
                Integer.parseInt(args[4]),
                Integer.parseInt(args[5]),
                Integer.parseInt(args[6]),
                Long.parseLong(args[8]),
                defaults.analysisTimeout(),
                defaults.forceKillGrace());

        ObjectMapper mapper = new ObjectMapper()
                .findAndRegisterModules()
                .enable(DeserializationFeature.FAIL_ON_UNKNOWN_PROPERTIES);
        AnalysisMetadata metadata = mapper.readValue(metadataPath.toFile(), AnalysisMetadata.class);
        ValidatedRequest request = loadRequest(metadata, bundlePath, limits);
        JavaRuleEvaluator rules = new JavaRuleEvaluator(limits);
        AnalysisResponse response = new JavaAnalyzer(limits, rules)
                .analyze(request, new AnalysisRunContext(() -> false));

        Path temporary = outputPath.resolveSibling(outputPath.getFileName() + ".tmp");
        long responseLimit = Long.parseLong(args[8]);
        try {
            writeBounded(mapper, temporary, response, responseLimit);
        } catch (Exception error) {
            if (!BoundedOutputStream.isLimitExceeded(error)) {
                throw error;
            }
            Files.deleteIfExists(temporary);
            AnalysisResponse failed = ResponseFactory.terminal(metadata, "failed", "response_too_large",
                    "serialized Java checker response exceeded the configured byte limit");
            writeBounded(mapper, temporary, failed, responseLimit);
        }
        Files.move(temporary, outputPath, StandardCopyOption.ATOMIC_MOVE);
    }

    private static ValidatedRequest loadRequest(
            AnalysisMetadata metadata, Path bundlePath, CheckerLimits limits) throws Exception {
        byte[] bundle = Files.readAllBytes(bundlePath);
        return new SourceValidator(limits).validate(metadata.analysisId(), metadata, bundle);
    }

    private static void writeBounded(
            ObjectMapper mapper, Path output, AnalysisResponse response, long limit) throws Exception {
        try (OutputStream file = Files.newOutputStream(output,
                StandardOpenOption.CREATE, StandardOpenOption.TRUNCATE_EXISTING, StandardOpenOption.WRITE);
                BoundedOutputStream bounded = new BoundedOutputStream(file, limit)) {
            mapper.writeValue(bounded, response);
        }
    }
}
