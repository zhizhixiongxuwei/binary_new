package com.binaryscan.javachecker.engine;

import static org.assertj.core.api.Assertions.assertThat;

import java.nio.charset.StandardCharsets;
import java.util.Set;
import java.util.stream.Collectors;

import org.junit.jupiter.api.Test;

import com.binaryscan.javachecker.TestProject;
import com.binaryscan.javachecker.api.AnalysisResponse;
import com.binaryscan.javachecker.service.CheckerLimits;
import com.binaryscan.javachecker.service.SourceValidator;

class FixedRulesTest {
    private static final String ALL_RULES = """
            package example;
            import java.io.*;
            import java.security.MessageDigest;
            import java.sql.Statement;
            import java.io.File;
            import javax.crypto.Cipher;
            import javax.crypto.spec.SecretKeySpec;
            import javax.net.ssl.*;
            import javax.script.ScriptEngine;
            import javax.servlet.http.Cookie;
            import javax.xml.parsers.DocumentBuilderFactory;

            class Rules implements HostnameVerifier, X509TrustManager {
                public boolean verify(String host, SSLSession session) { return true; }
                public void checkClientTrusted(java.security.cert.X509Certificate[] chain, String auth) {}
                public void checkServerTrusted(java.security.cert.X509Certificate[] chain, String auth) {}
                public java.security.cert.X509Certificate[] getAcceptedIssuers() { return null; }

                void scan(String user, InputStream raw) throws Exception {
                    MessageDigest.getInstance("MD5");
                    Cipher.getInstance("AES/ECB/PKCS5Padding");
                    SSLContext.getInstance("TLSv1.1");
                    new SecretKeySpec("embedded-key".getBytes(java.nio.charset.StandardCharsets.UTF_8), "AES");
                    DocumentBuilderFactory factory = DocumentBuilderFactory.newInstance();
                    factory.setFeature("http://xml.org/sax/features/external-general-entities", true);
                    ObjectInputStream objects = new ObjectInputStream(raw);
                    objects.readObject();
                    Statement statement = null;
                    String sql = "SELECT * FROM users WHERE name='" + user + "'";
                    statement.executeQuery(sql);
                    Runtime.getRuntime().exec(user);
                    new ProcessBuilder(user);
                    ScriptEngine engine = null;
                    engine.eval(user);
                    File file = null;
                    file.setWritable(true, false);
                    Cookie cookie = null;
                    cookie.setSecure(false);
                }
            }
            """;

    @Test
    void detectsThePinnedThirteenRuleFamiliesWithContractFields() {
        CheckerLimits limits = CheckerLimits.defaults();
        TestProject.Request raw = TestProject.oneFile(ALL_RULES);
        var request = new SourceValidator(limits)
                .validate(raw.metadata().analysisId(), raw.metadata(), raw.bundle());
        JavaRuleEvaluator evaluator = new JavaRuleEvaluator(limits);
        AnalysisResponse response = new JavaAnalyzer(limits, evaluator)
                .analyze(request, new AnalysisRunContext(() -> false));

        Set<String> actualRules = response.findings().stream()
                .map(AnalysisResponse.Finding::ruleId).collect(Collectors.toSet());
        assertThat(actualRules)
                .withFailMessage("findings=%s diagnostics=%s", response.findings(), response.diagnostics())
                .containsExactlyInAnyOrderElementsOf(JavaRuleEvaluator.RULE_IDS);
        assertThat(response.status()).isEqualTo("complete");
        assertThat(response.identity().product()).isEqualTo("binaryscan-java-checker");
        assertThat(response.identity().version()).isEqualTo("0.1.0");
        assertThat(response.identity().ruleset()).isEqualTo("java-rules-v1");
        assertThat(response.findings()).allSatisfy(finding -> {
            assertThat(finding.cwe()).startsWith("CWE-");
            assertThat(finding.severity()).isIn("LOW", "MEDIUM", "HIGH", "CRITICAL");
            assertThat(finding.callable()).isNotNull();
            assertThat(finding.callable().kind()).isNotBlank();
            assertThat(finding.callable().typeName()).isNotBlank();
            assertThat(finding.callable().name()).isNotBlank();
            assertThat(finding.callable().signature()).isNotBlank();
            assertThat(finding.snippet().getBytes(StandardCharsets.UTF_8)).hasSizeLessThanOrEqualTo(1024);
            assertThat(finding.snippetStartLine()).isPositive();
        });
    }

    @Test
    void avoidsNearbyConstantAndSecureForms() {
        String source = """
                package example;
                import java.security.MessageDigest;
                import javax.crypto.Cipher;
                import javax.net.ssl.SSLContext;
                class Safe {
                  void run() throws Exception {
                    MessageDigest.getInstance("SHA-256");
                    Cipher.getInstance("AES/GCM/NoPadding");
                    SSLContext.getInstance("TLSv1.3");
                    Runtime.getRuntime().exec("/usr/bin/id");
                  }
                }
                """;
        CheckerLimits limits = CheckerLimits.defaults();
        TestProject.Request raw = TestProject.oneFile(source);
        var request = new SourceValidator(limits)
                .validate(raw.metadata().analysisId(), raw.metadata(), raw.bundle());

        AnalysisResponse response = new JavaAnalyzer(limits, new JavaRuleEvaluator(limits))
                .analyze(request, new AnalysisRunContext(() -> false));

        assertThat(response.findings()).isEmpty();
    }

    @Test
    void boundsMaliciousMultibyteCallableIdentityAndConfigurationText() {
        String typeName = "\u7c7b".repeat(1000);
        String methodName = "\u65b9".repeat(1000);
        String hugeAlgorithmSuffix = "\u754c".repeat(1000);
        String source = "import java.security.MessageDigest; class " + typeName
                + " { void " + methodName + "() throws Exception {"
                + "MessageDigest.getInstance(\"MD5\");"
                + "MessageDigest.getInstance(\"MD5" + hugeAlgorithmSuffix + "\");"
                + "} }";
        CheckerLimits limits = CheckerLimits.defaults();
        TestProject.Request raw = TestProject.oneFile(source);
        var request = new SourceValidator(limits)
                .validate(raw.metadata().analysisId(), raw.metadata(), raw.bundle());

        AnalysisResponse response = new JavaAnalyzer(limits, new JavaRuleEvaluator(limits))
                .analyze(request, new AnalysisRunContext(() -> false));

        assertThat(response.findings()).hasSize(1);
        AnalysisResponse.Finding finding = response.findings().get(0);
        assertThat(com.binaryscan.javachecker.service.Utf8Text.bytes(finding.message())).isLessThanOrEqualTo(2048);
        assertThat(com.binaryscan.javachecker.service.Utf8Text.bytes(finding.callable().kind())).isLessThanOrEqualTo(32);
        assertThat(com.binaryscan.javachecker.service.Utf8Text.bytes(finding.callable().typeName()))
                .isLessThanOrEqualTo(1024);
        assertThat(com.binaryscan.javachecker.service.Utf8Text.bytes(finding.callable().name()))
                .isLessThanOrEqualTo(512);
        assertThat(com.binaryscan.javachecker.service.Utf8Text.bytes(finding.callable().signature()))
                .isLessThanOrEqualTo(2048);
    }
}
