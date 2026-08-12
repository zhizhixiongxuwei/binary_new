package com.binaryscan.javachecker.engine;

import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.Comparator;
import java.util.HashSet;
import java.util.IdentityHashMap;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.Optional;
import java.util.Set;
import java.util.regex.Pattern;

import org.springframework.stereotype.Component;

import com.binaryscan.javachecker.api.AnalysisResponse;
import com.binaryscan.javachecker.service.CheckerLimits;
import com.binaryscan.javachecker.service.SourceFile;
import com.binaryscan.javachecker.service.Utf8Text;
import com.github.javaparser.Position;
import com.github.javaparser.Range;
import com.github.javaparser.ast.CompilationUnit;
import com.github.javaparser.ast.ImportDeclaration;
import com.github.javaparser.ast.Node;
import com.github.javaparser.ast.body.ClassOrInterfaceDeclaration;
import com.github.javaparser.ast.body.ConstructorDeclaration;
import com.github.javaparser.ast.body.FieldDeclaration;
import com.github.javaparser.ast.body.InitializerDeclaration;
import com.github.javaparser.ast.body.MethodDeclaration;
import com.github.javaparser.ast.body.Parameter;
import com.github.javaparser.ast.body.TypeDeclaration;
import com.github.javaparser.ast.expr.BooleanLiteralExpr;
import com.github.javaparser.ast.expr.Expression;
import com.github.javaparser.ast.expr.LambdaExpr;
import com.github.javaparser.ast.expr.MethodCallExpr;
import com.github.javaparser.ast.expr.ObjectCreationExpr;
import com.github.javaparser.ast.stmt.BlockStmt;
import com.github.javaparser.ast.stmt.ReturnStmt;
import com.github.javaparser.ast.stmt.Statement;

@Component
public class JavaRuleEvaluator {
    public static final RuleDefinition WEAK_DIGEST =
            new RuleDefinition("java-weak-message-digest", "CWE-328", "MEDIUM");
    public static final RuleDefinition WEAK_CIPHER =
            new RuleDefinition("java-weak-cipher", "CWE-327", "MEDIUM");
    public static final RuleDefinition LEGACY_TLS =
            new RuleDefinition("java-legacy-tls", "CWE-326", "MEDIUM");
    public static final RuleDefinition HARDCODED_KEY =
            new RuleDefinition("java-hardcoded-crypto-key", "CWE-321", "HIGH");
    public static final RuleDefinition TRUST_HOSTNAME =
            new RuleDefinition("java-trust-all-hostname-verifier", "CWE-295", "HIGH");
    public static final RuleDefinition TRUST_X509 =
            new RuleDefinition("java-trust-all-x509-manager", "CWE-295", "HIGH");
    public static final RuleDefinition XXE =
            new RuleDefinition("java-xxe-enabled", "CWE-611", "HIGH");
    public static final RuleDefinition DESERIALIZATION =
            new RuleDefinition("java-unsafe-deserialization", "CWE-502", "HIGH");
    public static final RuleDefinition SQL_INJECTION =
            new RuleDefinition("java-sql-injection", "CWE-89", "HIGH");
    public static final RuleDefinition COMMAND_INJECTION =
            new RuleDefinition("java-command-injection", "CWE-78", "HIGH");
    public static final RuleDefinition DYNAMIC_CODE =
            new RuleDefinition("java-dynamic-code-execution", "CWE-94", "HIGH");
    public static final RuleDefinition BROAD_PERMISSION =
            new RuleDefinition("java-overly-permissive-file", "CWE-732", "MEDIUM");
    public static final RuleDefinition INSECURE_COOKIE =
            new RuleDefinition("java-insecure-cookie", "CWE-614", "MEDIUM");

    public static final Set<String> RULE_IDS = Set.of(
            WEAK_DIGEST.ruleId(), WEAK_CIPHER.ruleId(), LEGACY_TLS.ruleId(), HARDCODED_KEY.ruleId(),
            TRUST_HOSTNAME.ruleId(), TRUST_X509.ruleId(), XXE.ruleId(), DESERIALIZATION.ruleId(),
            SQL_INJECTION.ruleId(), COMMAND_INJECTION.ruleId(), DYNAMIC_CODE.ruleId(),
            BROAD_PERMISSION.ruleId(), INSECURE_COOKIE.ruleId());

    private static final Pattern SQL_TEXT = Pattern.compile(
            "(?is)\\b(select|insert|update|delete|merge|replace|call)\\b.*");
    private static final Set<String> SQL_METHODS = Set.of(
            "execute", "executeQuery", "executeUpdate", "executeLargeUpdate", "addBatch", "prepareStatement",
            "prepareCall", "createNativeQuery", "createQuery");
    private static final Set<String> EXTERNAL_ENTITY_FEATURES = Set.of(
            "http://xml.org/sax/features/external-general-entities",
            "http://xml.org/sax/features/external-parameter-entities",
            "http://apache.org/xml/features/nonvalidating/load-external-dtd");
    private static final Set<String> DISABLE_DTD_FEATURES = Set.of(
            "http://apache.org/xml/features/disallow-doctype-decl");

    private final CheckerLimits limits;

    public JavaRuleEvaluator(CheckerLimits limits) {
        this.limits = limits;
    }

    public RuleEvaluation evaluate(
            CompilationUnit unit,
            SourceFile file,
            AnalysisRunContext context,
            int findingCapacity,
            long findingByteCapacity) {
        Emitter emitter = new Emitter(file, Math.max(0, findingCapacity),
                limits.maxSnippetBytes(), Math.max(0, findingByteCapacity));

        List<MethodCallExpr> calls = sorted(unit.findAll(MethodCallExpr.class));
        for (MethodCallExpr call : calls) {
            context.checkpoint();
            evaluateCrypto(unit, call, emitter);
            evaluateXxe(call, emitter);
            evaluateDeserialization(call, emitter);
            evaluateSql(call, emitter);
            evaluateCommand(call, emitter);
            evaluateDynamicCode(call, emitter);
            evaluatePermissions(call, emitter);
            evaluateCookie(call, emitter);
            evaluateHostnameCall(call, emitter);
        }

        for (ObjectCreationExpr creation : sorted(unit.findAll(ObjectCreationExpr.class))) {
            context.checkpoint();
            evaluateHardcodedKey(creation, emitter);
            evaluateProcessBuilder(creation, emitter);
        }
        evaluateHostnameImplementations(unit, emitter, context);
        evaluateTrustManagers(unit, emitter, context);

        emitter.findings.sort(Comparator
                .comparing((AnalysisResponse.Finding finding) -> finding.file().logicalPath(),
                        JavaRuleEvaluator::compareUtf8)
                .thenComparingInt(finding -> finding.location().startLine())
                .thenComparingInt(finding -> finding.location().startColumn())
                .thenComparing(AnalysisResponse.Finding::ruleId));
        return new RuleEvaluation(List.copyOf(emitter.findings), emitter.truncated, emitter.estimatedBytes);
    }

    private static void evaluateCrypto(CompilationUnit unit, MethodCallExpr call, Emitter emitter) {
        if (!"getInstance".equals(call.getNameAsString()) || call.getArguments().isEmpty()) {
            return;
        }
        Optional<String> configured = ExpressionFacts.constantString(call.getArgument(0));
        if (configured.isEmpty()) {
            return;
        }
        String rawAlgorithm = configured.get();
        if (rawAlgorithm.length() > 128) {
            return;
        }
        String displayAlgorithm = Utf8Text.bound(rawAlgorithm.trim(), 256, "<algorithm>");
        String algorithm = rawAlgorithm.trim().toUpperCase(Locale.ROOT).replace("-", "");
        if (isStaticTypeCall(unit, call, "MessageDigest", "java.security.MessageDigest")
                && Set.of("MD2", "MD4", "MD5", "SHA1").contains(algorithm)) {
            emitter.emit(WEAK_DIGEST, call,
                    "MessageDigest selects the weak " + displayAlgorithm + " algorithm");
        }
        if (isStaticTypeCall(unit, call, "Cipher", "javax.crypto.Cipher") && weakCipher(algorithm)) {
            emitter.emit(WEAK_CIPHER, call,
                    "Cipher selects a weak algorithm or ECB transformation: " + displayAlgorithm);
        }
        if (isStaticTypeCall(unit, call, "SSLContext", "javax.net.ssl.SSLContext")
                && Set.of("SSL", "SSLV2", "SSLV3", "TLSV1", "TLSV1.0", "TLSV1.1").contains(algorithm)) {
            emitter.emit(LEGACY_TLS, call,
                    "SSLContext explicitly selects legacy protocol " + displayAlgorithm);
        }
    }

    private static boolean weakCipher(String algorithm) {
        String primitive = algorithm.split("/", -1)[0];
        return Set.of("DES", "DESEDE", "TRIPLEDES", "RC2", "RC4", "ARCFOUR").contains(primitive)
                || algorithm.contains("/ECB/") || algorithm.endsWith("/ECB");
    }

    private static void evaluateHardcodedKey(ObjectCreationExpr creation, Emitter emitter) {
        String type = simpleName(creation.getType().asString());
        if (!("SecretKeySpec".equals(type) || "PBEKeySpec".equals(type)) || creation.getArguments().isEmpty()) {
            return;
        }
        ExpressionFacts.Fact key = ExpressionFacts.inspect(creation.getArgument(0));
        boolean hardcoded = key.hardcodedBytes()
                || ("PBEKeySpec".equals(type) && key.constant() != null && !key.dynamic());
        if (hardcoded) {
            emitter.emit(HARDCODED_KEY, creation,
                    type + " is constructed from key material embedded in source code");
        }
    }

    private static void evaluateHostnameCall(MethodCallExpr call, Emitter emitter) {
        if (!Set.of("setHostnameVerifier", "setDefaultHostnameVerifier", "hostnameVerifier")
                .contains(call.getNameAsString()) || call.getArguments().isEmpty()) {
            return;
        }
        Expression verifier = call.getArgument(0);
        if (verifier.isLambdaExpr() && alwaysTrue(verifier.asLambdaExpr())) {
            emitter.emit(TRUST_HOSTNAME, verifier,
                    "hostname verifier always returns true and accepts every host");
        }
    }

    private static void evaluateHostnameImplementations(
            CompilationUnit unit, Emitter emitter, AnalysisRunContext context) {
        for (MethodDeclaration method : sorted(unit.findAll(MethodDeclaration.class))) {
            context.checkpoint();
            if (!"verify".equals(method.getNameAsString()) || !returnsOnlyTrue(method)) {
                continue;
            }
            if (insideImplementation(method, "HostnameVerifier")) {
                emitter.emit(TRUST_HOSTNAME, method,
                        "HostnameVerifier.verify always returns true and accepts every host");
            }
        }
    }

    private static void evaluateTrustManagers(
            CompilationUnit unit, Emitter emitter, AnalysisRunContext context) {
        Set<Node> emittedContainers = new HashSet<>();
        for (MethodDeclaration method : sorted(unit.findAll(MethodDeclaration.class))) {
            context.checkpoint();
            if (!("checkClientTrusted".equals(method.getNameAsString())
                    || "checkServerTrusted".equals(method.getNameAsString()))) {
                continue;
            }
            if (method.getBody().isEmpty() || !method.getBody().get().getStatements().isEmpty()) {
                continue;
            }
            Node container = implementationContainer(method, "X509TrustManager");
            if (container != null && emittedContainers.add(container)) {
                emitter.emit(TRUST_X509, method,
                        "X509TrustManager trust checks are empty and accept unverified certificates");
            }
        }
    }

    private static void evaluateXxe(MethodCallExpr call, Emitter emitter) {
        String method = call.getNameAsString();
        if ("setFeature".equals(method) && call.getArguments().size() >= 2) {
            Optional<String> feature = ExpressionFacts.constantString(call.getArgument(0));
            Optional<Boolean> enabled = ExpressionFacts.constantBoolean(call.getArgument(1));
            if (feature.isPresent() && feature.get().length() <= 512 && enabled.isPresent()) {
                String normalized = feature.get().toLowerCase(Locale.ROOT);
                if ((enabled.get() && EXTERNAL_ENTITY_FEATURES.contains(normalized))
                        || (!enabled.get() && DISABLE_DTD_FEATURES.contains(normalized))) {
                    emitter.emit(XXE, call, "XML parser explicitly enables external entity or DTD processing");
                }
            }
            return;
        }
        if (("setExpandEntityReferences".equals(method) || "setXIncludeAware".equals(method))
                && !call.getArguments().isEmpty()
                && ExpressionFacts.constantBoolean(call.getArgument(0)).orElse(false)) {
            emitter.emit(XXE, call, "XML parser explicitly enables external entity expansion");
            return;
        }
        if (("setAttribute".equals(method) || "setProperty".equals(method)) && call.getArguments().size() >= 2) {
            String property = call.getArgument(0).toString().toLowerCase(Locale.ROOT);
            String value = ExpressionFacts.constantString(call.getArgument(1)).orElse("").trim();
            if ((property.contains("access_external_dtd") || property.contains("access_external_schema")
                    || property.contains("accessexternaldtd") || property.contains("accessexternalschema"))
                    && !value.isEmpty()) {
                emitter.emit(XXE, call, "XML parser permits external DTD or schema access");
            }
        }
    }

    private static void evaluateDeserialization(MethodCallExpr call, Emitter emitter) {
        if (!("readObject".equals(call.getNameAsString()) || "readUnshared".equals(call.getNameAsString()))
                || call.getScope().isEmpty()) {
            return;
        }
        Expression scope = call.getScope().get();
        String type = simpleName(ExpressionFacts.declaredType(scope, call));
        boolean objectInput = "ObjectInputStream".equals(type)
                || (scope.isObjectCreationExpr()
                        && "ObjectInputStream".equals(simpleName(scope.asObjectCreationExpr().getType().asString())));
        if (objectInput) {
            emitter.emit(DESERIALIZATION, call,
                    "ObjectInputStream deserializes an object without an evident input filter");
        }
    }

    private static void evaluateSql(MethodCallExpr call, Emitter emitter) {
        if (!SQL_METHODS.contains(call.getNameAsString()) || call.getArguments().isEmpty()) {
            return;
        }
        ExpressionFacts.Fact sql = ExpressionFacts.inspect(call.getArgument(0));
        if (sql.dynamic() && sql.concatenated() && SQL_TEXT.matcher(sql.literalText()).find()) {
            emitter.emit(SQL_INJECTION, call,
                    "SQL text is assembled by concatenating a non-constant value");
        }
    }

    private static void evaluateCommand(MethodCallExpr call, Emitter emitter) {
        if (!"exec".equals(call.getNameAsString()) || call.getArguments().isEmpty()
                || call.getScope().isEmpty()) {
            return;
        }
        Expression scope = call.getScope().get();
        String type = simpleName(ExpressionFacts.declaredType(scope, call));
        boolean runtime = "Runtime".equals(type) || scope.toString().contains("Runtime.getRuntime()");
        if (runtime && ExpressionFacts.inspect(call.getArgument(0)).dynamic()) {
            emitter.emit(COMMAND_INJECTION, call,
                    "Runtime.exec receives a command that is not compile-time constant");
        }
    }

    private static void evaluateProcessBuilder(ObjectCreationExpr creation, Emitter emitter) {
        if (!"ProcessBuilder".equals(simpleName(creation.getType().asString()))
                || creation.getArguments().isEmpty()) {
            return;
        }
        boolean dynamic = creation.getArguments().stream().anyMatch(argument -> ExpressionFacts.inspect(argument).dynamic());
        if (dynamic) {
            emitter.emit(COMMAND_INJECTION, creation,
                    "ProcessBuilder receives a command that is not compile-time constant");
        }
    }

    private static void evaluateDynamicCode(MethodCallExpr call, Emitter emitter) {
        if (call.getArguments().isEmpty() || call.getScope().isEmpty()) {
            return;
        }
        String method = call.getNameAsString();
        Expression scope = call.getScope().get();
        String type = simpleName(ExpressionFacts.declaredType(scope, call));
        String renderedScope = scope.toString();
        int expressionIndex = 0;
        boolean engine = "eval".equals(method)
                && ("ScriptEngine".equals(type) || type.endsWith("ScriptEngine")
                        || renderedScope.contains("getEngineBy"));
        boolean el = Set.of("eval", "createValueExpression", "createMethodExpression").contains(method)
                && (Set.of("ELProcessor", "ExpressionFactory").contains(type)
                        || renderedScope.contains("ExpressionFactory"));
        if ((engine || el) && call.getArguments().size() > expressionIndex
                && ExpressionFacts.inspect(call.getArgument(expressionIndex)).dynamic()) {
            emitter.emit(DYNAMIC_CODE, call,
                    "dynamic script or expression text is evaluated at runtime");
        }
    }

    private static void evaluatePermissions(MethodCallExpr call, Emitter emitter) {
        String method = call.getNameAsString();
        if (Set.of("setReadable", "setWritable", "setExecutable").contains(method)
                && call.getScope().isPresent() && call.getArguments().size() >= 2) {
            String type = simpleName(ExpressionFacts.declaredType(call.getScope().get(), call));
            boolean enable = ExpressionFacts.constantBoolean(call.getArgument(0)).orElse(false);
            boolean ownerOnly = ExpressionFacts.constantBoolean(call.getArgument(1)).orElse(true);
            if ("File".equals(type) && enable && !ownerOnly) {
                emitter.emit(BROAD_PERMISSION, call,
                        "File permission is granted to every user rather than only the owner");
            }
            return;
        }
        if ("fromString".equals(method) && !call.getArguments().isEmpty()
                && call.getScope().map(Object::toString).orElse("").endsWith("PosixFilePermissions")) {
            Optional<String> mode = ExpressionFacts.constantString(call.getArgument(0));
            if (mode.isPresent() && mode.get().length() == 9
                    && (mode.get().charAt(7) == 'w' || mode.get().charAt(8) == 'x')) {
                emitter.emit(BROAD_PERMISSION, call,
                        "POSIX mode grants write or execute permission to other users");
            }
        }
    }

    private static void evaluateCookie(MethodCallExpr call, Emitter emitter) {
        if (!"setSecure".equals(call.getNameAsString()) || call.getArguments().isEmpty()
                || call.getScope().isEmpty()
                || ExpressionFacts.constantBoolean(call.getArgument(0)).orElse(true)) {
            return;
        }
        String type = simpleName(ExpressionFacts.declaredType(call.getScope().get(), call));
        if ("Cookie".equals(type)) {
            emitter.emit(INSECURE_COOKIE, call,
                    "cookie Secure protection is explicitly disabled");
        }
    }

    private static boolean isStaticTypeCall(
            CompilationUnit unit, MethodCallExpr call, String simple, String qualified) {
        if (call.getScope().isEmpty()) {
            return false;
        }
        String scope = call.getScope().get().toString();
        if (qualified.equals(scope)) {
            return true;
        }
        if (!simple.equals(scope)) {
            return false;
        }
        String packageName = qualified.substring(0, qualified.lastIndexOf('.'));
        for (ImportDeclaration imported : unit.getImports()) {
            if ((!imported.isAsterisk() && imported.getNameAsString().equals(qualified))
                    || (imported.isAsterisk() && imported.getNameAsString().equals(packageName))) {
                return true;
            }
        }
        return false;
    }

    private static boolean alwaysTrue(LambdaExpr lambda) {
        Statement body = lambda.getBody();
        if (body.isExpressionStmt()) {
            Expression expression = body.asExpressionStmt().getExpression();
            return expression instanceof BooleanLiteralExpr literal && literal.getValue();
        }
        if (body.isBlockStmt()) {
            return returnsOnlyTrue(body.asBlockStmt());
        }
        return false;
    }

    private static boolean returnsOnlyTrue(MethodDeclaration method) {
        return method.getBody().map(JavaRuleEvaluator::returnsOnlyTrue).orElse(false);
    }

    private static boolean returnsOnlyTrue(BlockStmt body) {
        if (body.getStatements().size() != 1 || !body.getStatement(0).isReturnStmt()) {
            return false;
        }
        ReturnStmt returned = body.getStatement(0).asReturnStmt();
        return returned.getExpression().filter(Expression::isBooleanLiteralExpr)
                .map(Expression::asBooleanLiteralExpr).map(BooleanLiteralExpr::getValue).orElse(false);
    }

    private static boolean insideImplementation(MethodDeclaration method, String interfaceName) {
        return implementationContainer(method, interfaceName) != null;
    }

    private static Node implementationContainer(MethodDeclaration method, String interfaceName) {
        Node current = method.getParentNode().orElse(null);
        while (current != null) {
            if (current instanceof ObjectCreationExpr creation && creation.getAnonymousClassBody().isPresent()) {
                return simpleName(creation.getType().asString()).equals(interfaceName) ? creation : null;
            }
            if (current instanceof ClassOrInterfaceDeclaration declaration) {
                boolean implementsType = declaration.getImplementedTypes().stream()
                        .anyMatch(type -> simpleName(type.asString()).equals(interfaceName));
                return implementsType ? declaration : null;
            }
            if (current instanceof MethodDeclaration || current instanceof ConstructorDeclaration) {
                return null;
            }
            current = current.getParentNode().orElse(null);
        }
        return null;
    }

    private static String simpleName(String type) {
        if (type == null || type.isBlank()) {
            return "";
        }
        String withoutGeneric = type.replaceAll("<.*>", "");
        int dot = Math.max(withoutGeneric.lastIndexOf('.'), withoutGeneric.lastIndexOf('$'));
        return dot >= 0 ? withoutGeneric.substring(dot + 1) : withoutGeneric;
    }

    private static <T extends Node> List<T> sorted(List<T> nodes) {
        nodes.sort(Comparator
                .comparingInt((Node node) -> node.getRange().map(range -> range.begin.line).orElse(Integer.MAX_VALUE))
                .thenComparingInt(node -> node.getRange().map(range -> range.begin.column).orElse(Integer.MAX_VALUE)));
        return nodes;
    }

    private static int compareUtf8(String left, String right) {
        return java.util.Arrays.compareUnsigned(
                left.getBytes(StandardCharsets.UTF_8), right.getBytes(StandardCharsets.UTF_8));
    }

    private static final class Emitter {
        private final SourceFile file;
        private final int capacity;
        private final long byteCapacity;
        private final SnippetExtractor snippets;
        private final Set<String> dedupe = new HashSet<>();
        private final Map<Node, AnalysisResponse.Callable> callableCache = new IdentityHashMap<>();
        private final List<AnalysisResponse.Finding> findings = new ArrayList<>();
        private boolean truncated;
        private long estimatedBytes;

        private Emitter(SourceFile file, int capacity, int maxSnippetBytes, long byteCapacity) {
            this.file = file;
            this.capacity = capacity;
            this.byteCapacity = byteCapacity;
            this.snippets = new SnippetExtractor(file.source(), maxSnippetBytes);
        }

        private void emit(RuleDefinition rule, Node node, String message) {
            Range range = node.getRange().orElse(new Range(new Position(1, 1), new Position(1, 1)));
            String key = rule.ruleId() + ':' + range.begin.line + ':' + range.begin.column;
            if (!dedupe.add(key)) {
                return;
            }
            if (findings.size() >= capacity) {
                truncated = true;
                return;
            }
            SnippetExtractor.Snippet snippet = snippets.extract(range);
            AnalysisResponse.Finding finding = new AnalysisResponse.Finding(
                    rule.ruleId(),
                    rule.cwe(),
                    rule.severity(),
                    Utf8Text.message(message),
                    file.identity(),
                    callable(node),
                    new AnalysisResponse.Location(
                            range.begin.line, range.begin.column, range.end.line, range.end.column),
                    snippet.text(),
                    snippet.startLine());
            long bytes = JsonSize.finding(finding);
            if (bytes > byteCapacity - estimatedBytes) {
                truncated = true;
                return;
            }
            findings.add(finding);
            estimatedBytes += bytes;
        }

        private AnalysisResponse.Callable callable(Node node) {
            Node owner = callableOwner(node);
            return callableCache.computeIfAbsent(owner, ignored -> createCallable(owner, file));
        }
    }

    private static Node callableOwner(Node node) {
        Node current = node;
        while (current != null) {
            if (current instanceof MethodDeclaration || current instanceof ConstructorDeclaration
                    || current instanceof LambdaExpr || current instanceof InitializerDeclaration
                    || current instanceof FieldDeclaration || current instanceof TypeDeclaration<?>) {
                return current;
            }
            current = current.getParentNode().orElse(null);
        }
        return node.findCompilationUnit().map(unit -> (Node) unit).orElse(node);
    }

    private static AnalysisResponse.Callable createCallable(Node owner, SourceFile file) {
        if (owner instanceof MethodDeclaration method) {
            return boundedCallable("method", typeName(method, file), method.getNameAsString(),
                    signature(method.getNameAsString(), method.getParameters()));
        }
        if (owner instanceof ConstructorDeclaration constructor) {
            return boundedCallable("constructor", typeName(constructor, file), constructor.getNameAsString(),
                    signature(constructor.getNameAsString(), constructor.getParameters()));
        }
        if (owner instanceof LambdaExpr lambda) {
            return boundedCallable("lambda", typeName(lambda, file), "<lambda>",
                    "lambda(" + lambda.getParameters().size() + ")");
        }
        if (owner instanceof InitializerDeclaration initializer) {
            String name = initializer.isStatic() ? "<clinit>" : "<init-block>";
            return boundedCallable("initializer", typeName(initializer, file), name, name + "()");
        }
        if (owner instanceof FieldDeclaration field) {
            String name = field.getVariables().isEmpty() ? "<field>" : field.getVariable(0).getNameAsString();
            return boundedCallable("field", typeName(field, file), name,
                    Utf8Text.bound(field.getElementType().asString(), 512, "Object") + " "
                            + Utf8Text.bound(name, 512, "<field>"));
        }
        String typeName = owner instanceof TypeDeclaration<?> declaration
                ? declaration.getNameAsString() : typeName(owner, file);
        return boundedCallable("type", typeName, typeName, typeName);
    }

    private static String signature(String name, Iterable<Parameter> parameters) {
        StringBuilder signature = new StringBuilder();
        signature.append(Utf8Text.bound(name, 512, "<unknown>")).append('(');
        boolean first = true;
        for (Parameter parameter : parameters) {
            if (signature.length() >= 2048) {
                signature.append("...");
                break;
            }
            if (!first) {
                signature.append(", ");
            }
            signature.append(Utf8Text.bound(parameter.getType().asString(), 512, "Object"));
            first = false;
        }
        signature.append(')');
        return Utf8Text.required(signature.toString(), Utf8Text.CALLABLE_SIGNATURE_BYTES, "<unknown>()");
    }

    private static String typeName(Node node, SourceFile file) {
        Node current = node;
        while ((current = current.getParentNode().orElse(null)) != null) {
            if (current instanceof TypeDeclaration<?> declaration
                    && !declaration.getNameAsString().isBlank()) {
                return declaration.getNameAsString();
            }
        }
        return file.metadata().binaryName().isBlank()
                ? file.metadata().logicalPath() : file.metadata().binaryName();
    }

    private static AnalysisResponse.Callable boundedCallable(
            String kind, String typeName, String name, String signature) {
        return new AnalysisResponse.Callable(
                Utf8Text.required(kind, Utf8Text.CALLABLE_KIND_BYTES, "type"),
                Utf8Text.required(typeName, Utf8Text.CALLABLE_TYPE_BYTES, "<unknown-type>"),
                Utf8Text.required(name, Utf8Text.CALLABLE_NAME_BYTES, "<unknown>"),
                Utf8Text.required(signature, Utf8Text.CALLABLE_SIGNATURE_BYTES, "<unknown>()"));
    }
}
