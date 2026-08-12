package com.binaryscan.javachecker.engine;

import java.util.ArrayList;
import java.util.Comparator;
import java.util.HashSet;
import java.util.List;
import java.util.Locale;
import java.util.Optional;
import java.util.Set;

import com.binaryscan.javachecker.service.Utf8Text;

import com.github.javaparser.Position;
import com.github.javaparser.ast.Node;
import com.github.javaparser.ast.body.CallableDeclaration;
import com.github.javaparser.ast.body.Parameter;
import com.github.javaparser.ast.body.VariableDeclarator;
import com.github.javaparser.ast.expr.ArrayCreationExpr;
import com.github.javaparser.ast.expr.ArrayInitializerExpr;
import com.github.javaparser.ast.expr.AssignExpr;
import com.github.javaparser.ast.expr.BinaryExpr;
import com.github.javaparser.ast.expr.BooleanLiteralExpr;
import com.github.javaparser.ast.expr.CastExpr;
import com.github.javaparser.ast.expr.CharLiteralExpr;
import com.github.javaparser.ast.expr.ConditionalExpr;
import com.github.javaparser.ast.expr.EnclosedExpr;
import com.github.javaparser.ast.expr.Expression;
import com.github.javaparser.ast.expr.IntegerLiteralExpr;
import com.github.javaparser.ast.expr.LongLiteralExpr;
import com.github.javaparser.ast.expr.MethodCallExpr;
import com.github.javaparser.ast.expr.NameExpr;
import com.github.javaparser.ast.expr.NullLiteralExpr;
import com.github.javaparser.ast.expr.StringLiteralExpr;
import com.github.javaparser.ast.expr.UnaryExpr;

final class ExpressionFacts {
    record Fact(String constant, String literalText, boolean dynamic, boolean concatenated, boolean hardcodedBytes) {
        static Fact unknown() {
            return new Fact(null, "", true, false, false);
        }

        static Fact constant(String value) {
            return new Fact(value, value == null ? "" : Utf8Text.bound(value, 4096, ""),
                    false, false, false);
        }
    }

    private ExpressionFacts() {
    }

    static Fact inspect(Expression expression) {
        Node callable = enclosingCallable(expression);
        return inspect(expression, callable, expression, new HashSet<>(), 0);
    }

    static Optional<String> constantString(Expression expression) {
        return Optional.ofNullable(inspect(expression).constant());
    }

    static Optional<Boolean> constantBoolean(Expression expression) {
        if (expression.isBooleanLiteralExpr()) {
            return Optional.of(expression.asBooleanLiteralExpr().getValue());
        }
        Fact fact = inspect(expression);
        if ("true".equals(fact.constant())) {
            return Optional.of(true);
        }
        if ("false".equals(fact.constant())) {
            return Optional.of(false);
        }
        return Optional.empty();
    }

    static String declaredType(Expression scope, Node use) {
        if (scope.isObjectCreationExpr()) {
            return scope.asObjectCreationExpr().getType().asString();
        }
        if (scope.isCastExpr()) {
            return scope.asCastExpr().getType().asString();
        }
        if (!scope.isNameExpr()) {
            return "";
        }
        String name = scope.asNameExpr().getNameAsString();
        Node callable = enclosingCallable(use);
        if (callable == null) {
            return "";
        }
        for (Parameter parameter : callable.findAll(Parameter.class)) {
            if (parameter.getNameAsString().equals(name) && sameCallable(parameter, callable)) {
                return parameter.getType().asString();
            }
        }
        return callable.findAll(VariableDeclarator.class).stream()
                .filter(variable -> variable.getNameAsString().equals(name))
                .filter(variable -> sameCallable(variable, callable))
                .filter(variable -> before(variable, use))
                .max(Comparator.comparing(ExpressionFacts::begin))
                .map(variable -> variable.getType().asString())
                .orElse("");
    }

    private static Fact inspect(
            Expression expression,
            Node callable,
            Node use,
            Set<String> resolving,
            int depth) {
        if (depth > 24) {
            return Fact.unknown();
        }
        if (expression instanceof StringLiteralExpr literal) {
            return Fact.constant(literal.asString());
        }
        if (expression instanceof CharLiteralExpr literal) {
            return Fact.constant(literal.getValue());
        }
        if (expression instanceof BooleanLiteralExpr literal) {
            return Fact.constant(Boolean.toString(literal.getValue()));
        }
        if (expression instanceof IntegerLiteralExpr
                || expression instanceof LongLiteralExpr
                || expression instanceof NullLiteralExpr) {
            return Fact.constant(expression.toString());
        }
        if (expression instanceof EnclosedExpr enclosed) {
            return inspect(enclosed.getInner(), callable, use, resolving, depth + 1);
        }
        if (expression instanceof CastExpr cast) {
            return inspect(cast.getExpression(), callable, use, resolving, depth + 1);
        }
        if (expression instanceof UnaryExpr unary) {
            Fact inner = inspect(unary.getExpression(), callable, use, resolving, depth + 1);
            return inner.constant() == null
                    ? inner
                    : new Fact(unary.getOperator().asString() + inner.constant(), inner.literalText(),
                            inner.dynamic(), inner.concatenated(), inner.hardcodedBytes());
        }
        if (expression instanceof BinaryExpr binary) {
            Fact left = inspect(binary.getLeft(), callable, use, resolving, depth + 1);
            Fact right = inspect(binary.getRight(), callable, use, resolving, depth + 1);
            boolean plus = binary.getOperator() == BinaryExpr.Operator.PLUS;
            String constant = plus && left.constant() != null && right.constant() != null
                    ? concatenateConstant(left.constant(), right.constant()) : null;
            return new Fact(
                    constant,
                    join(left.literalText(), right.literalText()),
                    left.dynamic() || right.dynamic() || constant == null,
                    plus && (!left.literalText().isEmpty() || !right.literalText().isEmpty()),
                    left.hardcodedBytes() && right.hardcodedBytes());
        }
        if (expression instanceof ConditionalExpr conditional) {
            Fact thenFact = inspect(conditional.getThenExpr(), callable, use, resolving, depth + 1);
            Fact elseFact = inspect(conditional.getElseExpr(), callable, use, resolving, depth + 1);
            String constant = thenFact.constant() != null && thenFact.constant().equals(elseFact.constant())
                    ? thenFact.constant()
                    : null;
            return new Fact(constant, join(thenFact.literalText(), elseFact.literalText()),
                    thenFact.dynamic() || elseFact.dynamic() || constant == null,
                    thenFact.concatenated() || elseFact.concatenated(),
                    thenFact.hardcodedBytes() && elseFact.hardcodedBytes());
        }
        if (expression instanceof NameExpr name) {
            return resolveName(name.getNameAsString(), callable, use, resolving, depth + 1);
        }
        if (expression instanceof ArrayInitializerExpr initializer) {
            boolean allConstant = true;
            StringBuilder literals = new StringBuilder();
            for (Expression value : initializer.getValues()) {
                Fact fact = inspect(value, callable, use, resolving, depth + 1);
                allConstant &= fact.constant() != null && !fact.dynamic();
                literals.append(fact.literalText());
            }
            return new Fact(null, literals.toString(), !allConstant, false, allConstant);
        }
        if (expression instanceof ArrayCreationExpr array && array.getInitializer().isPresent()) {
            Fact fact = inspect(array.getInitializer().get(), callable, use, resolving, depth + 1);
            return new Fact(null, fact.literalText(), fact.dynamic(), false, fact.hardcodedBytes());
        }
        if (expression instanceof MethodCallExpr call) {
            String method = call.getNameAsString();
            if (("getBytes".equals(method) || "toCharArray".equals(method)) && call.getScope().isPresent()) {
                Fact scope = inspect(call.getScope().get(), callable, use, resolving, depth + 1);
                return new Fact(null, scope.literalText(), scope.dynamic(), scope.concatenated(),
                        scope.constant() != null && !scope.dynamic());
            }
            if (("decode".equals(method) || "parseHexBinary".equals(method)) && !call.getArguments().isEmpty()) {
                Fact argument = inspect(call.getArgument(0), callable, use, resolving, depth + 1);
                return new Fact(null, argument.literalText(), argument.dynamic(), argument.concatenated(),
                        argument.constant() != null && !argument.dynamic());
            }
            if ("format".equals(method) && !call.getArguments().isEmpty()) {
                Fact format = inspect(call.getArgument(0), callable, use, resolving, depth + 1);
                boolean dynamic = false;
                for (int i = 1; i < call.getArguments().size(); i++) {
                    dynamic |= inspect(call.getArgument(i), callable, use, resolving, depth + 1).dynamic();
                }
                return new Fact(null, format.literalText(), dynamic, call.getArguments().size() > 1, false);
            }
            return Fact.unknown();
        }
        return Fact.unknown();
    }

    private static Fact resolveName(
            String name,
            Node callable,
            Node use,
            Set<String> resolving,
            int depth) {
        if (callable == null || !resolving.add(name)) {
            return Fact.unknown();
        }
        try {
            for (Parameter parameter : callable.findAll(Parameter.class)) {
                if (parameter.getNameAsString().equals(name) && sameCallable(parameter, callable)) {
                    return Fact.unknown();
                }
            }

            List<Definition> definitions = new ArrayList<>();
            for (VariableDeclarator variable : callable.findAll(VariableDeclarator.class)) {
                if (variable.getNameAsString().equals(name) && sameCallable(variable, callable)
                        && variable.getInitializer().isPresent() && before(variable, use)) {
                    definitions.add(new Definition(variable, variable.getInitializer().get()));
                }
            }
            for (AssignExpr assignment : callable.findAll(AssignExpr.class)) {
                if (assignment.getOperator() == AssignExpr.Operator.ASSIGN
                        && assignment.getTarget().isNameExpr()
                        && assignment.getTarget().asNameExpr().getNameAsString().equals(name)
                        && sameCallable(assignment, callable) && before(assignment, use)) {
                    definitions.add(new Definition(assignment, assignment.getValue()));
                }
            }
            return definitions.stream()
                    .max(Comparator.comparing(definition -> begin(definition.node())))
                    .map(definition -> inspect(definition.value(), callable, definition.node(), resolving, depth + 1))
                    .orElseGet(Fact::unknown);
        } finally {
            resolving.remove(name);
        }
    }

    private static Node enclosingCallable(Node node) {
        Node current = node;
        while ((current = current.getParentNode().orElse(null)) != null) {
            if (current instanceof CallableDeclaration<?> || current instanceof com.github.javaparser.ast.expr.LambdaExpr
                    || current instanceof com.github.javaparser.ast.body.InitializerDeclaration) {
                return current;
            }
        }
        return null;
    }

    private static boolean sameCallable(Node node, Node callable) {
        return enclosingCallable(node) == callable;
    }

    private static boolean before(Node candidate, Node use) {
        return begin(candidate).compareTo(begin(use)) < 0;
    }

    private static Position begin(Node node) {
        return node.getRange().map(range -> range.begin).orElse(new Position(Integer.MAX_VALUE, Integer.MAX_VALUE));
    }

    private static String join(String left, String right) {
        if (left.isEmpty()) {
            return right;
        }
        if (right.isEmpty()) {
            return left;
        }
        return Utf8Text.bound(left, 2048, "") + " " + Utf8Text.bound(right, 2048, "");
    }

    private static String concatenateConstant(String left, String right) {
        if (left.length() + right.length() <= 4096) {
            return left + right;
        }
        // The NUL marker preserves "known constant" without allowing the
        // truncated prefix to equal a security-sensitive configuration value.
        return Utf8Text.bound(left, 2048, "") + Utf8Text.bound(right, 2048, "") + '\0';
    }

    private record Definition(Node node, Expression value) {
    }
}
