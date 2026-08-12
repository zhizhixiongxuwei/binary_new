package com.binaryscan.javachecker.engine;

import static org.assertj.core.api.Assertions.assertThat;

import java.util.function.Function;

import org.junit.jupiter.api.Test;

import com.github.javaparser.StaticJavaParser;
import com.github.javaparser.ast.expr.MethodCallExpr;

class ExpressionFactsTest {
    @Test
    void resolvesParametersLocalAliasesAndDeclaredReceiverTypes() {
        var unit = StaticJavaParser.parse("""
                class Sample {
                  void run(String user, java.io.InputStream raw) throws Exception {
                    java.io.ObjectInputStream input = new java.io.ObjectInputStream(raw);
                    input.readObject();
                    java.sql.Statement statement = null;
                    String sql = "SELECT * FROM users WHERE name=" + user;
                    statement.executeQuery(sql);
                    java.io.File file = null;
                    file.setWritable(true, false);
                  }
                }
                """);
        Function<String, MethodCallExpr> named = name -> unit.findAll(MethodCallExpr.class).stream()
                .filter(call -> call.getNameAsString().equals(name)).findFirst().orElseThrow();

        MethodCallExpr read = named.apply("readObject");
        assertThat(ExpressionFacts.declaredType(read.getScope().orElseThrow(), read))
                .isEqualTo("java.io.ObjectInputStream");
        MethodCallExpr query = named.apply("executeQuery");
        ExpressionFacts.Fact sql = ExpressionFacts.inspect(query.getArgument(0));
        assertThat(sql.dynamic()).isTrue();
        assertThat(sql.concatenated()).isTrue();
        assertThat(sql.literalText()).containsIgnoringCase("select");
        MethodCallExpr permission = named.apply("setWritable");
        assertThat(ExpressionFacts.declaredType(permission.getScope().orElseThrow(), permission))
                .isEqualTo("java.io.File");
    }
}
