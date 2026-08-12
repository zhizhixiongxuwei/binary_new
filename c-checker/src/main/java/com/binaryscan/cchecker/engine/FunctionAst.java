package com.binaryscan.cchecker.engine;

import java.util.List;

import org.antlr.v4.runtime.CommonTokenStream;

import com.binaryscan.cchecker.grammar.CParser;

public record FunctionAst(
        CommonTokenStream tokens,
        List<CParser.DeclarationContext> declarations,
        List<CParser.PostfixExpressionContext> postfixExpressions,
        List<CParser.AssignmentExpressionContext> assignments,
        List<CParser.MultiplicativeExpressionContext> multiplicativeExpressions,
        List<CParser.JumpStatementContext> jumps) {
}
