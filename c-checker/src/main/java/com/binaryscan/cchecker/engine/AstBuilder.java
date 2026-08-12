package com.binaryscan.cchecker.engine;

import java.util.ArrayList;
import java.util.List;

import org.antlr.v4.runtime.CommonTokenStream;
import org.antlr.v4.runtime.ParserRuleContext;

import com.binaryscan.cchecker.grammar.CBaseListener;
import com.binaryscan.cchecker.grammar.CParser;
import com.binaryscan.cchecker.service.AnalysisRunContext;

final class AstBuilder extends CBaseListener {
    private final CommonTokenStream tokens;
    private final AnalysisRunContext context;
    private final List<CParser.DeclarationContext> declarations = new ArrayList<>();
    private final List<CParser.PostfixExpressionContext> postfixExpressions = new ArrayList<>();
    private final List<CParser.AssignmentExpressionContext> assignments = new ArrayList<>();
    private final List<CParser.MultiplicativeExpressionContext> multiplicativeExpressions = new ArrayList<>();
    private final List<CParser.JumpStatementContext> jumps = new ArrayList<>();

    AstBuilder(CommonTokenStream tokens, AnalysisRunContext context) {
        this.tokens = tokens;
        this.context = context;
    }

    @Override
    public void enterEveryRule(ParserRuleContext ignored) {
        context.checkpoint();
    }

    @Override
    public void enterDeclaration(CParser.DeclarationContext context) {
        declarations.add(context);
    }

    @Override
    public void enterPostfixExpression(CParser.PostfixExpressionContext context) {
        postfixExpressions.add(context);
    }

    @Override
    public void enterAssignmentExpression(CParser.AssignmentExpressionContext context) {
        assignments.add(context);
    }

    @Override
    public void enterMultiplicativeExpression(CParser.MultiplicativeExpressionContext context) {
        multiplicativeExpressions.add(context);
    }

    @Override
    public void enterJumpStatement(CParser.JumpStatementContext context) {
        jumps.add(context);
    }

    FunctionAst build() {
        return new FunctionAst(
                tokens,
                List.copyOf(declarations),
                List.copyOf(postfixExpressions),
                List.copyOf(assignments),
                List.copyOf(multiplicativeExpressions),
                List.copyOf(jumps));
    }
}
