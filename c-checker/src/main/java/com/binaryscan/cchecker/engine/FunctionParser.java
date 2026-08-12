package com.binaryscan.cchecker.engine;

import java.util.List;

import org.antlr.v4.runtime.CharStreams;
import org.antlr.v4.runtime.CommonTokenStream;
import org.antlr.v4.runtime.tree.ParseTreeWalker;
import org.springframework.stereotype.Component;

import com.binaryscan.cchecker.grammar.CLexer;
import com.binaryscan.cchecker.grammar.CParser;
import com.binaryscan.cchecker.service.AnalysisRunContext;
import com.binaryscan.cchecker.service.CheckerLimits;
import com.binaryscan.cchecker.service.FunctionSlice;

@Component
public class FunctionParser {
    private final FunctionRuleEvaluator evaluator;
    private final CheckerLimits limits;

    public FunctionParser(FunctionRuleEvaluator evaluator, CheckerLimits limits) {
        this.evaluator = evaluator;
        this.limits = limits;
    }

    public FunctionParseResult parse(FunctionSlice function, AnalysisRunContext context, int findingCapacity) {
        context.checkpoint();
        CLexer lexer = new CLexer(CharStreams.fromString(function.source(), function.identity().name()));
        SyntaxDiagnosticListener errors = new SyntaxDiagnosticListener(function, context, limits.maxDiagnostics() + 1);
        lexer.removeErrorListeners();
        lexer.addErrorListener(errors);

        CommonTokenStream tokens = new CommonTokenStream(new CancellableTokenSource(lexer, context));
        CParser parser = new CancellableCParser(tokens, context);
        parser.removeErrorListeners();
        parser.addErrorListener(errors);
        parser.setBuildParseTree(true);

        CParser.CompilationUnitContext tree = parser.compilationUnit();
        context.checkpoint();
        if (errors.errorCount() > 0) {
            return new FunctionParseResult(false, errors.diagnostics(), List.of(), false);
        }

        AstBuilder builder = new AstBuilder(tokens, context);
        ParseTreeWalker.DEFAULT.walk(builder, tree);
        RuleEvaluation evaluation = evaluator.evaluate(builder.build(), function, context, findingCapacity);
        return new FunctionParseResult(
                true,
                errors.diagnostics(),
                evaluation.findings(),
                evaluation.truncated());
    }
}
