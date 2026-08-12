package com.binaryscan.cchecker.engine;

import org.antlr.v4.runtime.ParserRuleContext;
import org.antlr.v4.runtime.TokenStream;

import com.binaryscan.cchecker.grammar.CParser;
import com.binaryscan.cchecker.service.AnalysisRunContext;

final class CancellableCParser extends CParser {
    private final AnalysisRunContext context;

    CancellableCParser(TokenStream input, AnalysisRunContext context) {
        super(input);
        this.context = context;
    }

    @Override
    public void enterRule(ParserRuleContext localContext, int state, int ruleIndex) {
        context.checkpoint();
        super.enterRule(localContext, state, ruleIndex);
    }
}
