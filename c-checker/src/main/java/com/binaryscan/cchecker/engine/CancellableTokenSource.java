package com.binaryscan.cchecker.engine;

import org.antlr.v4.runtime.CharStream;
import org.antlr.v4.runtime.Token;
import org.antlr.v4.runtime.TokenFactory;
import org.antlr.v4.runtime.TokenSource;

import com.binaryscan.cchecker.service.AnalysisRunContext;

final class CancellableTokenSource implements TokenSource {
    private final TokenSource delegate;
    private final AnalysisRunContext context;

    CancellableTokenSource(TokenSource delegate, AnalysisRunContext context) {
        this.delegate = delegate;
        this.context = context;
    }

    @Override
    public Token nextToken() {
        context.checkpoint();
        return delegate.nextToken();
    }

    @Override
    public int getLine() {
        return delegate.getLine();
    }

    @Override
    public int getCharPositionInLine() {
        return delegate.getCharPositionInLine();
    }

    @Override
    public CharStream getInputStream() {
        return delegate.getInputStream();
    }

    @Override
    public String getSourceName() {
        return delegate.getSourceName();
    }

    @Override
    public void setTokenFactory(TokenFactory<?> factory) {
        delegate.setTokenFactory(factory);
    }

    @Override
    public TokenFactory<?> getTokenFactory() {
        return delegate.getTokenFactory();
    }
}
