package com.coam.pdfvalidator.api.concurrency;

import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;

import org.springframework.web.filter.OncePerRequestFilter;
import org.springframework.web.servlet.HandlerExceptionResolver;

import java.io.IOException;

/**
 * Applies {@link AnalysisBulkhead} to {@code POST /api/v1/pdf/analyze} as a
 * servlet filter rather than inside the controller: Spring parses (and
 * buffers) the multipart body <em>before</em> the controller runs, so a permit
 * taken in the controller would leave up to {@code threads.max} uploads
 * buffered at once. The filter takes the permit first, so upload buffering and
 * analysis are both bounded, and releases it in {@code finally} when the
 * request completes (normally, by exception, or after a client disconnect).
 *
 * <p>A saturated bulkhead is reported through the {@link
 * HandlerExceptionResolver} chain so the same {@code @RestControllerAdvice}
 * machinery that formats every other API error produces the 503 body.
 */
public class AnalysisBulkheadFilter extends OncePerRequestFilter {

    static final String ANALYZE_PATH = "/api/v1/pdf/analyze";

    private final AnalysisBulkhead bulkhead;
    private final HandlerExceptionResolver exceptionResolver;

    public AnalysisBulkheadFilter(AnalysisBulkhead bulkhead, HandlerExceptionResolver exceptionResolver) {
        this.bulkhead = bulkhead;
        this.exceptionResolver = exceptionResolver;
    }

    @Override
    protected boolean shouldNotFilter(HttpServletRequest request) {
        return !"POST".equalsIgnoreCase(request.getMethod()) || !ANALYZE_PATH.equals(request.getRequestURI());
    }

    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain chain)
            throws ServletException, IOException {
        AnalysisBulkhead.Permit permit;
        try {
            permit = bulkhead.acquire();
        } catch (AnalysisBusyException busy) {
            exceptionResolver.resolveException(request, response, null, busy);
            return;
        }
        try {
            chain.doFilter(request, response);
        } finally {
            permit.close();
        }
    }
}
