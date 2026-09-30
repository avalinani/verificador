package com.coam.pdfvalidator.api.concurrency;

import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;

import org.springframework.web.filter.OncePerRequestFilter;
import org.springframework.web.servlet.HandlerExceptionResolver;

import java.io.IOException;
import java.util.Locale;

/**
 * Applies {@link AnalysisBulkhead} to every multipart request, as a servlet
 * filter rather than inside the controller: Spring parses (and buffers) the
 * multipart body <em>before</em> the controller runs, so a permit taken in the
 * controller would leave up to {@code threads.max} uploads buffered at once.
 * The filter takes the permit first, so upload buffering and analysis are both
 * bounded, and releases it in {@code finally} when the request completes
 * (normally, by exception, or after a client disconnect).
 *
 * <p><b>Scope is the content type, not the path.</b> Matching the upload URL
 * would be a bypass waiting to happen: the servlet container and Spring MVC
 * accept many spellings of one route (path parameters {@code ;x=y},
 * percent-encoding, duplicate or dot segments, trailing slash, context path),
 * and any spelling missed here would buffer and analyze without a permit.
 * Deciding on {@code multipart/*} instead fails safe: whatever path a
 * multipart body is sent to, it is counted. The only multipart endpoint is the
 * analysis upload, so nothing else is affected.
 *
 * <p>A saturated bulkhead is reported through the {@link
 * HandlerExceptionResolver} chain so the same {@code @RestControllerAdvice}
 * machinery that formats every other API error produces the 503 body. The
 * rejected request's body is never read, so the response carries {@code
 * Connection: close}: the container then drops the connection instead of
 * trying to drain up to 80 MB the client may still be sending.
 */
public class AnalysisBulkheadFilter extends OncePerRequestFilter {

    private final AnalysisBulkhead bulkhead;
    private final HandlerExceptionResolver exceptionResolver;

    public AnalysisBulkheadFilter(AnalysisBulkhead bulkhead, HandlerExceptionResolver exceptionResolver) {
        this.bulkhead = bulkhead;
        this.exceptionResolver = exceptionResolver;
    }

    @Override
    protected boolean shouldNotFilter(HttpServletRequest request) {
        String contentType = request.getContentType();
        return contentType == null || !contentType.toLowerCase(Locale.ROOT).startsWith("multipart/");
    }

    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain chain)
            throws ServletException, IOException {
        AnalysisBulkhead.Permit permit;
        try {
            permit = bulkhead.acquire();
        } catch (AnalysisBusyException busy) {
            response.setHeader("Connection", "close");
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
