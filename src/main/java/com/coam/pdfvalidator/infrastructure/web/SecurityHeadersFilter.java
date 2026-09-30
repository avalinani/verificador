package com.coam.pdfvalidator.infrastructure.web;

import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;

import org.springframework.web.filter.OncePerRequestFilter;

import java.io.IOException;

/**
 * Adds baseline hardening headers to <b>every</b> response (UI, API, errors,
 * Actuator, Swagger) -- T18d:
 * <ul>
 *   <li>{@code X-Content-Type-Options: nosniff} so browsers never
 *       MIME-sniff a response into an executable type;</li>
 *   <li>{@code Referrer-Policy: no-referrer} so no URL leaks to third
 *       parties.</li>
 * </ul>
 * The headers are set before the chain runs, so short-circuited responses
 * (the 503 of the bulkhead, the 413 of the upload limit) carry them too.
 * {@code X-Frame-Options} is deliberately not added: the UI's CSP already
 * sends {@code frame-ancestors 'none'} ({@link CspHeaderFilter}), which every
 * browser this UI supports honors, and the API returns no framable page.
 */
public final class SecurityHeadersFilter extends OncePerRequestFilter {

    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain filterChain)
            throws ServletException, IOException {
        response.setHeader("X-Content-Type-Options", "nosniff");
        response.setHeader("Referrer-Policy", "no-referrer");
        filterChain.doFilter(request, response);
    }
}
