package com.coam.pdfvalidator.infrastructure.web;

import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;

import org.springframework.web.filter.OncePerRequestFilter;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.util.Set;

/**
 * Adds a Content-Security-Policy header, and forces the UTF-8 response
 * encoding, on the static "Validar" web UI only (T11 -- README section on
 * the web interface): {@code /}, {@code /index.html}, {@code /app.js} and
 * {@code /styles.css}. Every other request (the REST API, Swagger UI,
 * Actuator, ...) passes through unmodified.
 *
 * <p><b>Why the exact-path check lives inside the filter, not in its URL
 * pattern registration</b>: a servlet {@code url-pattern} of {@code "/"} is
 * specified by the Servlet spec as the <em>default</em> mapping -- it
 * matches every request, not just the literal root path. Registering this
 * filter under {@code "/*"} and deciding per-request here (instead of
 * relying on the registration's own pattern matching for the root path)
 * avoids that footgun while still reaching every candidate path.
 *
 * <p>The report itself contains PDF-derived, attacker-controlled strings
 * (README section on rendering server strings with {@code textContent}
 * only), so this header is defense in depth on top of that -- it never runs
 * inline scripts or styles, loads nothing from a CDN, and disallows framing
 * this page from another origin.
 *
 * <p><b>Why the charset is forced here, and not with the global
 * {@code spring.servlet.encoding.force} property</b>: that property applies
 * to every response, including the JSON API (its tests assert a bare
 * {@code application/json} content type, without a charset parameter).
 * {@link HttpServletResponse#setCharacterEncoding(String)} must be called
 * before the resource handler calls {@code setContentType(...)} for the
 * charset to survive into the final {@code Content-Type} header -- which is
 * exactly the case here, since this filter runs upstream of it -- so this
 * stays scoped to the same four static-UI paths as the CSP header, without
 * touching the API's response encoding at all.
 */
public final class CspHeaderFilter extends OncePerRequestFilter {

    private static final Set<String> PROTECTED_PATHS = Set.of("/", "/index.html", "/app.js", "/styles.css");

    private static final String POLICY = "default-src 'self'; img-src 'self' data:; style-src 'self'; "
            + "script-src 'self'; object-src 'none'; base-uri 'none'; frame-ancestors 'none'";

    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain filterChain)
            throws ServletException, IOException {
        // T11c: getRequestURI() already includes the context path (e.g.
        // "/pdfvalidator/app.js" when deployed under "/pdfvalidator"), so
        // comparing it unchanged against PROTECTED_PATHS silently stopped
        // matching as soon as the app was deployed under a context path.
        String contextRelativePath = request.getRequestURI().substring(request.getContextPath().length());
        if (PROTECTED_PATHS.contains(contextRelativePath)) {
            response.setHeader("Content-Security-Policy", POLICY);
            response.setCharacterEncoding(StandardCharsets.UTF_8.name());
        }
        filterChain.doFilter(request, response);
    }
}
