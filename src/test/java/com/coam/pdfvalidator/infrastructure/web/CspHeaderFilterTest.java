package com.coam.pdfvalidator.infrastructure.web;

import org.junit.jupiter.api.Test;

import org.springframework.mock.web.MockFilterChain;
import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.mock.web.MockHttpServletResponse;

import java.io.IOException;

import jakarta.servlet.ServletException;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * {@link CspHeaderFilter} unit-tested directly (not through {@code MockMvc},
 * which always runs with an empty context path) -- T11c: the filter's
 * exact-path allow-list previously compared against {@code
 * request.getRequestURI()} unchanged, which already includes the context
 * path, so the filter silently stopped protecting the static UI as soon as
 * the application was deployed under one (e.g. {@code /pdfvalidator}). Fixed
 * to compare against the URI with the context path stripped.
 */
class CspHeaderFilterTest {

    private final CspHeaderFilter filter = new CspHeaderFilter();

    @Test
    void theCspHeaderIsAppliedToTheWelcomePageWithNoContextPath() throws ServletException, IOException {
        MockHttpServletResponse response = filterRequest("", "/");

        assertThat(response.getHeader("Content-Security-Policy")).isNotNull();
    }

    @Test
    void theCspHeaderIsAppliedToAppJsWhenDeployedUnderAContextPath() throws ServletException, IOException {
        MockHttpServletResponse response = filterRequest("/pdfvalidator", "/pdfvalidator/app.js");

        assertThat(response.getHeader("Content-Security-Policy")).isNotNull();
    }

    @Test
    void theCspHeaderIsAppliedToTheWelcomePageWhenDeployedUnderAContextPath() throws ServletException, IOException {
        MockHttpServletResponse response = filterRequest("/pdfvalidator", "/pdfvalidator/");

        assertThat(response.getHeader("Content-Security-Policy")).isNotNull();
    }

    @Test
    void anUnrelatedPathUnderTheSameContextPathIsNotAffected() throws ServletException, IOException {
        MockHttpServletResponse response = filterRequest("/pdfvalidator", "/pdfvalidator/v3/api-docs");

        assertThat(response.getHeader("Content-Security-Policy")).isNull();
    }

    private MockHttpServletResponse filterRequest(String contextPath, String requestUri)
            throws ServletException, IOException {
        MockHttpServletRequest request = new MockHttpServletRequest("GET", requestUri);
        request.setContextPath(contextPath);
        MockHttpServletResponse response = new MockHttpServletResponse();

        filter.doFilter(request, response, new MockFilterChain());

        return response;
    }
}
