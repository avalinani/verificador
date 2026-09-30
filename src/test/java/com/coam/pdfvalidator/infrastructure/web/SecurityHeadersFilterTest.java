package com.coam.pdfvalidator.infrastructure.web;

import org.junit.jupiter.api.Test;
import org.springframework.mock.web.MockFilterChain;
import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.mock.web.MockHttpServletResponse;

import static org.assertj.core.api.Assertions.assertThat;

/** T18d: every response, whatever the path or method, carries nosniff and a no-referrer policy. */
class SecurityHeadersFilterTest {

    private final SecurityHeadersFilter filter = new SecurityHeadersFilter();

    @Test
    void addsNosniffAndNoReferrerToAnyPath() throws Exception {
        for (String path : new String[] {"/", "/api/v1/pdf/analyze", "/actuator/health", "/v3/api-docs", "/nope"}) {
            MockHttpServletResponse response = new MockHttpServletResponse();
            filter.doFilter(new MockHttpServletRequest("GET", path), response, new MockFilterChain());

            assertThat(response.getHeader("X-Content-Type-Options")).as(path).isEqualTo("nosniff");
            assertThat(response.getHeader("Referrer-Policy")).as(path).isEqualTo("no-referrer");
        }
    }

    @Test
    void theHeadersAreAlreadySetWhenTheChainRuns() throws Exception {
        MockHttpServletResponse response = new MockHttpServletResponse();
        String[] seen = new String[2];

        filter.doFilter(new MockHttpServletRequest("POST", "/api/v1/pdf/analyze"), response,
                (req, res) -> {
                    var http = (jakarta.servlet.http.HttpServletResponse) res;
                    seen[0] = http.getHeader("X-Content-Type-Options");
                    seen[1] = http.getHeader("Referrer-Policy");
                });

        assertThat(seen).containsExactly("nosniff", "no-referrer");
    }
}
