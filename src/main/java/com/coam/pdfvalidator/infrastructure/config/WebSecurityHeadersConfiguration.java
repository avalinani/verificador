package com.coam.pdfvalidator.infrastructure.config;

import com.coam.pdfvalidator.infrastructure.web.CspHeaderFilter;
import com.coam.pdfvalidator.infrastructure.web.SecurityHeadersFilter;

import org.springframework.boot.web.servlet.FilterRegistrationBean;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.Ordered;

/**
 * Registers {@link CspHeaderFilter} against every request path ({@code
 * "/*"}); the filter itself only ever sets the header for its own narrow
 * allow-list of static UI paths -- see that class's Javadoc for why the
 * exact-path check lives there instead of in this registration's URL
 * pattern.
 */
@Configuration
public class WebSecurityHeadersConfiguration {

    @Bean
    public FilterRegistrationBean<CspHeaderFilter> cspHeaderFilter() {
        FilterRegistrationBean<CspHeaderFilter> registration = new FilterRegistrationBean<>(new CspHeaderFilter());
        registration.addUrlPatterns("/*");
        registration.setName("cspHeaderFilter");
        return registration;
    }

    /**
     * {@link SecurityHeadersFilter} on every path, ahead of every other
     * filter (including the bulkhead) so even short-circuited responses
     * carry the headers.
     */
    @Bean
    public FilterRegistrationBean<SecurityHeadersFilter> securityHeadersFilter() {
        FilterRegistrationBean<SecurityHeadersFilter> registration =
                new FilterRegistrationBean<>(new SecurityHeadersFilter());
        registration.addUrlPatterns("/*");
        registration.setName("securityHeadersFilter");
        registration.setOrder(Ordered.HIGHEST_PRECEDENCE);
        return registration;
    }
}
