package com.coam.pdfvalidator.infrastructure.config;

import com.coam.pdfvalidator.infrastructure.web.CspHeaderFilter;

import org.springframework.boot.web.servlet.FilterRegistrationBean;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;

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
}
