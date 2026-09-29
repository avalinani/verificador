package com.coam.pdfvalidator;

import com.coam.pdfvalidator.api.concurrency.AnalysisBulkhead;
import com.coam.pdfvalidator.api.concurrency.AnalysisBulkheadFilter;
import com.coam.pdfvalidator.infrastructure.config.AnalysisProperties;

import org.springframework.beans.factory.annotation.Qualifier;
import org.springframework.boot.context.properties.EnableConfigurationProperties;
import org.springframework.boot.web.servlet.FilterRegistrationBean;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.Ordered;
import org.springframework.web.servlet.HandlerExceptionResolver;

/**
 * Composition root for the analysis bulkhead (T12c). Lives outside the four
 * architecture layers (like {@link UseCaseConfiguration}) because it wires an
 * {@code api} class with {@code infrastructure.config} properties. The filter
 * is registered here, not as a {@code @Component}, so {@code @WebMvcTest}
 * slices are not affected by it.
 */
@Configuration
@EnableConfigurationProperties(AnalysisProperties.class)
public class ConcurrencyConfiguration {

    @Bean
    public AnalysisBulkhead analysisBulkhead(AnalysisProperties properties) {
        return new AnalysisBulkhead(properties.maxConcurrent(), properties.acquireTimeout());
    }

    @Bean
    public FilterRegistrationBean<AnalysisBulkheadFilter> analysisBulkheadFilter(
            AnalysisBulkhead bulkhead,
            @Qualifier("handlerExceptionResolver") HandlerExceptionResolver exceptionResolver) {
        FilterRegistrationBean<AnalysisBulkheadFilter> registration =
                new FilterRegistrationBean<>(new AnalysisBulkheadFilter(bulkhead, exceptionResolver));
        // Every path: the filter itself selects multipart requests (see its Javadoc).
        registration.addUrlPatterns("/*");
        // Early, so a rejection costs almost nothing, but after HIGHEST_PRECEDENCE itself so
        // any filter that must run first can be ordered ahead of it. It must stay before
        // Spring's multipart handling, which happens in the dispatcher servlet.
        registration.setOrder(Ordered.HIGHEST_PRECEDENCE + 10);
        return registration;
    }
}
