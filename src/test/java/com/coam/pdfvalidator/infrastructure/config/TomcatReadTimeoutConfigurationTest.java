package com.coam.pdfvalidator.infrastructure.config;

import org.junit.jupiter.api.Test;
import org.springframework.boot.context.properties.bind.Binder;
import org.springframework.boot.context.properties.source.ConfigurationPropertySources;
import org.springframework.boot.env.YamlPropertySourceLoader;
import org.springframework.core.env.PropertySource;
import org.springframework.core.io.ClassPathResource;

import java.io.IOException;
import java.time.Duration;
import java.util.List;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * T26b: the shipped {@code application.yml} bounds how long Tomcat waits for the next bytes of a request, so a
 * client that stops sending an upload cannot hold an analysis permit for Tomcat's 60 s default (the bulkhead
 * takes the permit before the body is read).
 */
class TomcatReadTimeoutConfigurationTest {

    @Test
    void applicationYmlBoundsTheTimeTomcatWaitsForTheNextBytesOfARequest() throws IOException {
        List<PropertySource<?>> sources =
                new YamlPropertySourceLoader().load("application", new ClassPathResource("application.yml"));

        Duration timeout = new Binder(ConfigurationPropertySources.from(sources))
                .bind("server.tomcat.connection-timeout", Duration.class)
                .orElseThrow(() -> new AssertionError("server.tomcat.connection-timeout is not set"));

        assertThat(timeout).isPositive().isLessThanOrEqualTo(Duration.ofSeconds(30));
    }
}
