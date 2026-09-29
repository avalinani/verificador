package com.coam.pdfvalidator.infrastructure.config;

import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.boot.context.properties.bind.DefaultValue;
import org.springframework.util.unit.DataSize;

import java.time.Duration;

/**
 * Configuration for the real {@code CompositeRevocationChecker} bean (T10):
 * a strict per-request timeout (OCSP and CRL each honor it independently)
 * and a response size cap, both with the defaults the task specified.
 *
 * @param timeout           per-request timeout for both OCSP and CRL requests (default 2 s)
 * @param maxResponseBytes  maximum accepted OCSP/CRL response size (default 10 MB)
 */
@ConfigurationProperties(prefix = "pdfvalidator.revocation")
public record RevocationProperties(
        @DefaultValue("2s") Duration timeout,
        @DefaultValue("10MB") DataSize maxResponseBytes) {
}
