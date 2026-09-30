package com.coam.pdfvalidator.infrastructure.config;

import com.coam.pdfvalidator.infrastructure.revocation.RevocationLimits;

import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.boot.context.properties.bind.DefaultValue;
import org.springframework.util.unit.DataSize;

import java.time.Duration;

/**
 * Configuration for the real {@code CompositeRevocationChecker} bean (T10,
 * hardened in T21): every bound on the optional OCSP/CRL check, all with
 * safe defaults (README section 4).
 *
 * @param timeout            per-request cap (DNS + connect + response) for each OCSP/CRL request (default 2 s)
 * @param totalTimeout       one deadline for the whole revocation check of a signature -- every OCSP and CRL
 *                           attempt of every certificate of the validated path (default 6 s)
 * @param maxResponseBytes   maximum accepted OCSP/CRL response size (default 10 MB)
 * @param maxUrlsPerMethod   AIA (OCSP) / CDP (CRL) URLs tried per certificate after de-duplication (default 3)
 * @param maxHeaderLineBytes maximum length of one HTTP response line (default 8 KB)
 * @param maxHeaders         maximum number of HTTP response headers, and of chunk trailers (default 100)
 * @param maxHeaderBytes     maximum combined size of the HTTP response headers, and of the trailers (default 64 KB)
 */
@ConfigurationProperties(prefix = "pdfvalidator.revocation")
public record RevocationProperties(
        @DefaultValue("2s") Duration timeout,
        @DefaultValue("6s") Duration totalTimeout,
        @DefaultValue("10MB") DataSize maxResponseBytes,
        @DefaultValue("3") int maxUrlsPerMethod,
        @DefaultValue("8KB") DataSize maxHeaderLineBytes,
        @DefaultValue("100") int maxHeaders,
        @DefaultValue("64KB") DataSize maxHeaderBytes) {

    /** The bounds as the infrastructure adapter consumes them; invalid (non-positive) values fail at startup. */
    public RevocationLimits toLimits() {
        return new RevocationLimits(
                timeout, totalTimeout, maxResponseBytes.toBytes(), maxUrlsPerMethod,
                Math.toIntExact(maxHeaderLineBytes.toBytes()), maxHeaders,
                Math.toIntExact(maxHeaderBytes.toBytes()));
    }
}
