package com.coam.pdfvalidator.infrastructure.config;

import org.springframework.boot.context.properties.ConfigurationProperties;

/**
 * Optional configuration for the {@code TrustAnchorProvider} bean's external
 * trust sources (README section 2.7): the bundled Spanish root certificates
 * are always loaded regardless of these properties; an external directory
 * and/or a PKCS#12 keystore are additive on top of them when set.
 *
 * @param externalDir     a directory containing one certificate (PEM or DER)
 *                        per file, or {@code null} to skip it
 * @param pkcs12Path      a PKCS#12 keystore file, or {@code null} to skip it
 * @param pkcs12Password  the PKCS#12 keystore password (ignored when {@code
 *                        pkcs12Path} is {@code null})
 */
@ConfigurationProperties(prefix = "pdfvalidator.truststore")
public record TrustStoreProperties(String externalDir, String pkcs12Path, String pkcs12Password) {
}
