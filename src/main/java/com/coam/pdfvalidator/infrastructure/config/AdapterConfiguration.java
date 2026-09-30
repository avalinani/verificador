package com.coam.pdfvalidator.infrastructure.config;

import com.coam.pdfvalidator.domain.port.CertificateChainValidator;
import com.coam.pdfvalidator.domain.port.HashCalculator;
import com.coam.pdfvalidator.domain.port.PdfDocumentReader;
import com.coam.pdfvalidator.domain.port.PdfaConformanceValidator;
import com.coam.pdfvalidator.domain.port.RevocationChecker;
import com.coam.pdfvalidator.domain.port.SignatureVerifier;
import com.coam.pdfvalidator.infrastructure.bouncycastle.BcSignatureVerifier;
import com.coam.pdfvalidator.infrastructure.crypto.JcaHashCalculator;
import com.coam.pdfvalidator.infrastructure.pdfbox.DecodedSizeGuard;
import com.coam.pdfvalidator.infrastructure.pdfbox.PdfBoxDocumentReader;
import com.coam.pdfvalidator.infrastructure.pdfbox.StructureLimits;
import com.coam.pdfvalidator.infrastructure.pki.PkixCertificateChainValidator;
import com.coam.pdfvalidator.infrastructure.pki.TrustAnchorProvider;
import com.coam.pdfvalidator.infrastructure.preflight.PreflightPdfaValidator;
import com.coam.pdfvalidator.infrastructure.revocation.CompositeRevocationChecker;

import org.springframework.boot.context.properties.EnableConfigurationProperties;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;

import java.io.IOException;
import java.nio.file.Path;
import java.security.GeneralSecurityException;
import java.time.Clock;

/**
 * Wires every {@code domain} port to its real {@code infrastructure} adapter
 * with plain Spring {@code @Bean} methods -- the adapters themselves stay
 * Spring-free (constructor-injectable plain classes, as documented on each
 * one).
 *
 * <p><b>Deliberately does not wire {@code AnalyzePdfUseCase} itself</b>: this
 * class lives under {@code infrastructure.config}, and {@code
 * ArchitectureTest} enforces that nothing under {@code infrastructure}
 * depends on {@code application} -- correctly so, since an adapter must
 * never know about the use case that consumes it. The use case bean (which
 * necessarily depends on both these adapter beans' port types and {@code
 * application.AnalyzePdfUseCase}) is instead wired by {@code
 * com.coam.pdfvalidator.UseCaseConfiguration}, in the top-level package that
 * sits outside all four architecture layers -- the conventional
 * "composition root" for a hexagonal application.
 */
@Configuration
@EnableConfigurationProperties({TrustStoreProperties.class, RevocationProperties.class, AnalysisProperties.class})
public class AdapterConfiguration {

    @Bean
    public Clock clock() {
        return Clock.systemUTC();
    }

    @Bean
    public HashCalculator hashCalculator() {
        return new JcaHashCalculator();
    }

    @Bean
    public PdfDocumentReader pdfDocumentReader(AnalysisProperties analysis) {
        return new PdfBoxDocumentReader(decodedSizeLimits(analysis),
                new StructureLimits(analysis.maxPages(), analysis.maxRevisionMarkers(), analysis.maxRevisions()));
    }

    @Bean
    public SignatureVerifier signatureVerifier() {
        return new BcSignatureVerifier();
    }

    @Bean
    public PdfaConformanceValidator pdfaConformanceValidator(AnalysisProperties analysis) {
        return new PreflightPdfaValidator(decodedSizeLimits(analysis));
    }

    private static DecodedSizeGuard.Limits decodedSizeLimits(AnalysisProperties analysis) {
        return new DecodedSizeGuard.Limits(analysis.maxDecodedStreamSize().toBytes(),
                analysis.maxDecodedTotalSize().toBytes());
    }

    /**
     * Loads the bundled classpath trust anchors (README section 2.7), plus
     * (additively) an external directory and/or a PKCS#12 keystore when
     * {@link TrustStoreProperties} configures them.
     */
    @Bean
    public TrustAnchorProvider trustAnchorProvider(TrustStoreProperties properties)
            throws IOException, GeneralSecurityException {
        Path externalDir = properties.externalDir() != null ? Path.of(properties.externalDir()) : null;
        Path pkcs12Path = properties.pkcs12Path() != null ? Path.of(properties.pkcs12Path()) : null;
        char[] pkcs12Password = properties.pkcs12Password() != null
                ? properties.pkcs12Password().toCharArray()
                : null;
        return TrustAnchorProvider.load(externalDir, pkcs12Path, pkcs12Password);
    }

    @Bean
    public CertificateChainValidator certificateChainValidator(TrustAnchorProvider trustAnchorProvider) {
        return new PkixCertificateChainValidator(trustAnchorProvider);
    }

    /**
     * Real OCSP/CRL revocation checker (T10), replacing the temporary {@code
     * NoOpRevocationChecker} that used to be wired here by {@code
     * UseCaseConfiguration}. Configured via {@link RevocationProperties}
     * ({@code pdfvalidator.revocation.*}); the SSRF guard against
     * private/loopback AIA/CDP addresses is always enabled in this
     * production wiring (see {@link CompositeRevocationChecker}'s Javadoc).
     */
    @Bean
    public RevocationChecker revocationChecker(RevocationProperties properties) {
        return new CompositeRevocationChecker(properties.timeout(), properties.maxResponseBytes().toBytes());
    }
}
