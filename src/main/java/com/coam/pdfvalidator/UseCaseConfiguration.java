package com.coam.pdfvalidator;

import com.coam.pdfvalidator.application.AnalyzePdfUseCase;
import com.coam.pdfvalidator.domain.port.CertificateChainValidator;
import com.coam.pdfvalidator.domain.port.HashCalculator;
import com.coam.pdfvalidator.domain.port.PdfDocumentReader;
import com.coam.pdfvalidator.domain.port.PdfaConformanceValidator;
import com.coam.pdfvalidator.domain.port.RevocationChecker;
import com.coam.pdfvalidator.domain.port.SignatureVerifier;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;

import java.time.Clock;

/**
 * Wires {@link AnalyzePdfUseCase} out of the adapter beans {@code
 * com.coam.pdfvalidator.infrastructure.config.AdapterConfiguration} provides.
 *
 * <p>Lives in this top-level package, outside {@code domain}, {@code
 * application}, {@code infrastructure} and {@code api}, on purpose: it is
 * the one place allowed to depend on both the use case (from {@code
 * application}) and the adapter beans (typed as {@code domain.port}
 * interfaces here, never as their concrete {@code infrastructure} classes),
 * because {@code ArchitectureTest} enforces that no class under {@code
 * infrastructure} may depend on {@code application} -- this class is
 * deliberately not under {@code infrastructure.config} for exactly that
 * reason. This is the conventional "composition root" of a hexagonal
 * application: the wiring glue is not itself part of any of the four layers
 * it wires together.
 *
 * <p>The {@link RevocationChecker} bean itself (T10: {@code
 * CompositeRevocationChecker}, OCSP/CRL) is wired in {@code
 * infrastructure.config.AdapterConfiguration} like every other adapter --
 * unlike the earlier temporary {@code NoOpRevocationChecker}, it is a real
 * adapter with no dependency on {@code application}, so it belongs there,
 * not here.
 */
@Configuration
public class UseCaseConfiguration {

    @Bean
    public AnalyzePdfUseCase analyzePdfUseCase(
            HashCalculator hashCalculator,
            PdfDocumentReader pdfDocumentReader,
            SignatureVerifier signatureVerifier,
            CertificateChainValidator certificateChainValidator,
            PdfaConformanceValidator pdfaConformanceValidator,
            RevocationChecker revocationChecker,
            Clock clock) {
        return new AnalyzePdfUseCase(
                hashCalculator, pdfDocumentReader, signatureVerifier, certificateChainValidator,
                pdfaConformanceValidator, revocationChecker, clock);
    }
}
