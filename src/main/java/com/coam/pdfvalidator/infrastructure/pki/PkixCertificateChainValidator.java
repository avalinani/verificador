package com.coam.pdfvalidator.infrastructure.pki;

import com.coam.pdfvalidator.domain.model.CertificateInfo;
import com.coam.pdfvalidator.domain.model.ChainStatus;
import com.coam.pdfvalidator.domain.port.CertificateChainValidator;

import java.io.ByteArrayInputStream;
import java.security.GeneralSecurityException;
import java.security.cert.CertPathBuilder;
import java.security.cert.CertStore;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.CollectionCertStoreParameters;
import java.security.cert.PKIXBuilderParameters;
import java.security.cert.TrustAnchor;
import java.security.cert.X509CertSelector;
import java.security.cert.X509Certificate;
import java.time.Instant;
import java.util.ArrayList;
import java.util.Date;
import java.util.List;
import java.util.Set;

/**
 * Validates a certificate chain with the JDK's own PKIX implementation
 * ({@link CertPathBuilder} + {@link PKIXBuilderParameters}), against a
 * configurable {@link TrustAnchorProvider}. Revocation checking is
 * deliberately disabled here ({@link PKIXBuilderParameters#setRevocationEnabled}
 * {@code (false)}) -- that is T10's responsibility, applied separately once
 * a chain is already trusted.
 *
 * <p>{@code validate}'s {@code chain} parameter is expected in the
 * signer-first order {@code BcSignatureVerifier} already produces (end-entity
 * first, its issuer next, and so on); the caller (the use case, in T08)
 * decides {@code validationTime} -- the signing time from a valid RFC 3161
 * timestamp if present, otherwise the signature's own claimed signing time,
 * otherwise "now".
 *
 * <h2>Mapping a PKIX failure to a specific {@link ChainStatus}</h2>
 * A successful {@link CertPathBuilder#build} means the presented chain
 * genuinely resolves to a trusted, correctly-signed path, so that case maps
 * directly to {@link ChainStatus#TRUSTED}. The JDK's PKIX exceptions do not
 * otherwise distinguish "the root isn't trusted" from "an issuer is
 * missing" in a way this adapter can rely on across JDK versions, so a
 * build failure is classified with an independent, simpler check instead:
 * whether the presented chain is <em>structurally complete</em> -- each
 * certificate's signature verifies against the next one's public key, all
 * the way to a self-signed (root) certificate. If it is, the failure must be
 * that the root is not one of the configured anchors ({@link
 * ChainStatus#UNTRUSTED_ROOT}); if the chain never reaches a self-signed
 * certificate, an issuer is missing ({@link ChainStatus#INCOMPLETE_CHAIN}).
 * This is a deliberate simplification: a build can in principle fail for
 * other PKIX reasons (e.g. basic constraints, name constraints, unsupported
 * critical extensions) that this two-way split does not distinguish; such
 * cases are reported as {@link ChainStatus#UNTRUSTED_ROOT} when the chain is
 * structurally complete, since the practical effect for the caller is the
 * same ("this chain cannot be trusted as presented").
 */
public final class PkixCertificateChainValidator implements CertificateChainValidator {

    private final TrustAnchorProvider trustAnchorProvider;

    public PkixCertificateChainValidator(TrustAnchorProvider trustAnchorProvider) {
        this.trustAnchorProvider = trustAnchorProvider;
    }

    @Override
    public ChainStatus validate(List<CertificateInfo> chain, Instant validationTime) {
        if (chain.isEmpty()) {
            return ChainStatus.NOT_CHECKED;
        }

        List<X509Certificate> certificates = toX509Certificates(chain);

        if (chain.stream().anyMatch(certificate -> !certificate.isValidAt(validationTime))) {
            return ChainStatus.EXPIRED;
        }

        try {
            buildPath(certificates, validationTime);
            return ChainStatus.TRUSTED;
        } catch (GeneralSecurityException e) {
            return isStructurallyComplete(certificates) ? ChainStatus.UNTRUSTED_ROOT : ChainStatus.INCOMPLETE_CHAIN;
        }
    }

    private void buildPath(List<X509Certificate> certificates, Instant validationTime) throws GeneralSecurityException {
        X509Certificate target = certificates.get(0);
        X509CertSelector targetSelector = new X509CertSelector();
        targetSelector.setCertificate(target);

        Set<TrustAnchor> trustAnchors = trustAnchorProvider.trustAnchors();
        PKIXBuilderParameters params = new PKIXBuilderParameters(trustAnchors, targetSelector);
        params.setRevocationEnabled(false);
        params.setDate(Date.from(validationTime));

        // The builder needs every certificate available in a CertStore to
        // discover a path with -- including the target/leaf certificate
        // itself, not just its issuers: the selector above is only a
        // matching criterion, not a certificate the builder already has in
        // hand.
        CertStore certStore =
                CertStore.getInstance("Collection", new CollectionCertStoreParameters(certificates));
        params.addCertStore(certStore);

        CertPathBuilder.getInstance("PKIX").build(params);
    }

    /**
     * Whether {@code certificates} (signer-first order) forms an unbroken
     * signature chain all the way to a self-signed certificate: each
     * certificate's signature must verify against the next certificate's
     * public key, and the last certificate must be self-signed. This says
     * nothing about whether that root is actually trusted -- only that the
     * presented chain does not have a missing link.
     */
    private static boolean isStructurallyComplete(List<X509Certificate> certificates) {
        for (int i = 0; i < certificates.size() - 1; i++) {
            if (!signedBy(certificates.get(i), certificates.get(i + 1))) {
                return false;
            }
        }
        return isSelfSigned(certificates.get(certificates.size() - 1));
    }

    private static boolean isSelfSigned(X509Certificate certificate) {
        return signedBy(certificate, certificate);
    }

    private static boolean signedBy(X509Certificate certificate, X509Certificate issuer) {
        try {
            certificate.verify(issuer.getPublicKey());
            return true;
        } catch (GeneralSecurityException e) {
            return false;
        }
    }

    private static List<X509Certificate> toX509Certificates(List<CertificateInfo> chain) {
        try {
            CertificateFactory factory = CertificateFactory.getInstance("X.509");
            List<X509Certificate> certificates = new ArrayList<>(chain.size());
            for (CertificateInfo certificateInfo : chain) {
                certificates.add((X509Certificate) factory.generateCertificate(
                        new ByteArrayInputStream(certificateInfo.encoded())));
            }
            return certificates;
        } catch (CertificateException e) {
            throw new IllegalStateException("Failed to parse a certificate from its DER encoding", e);
        }
    }
}
