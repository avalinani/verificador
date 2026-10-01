package com.coam.pdfvalidator.infrastructure.bouncycastle;

import com.coam.pdfvalidator.domain.model.CertificateInfo;
import com.coam.pdfvalidator.domain.port.TrustedCertificateSource;
import org.bouncycastle.asn1.cms.Attribute;
import org.bouncycastle.asn1.cms.AttributeTable;
import org.bouncycastle.asn1.ess.ESSCertID;
import org.bouncycastle.asn1.ess.ESSCertIDv2;
import org.bouncycastle.asn1.ess.SigningCertificate;
import org.bouncycastle.asn1.ess.SigningCertificateV2;
import org.bouncycastle.asn1.oiw.OIWObjectIdentifiers;
import org.bouncycastle.asn1.pkcs.PKCSObjectIdentifiers;
import org.bouncycastle.asn1.x509.AlgorithmIdentifier;
import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.cert.jcajce.JcaX509CertificateConverter;
import org.bouncycastle.cms.SignerId;
import org.bouncycastle.operator.DigestCalculator;
import org.bouncycastle.operator.OperatorCreationException;
import org.bouncycastle.operator.jcajce.JcaDigestCalculatorProviderBuilder;
import org.bouncycastle.tsp.TimeStampToken;

import java.io.IOException;
import java.security.MessageDigest;
import java.security.Provider;
import java.security.cert.CertificateEncodingException;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.Collection;
import java.util.List;

/**
 * Finds the TSA certificate of an RFC 3161 timestamp token (T26a): the one the token carries or -- for a token
 * requested with {@code certReq=false} (RFC 3161 section 2.4.1), which carries none -- one found in the signature's
 * own CMS {@code SignedData} or among the configured trust anchors, in that order.
 *
 * <p>A candidate is accepted only when it matches the token's signer identifier ({@link TimeStampToken#getSID()}:
 * issuer and serial number, or subject key identifier) and, when the token's signed attributes carry one, the
 * {@code ESSCertID}/{@code ESSCertIDv2} hash of the certificate (RFC 5035), so a different certificate (same
 * subject, other key or serial, or even the same identifier with other content) can never be substituted. Finding a
 * certificate here says nothing about trust: the application layer still validates its chain.
 */
final class TsaCertificateLocator {

    private static final System.Logger LOGGER = System.getLogger(TsaCertificateLocator.class.getName());

    private final Provider bcProvider;
    private final List<X509Certificate> signatureCertificates;
    private final TrustedCertificateSource trustedCertificates;
    private List<X509Certificate> trustAnchors;

    TsaCertificateLocator(
            Provider bcProvider, List<X509Certificate> signatureCertificates,
            TrustedCertificateSource trustedCertificates) {
        this.bcProvider = bcProvider;
        this.signatureCertificates = List.copyOf(signatureCertificates);
        this.trustedCertificates = trustedCertificates;
    }

    /** The TSA certificate, or {@code null} when it is nowhere. Never throws. */
    X509Certificate find(TimeStampToken token) {
        try {
            SignerId signerId = token.getSID();
            Collection<X509CertificateHolder> own = token.getCertificates().getMatches(signerId);
            if (!own.isEmpty()) {
                return new JcaX509CertificateConverter().setProvider(bcProvider).getCertificate(own.iterator().next());
            }
            for (X509Certificate candidate : signatureCertificates) {
                if (isTheTsaCertificate(candidate, token, signerId)) {
                    return candidate;
                }
            }
            for (X509Certificate candidate : trustAnchors()) {
                if (isTheTsaCertificate(candidate, token, signerId)) {
                    return candidate;
                }
            }
            return null;
        } catch (CertificateException | RuntimeException e) {
            return null;
        }
    }

    /** The certificates a TSA certificate's issuers may be found in besides the token: the signature CMS and anchors. */
    List<X509Certificate> issuerCandidates() {
        List<X509Certificate> candidates = new ArrayList<>(signatureCertificates);
        candidates.addAll(trustAnchors());
        return candidates;
    }

    private List<X509Certificate> trustAnchors() {
        if (trustAnchors == null) {
            List<X509Certificate> converted = new ArrayList<>();
            JcaX509CertificateConverter converter = new JcaX509CertificateConverter().setProvider(bcProvider);
            for (CertificateInfo info : trustedCertificates.trustedCertificates()) {
                try {
                    converted.add(converter.getCertificate(new X509CertificateHolder(info.encoded())));
                } catch (IOException | CertificateException | RuntimeException e) {
                    SignatureTimestampVerifier.logFailure("A trust anchor could not be read for the TSA lookup", e);
                }
            }
            trustAnchors = converted;
        }
        return trustAnchors;
    }

    private boolean isTheTsaCertificate(X509Certificate candidate, TimeStampToken token, SignerId signerId) {
        try {
            X509CertificateHolder holder = new X509CertificateHolder(candidate.getEncoded());
            return signerId.match(holder) && essCertIdMatches(token, holder);
        } catch (IOException | CertificateEncodingException | RuntimeException e) {
            return false;
        }
    }

    /**
     * Compares the hash of {@code holder} with the {@code ESSCertID} (SHA-1) or {@code ESSCertIDv2} the TSA signed
     * into the token (RFC 5035); {@code true} when the token carries neither (the signer identifier alone then
     * decides). An unreadable or unsupported attribute never matches.
     */
    private boolean essCertIdMatches(TimeStampToken token, X509CertificateHolder holder) {
        AttributeTable signed = token.getSignedAttributes();
        if (signed == null) {
            return true;
        }
        Attribute v2 = signed.get(PKCSObjectIdentifiers.id_aa_signingCertificateV2);
        Attribute v1 = signed.get(PKCSObjectIdentifiers.id_aa_signingCertificate);
        try {
            if (v2 != null) {
                ESSCertIDv2 id = SigningCertificateV2.getInstance(v2.getAttrValues().getObjectAt(0)).getCerts()[0];
                return hashEquals(holder, id.getHashAlgorithm(), id.getCertHash());
            }
            if (v1 != null) {
                ESSCertID id = SigningCertificate.getInstance(v1.getAttrValues().getObjectAt(0)).getCerts()[0];
                return hashEquals(holder, new AlgorithmIdentifier(OIWObjectIdentifiers.idSHA1), id.getCertHash());
            }
            return true;
        } catch (RuntimeException e) {
            LOGGER.log(System.Logger.Level.DEBUG, "Unreadable signing certificate attribute in a timestamp token", e);
            return false;
        }
    }

    private boolean hashEquals(X509CertificateHolder holder, AlgorithmIdentifier algorithm, byte[] expected) {
        try {
            DigestCalculator calculator =
                    new JcaDigestCalculatorProviderBuilder().setProvider(bcProvider).build().get(algorithm);
            calculator.getOutputStream().write(holder.getEncoded());
            return MessageDigest.isEqual(calculator.getDigest(), expected);
        } catch (IOException | OperatorCreationException | RuntimeException e) {
            return false;
        }
    }
}
