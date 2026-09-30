package com.coam.pdfvalidator.infrastructure.bouncycastle;

import com.coam.pdfvalidator.domain.model.CertificateInfo;
import com.coam.pdfvalidator.domain.model.TimestampInfo;
import org.bouncycastle.asn1.ASN1Encodable;
import org.bouncycastle.asn1.cms.Attribute;
import org.bouncycastle.asn1.cms.AttributeTable;
import org.bouncycastle.asn1.cms.ContentInfo;
import org.bouncycastle.asn1.pkcs.PKCSObjectIdentifiers;
import org.bouncycastle.asn1.x509.AlgorithmIdentifier;
import org.bouncycastle.asn1.x509.KeyPurposeId;
import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.cert.jcajce.JcaX509CertificateConverter;
import org.bouncycastle.cms.SignerId;
import org.bouncycastle.cms.SignerInformation;
import org.bouncycastle.cms.SignerInformationVerifier;
import org.bouncycastle.cms.jcajce.JcaSimpleSignerInfoVerifierBuilder;
import org.bouncycastle.operator.DigestCalculator;
import org.bouncycastle.operator.DigestCalculatorProvider;
import org.bouncycastle.operator.jcajce.JcaDigestCalculatorProviderBuilder;
import org.bouncycastle.tsp.TSPException;
import org.bouncycastle.tsp.TimeStampToken;
import org.bouncycastle.tsp.TimeStampTokenInfo;
import org.bouncycastle.util.Store;

import java.io.IOException;
import java.security.Provider;
import java.security.cert.CertificateException;
import java.security.cert.CertificateParsingException;
import java.security.cert.X509Certificate;
import java.time.Instant;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collection;
import java.util.List;
import java.util.Objects;

/**
 * Extracts and verifies an RFC 3161 signature timestamp -- the unsigned CMS
 * attribute {@code id-aa-signatureTimeStampToken} (OID {@code
 * 1.2.840.113549.1.9.16.2.14}) a TSA adds to a {@link SignerInformation}
 * after the signature itself is produced -- and reports it as a domain
 * {@link TimestampInfo}. Never throws: a missing attribute reports {@link
 * TimestampInfo#absent()}, and a malformed token reports a present-but-
 * invalid {@link TimestampInfo} carrying a diagnostic {@code note} rather
 * than escaping as an exception, since a bad timestamp must never affect
 * the surrounding signature's own integrity verdict.
 *
 * <p>Verification has two independent parts, both required for a
 * trustworthy timestamp:
 * <ol>
 *   <li><b>Message imprint</b>: the token's {@code messageImprint} must
 *       equal the hash -- using the token's own declared imprint algorithm
 *       -- of the timestamped {@link SignerInformation}'s signature value
 *       bytes (not the document content: a signature timestamp seals the
 *       signature itself, proving it existed at that time).</li>
 *   <li><b>TSA signature</b>: the token's own CMS signature must verify
 *       against the TSA certificate embedded in the token ({@link
 *       TimeStampToken#validate}).</li>
 * </ol>
 *
 * <p>Neither part says the TSA is <em>trustworthy</em>: the certificate that
 * verifies the token is the one the token itself carries. This class
 * therefore only <b>reports</b> the facts the application layer needs to
 * decide trust -- whether the TSA certificate declares the {@code
 * id-kp-timeStamping} extended key usage ({@link
 * TimestampInfo#tsaTimeStampingEku()}, presence required; RFC 3161 section
 * 2.3 also asks for "critical" and "only", which is deliberately not
 * enforced here: chain trust is the security-relevant control, and several
 * real TSAs omit the criticality bit) and the TSA certificate chain carried
 * in the token ({@link TimestampInfo#tsaChain()}). It never sets {@link
 * TimestampInfo#trusted()}.
 */
final class SignatureTimestampVerifier {

    private SignatureTimestampVerifier() {
    }

    static TimestampInfo verify(SignerInformation signerInformation, Provider bcProvider) {
        AttributeTable unsignedAttributes = signerInformation.getUnsignedAttributes();
        if (unsignedAttributes == null) {
            return TimestampInfo.absent();
        }
        Attribute attribute = unsignedAttributes.get(PKCSObjectIdentifiers.id_aa_signatureTimeStampToken);
        if (attribute == null) {
            return TimestampInfo.absent();
        }

        try {
            ASN1Encodable[] values = attribute.getAttributeValues();
            if (values.length == 0) {
                return malformed("Signature timestamp attribute has no value");
            }
            TimeStampToken token = new TimeStampToken(ContentInfo.getInstance(values[0]));
            return verifyToken(token, signerInformation.getSignature(), bcProvider);
        } catch (IOException | TSPException | RuntimeException e) {
            return malformed("Malformed RFC 3161 timestamp token: " + e);
        }
    }

    private static TimestampInfo verifyToken(TimeStampToken token, byte[] signatureValue, Provider bcProvider)
            throws IOException {
        TimeStampTokenInfo info = token.getTimeStampInfo();
        Instant genTime = info.getGenTime().toInstant();
        boolean imprintValid = imprintMatches(info, signatureValue, bcProvider);

        X509Certificate tsaCertificate = findTsaCertificate(token, bcProvider);
        boolean signatureValid = false;
        String note = null;
        CertificateInfo tsaCertificateInfo = null;
        List<CertificateInfo> tsaChain = List.of();
        boolean timeStampingEku = false;
        String tsaName = "";

        if (tsaCertificate == null) {
            note = "TSA certificate not found in the timestamp token";
        } else {
            tsaName = tsaCertificate.getSubjectX500Principal().getName();

            CertificateMapping mapping = mapTsaCertificate(tsaCertificate);
            tsaCertificateInfo = mapping.certificateInfo();
            note = appendNote(note, mapping.failureNote());
            if (tsaCertificateInfo != null) {
                tsaChain = mapTsaChain(tsaCertificate, tsaCertificateInfo, token, bcProvider);
            }

            try {
                SignerInformationVerifier verifier =
                        new JcaSimpleSignerInfoVerifierBuilder().setProvider(bcProvider).build(tsaCertificate);
                token.validate(verifier);
                signatureValid = true;
            } catch (TSPException | org.bouncycastle.operator.OperatorCreationException e) {
                note = appendNote(note, "TSA signature verification failed: " + e.getMessage());
            }
            // The missing-EKU check runs unconditionally alongside signature
            // validation above (not only when it succeeds): BC's own
            // signingCertificate/ESSCertID binding check (RFC 5035) means a
            // substituted TSA certificate typically fails signature
            // validation too, so in practice this note is most often seen
            // together with a signature failure rather than alone -- it is
            // still reported on its own merits rather than folded into that
            // failure, since the two are independent facts about the
            // certificate.
            timeStampingEku = hasTimeStampingEku(tsaCertificate);
            if (!timeStampingEku) {
                note = appendNote(note, "TSA certificate is missing the id-kp-timeStamping extended key usage");
            }
        }

        return new TimestampInfo(
                genTime, tsaName, imprintValid, signatureValid, tsaCertificateInfo, note,
                tsaChain, timeStampingEku, false);
    }

    /**
     * Maps the TSA certificate to the domain {@link CertificateInfo}. A
     * mapping failure (e.g. the certificate cannot be DER-re-encoded) must
     * not discard the rest of the timestamp result -- {@code genTime},
     * {@code imprintValid} and {@code signatureValid} are each independently
     * verifiable and stay meaningful even without the TSA's certificate
     * data -- so the failure is reported only as a note, package-private and
     * static so it can be unit-tested directly with a certificate double
     * that fails to map.
     */
    static CertificateMapping mapTsaCertificate(X509Certificate certificate) {
        try {
            return new CertificateMapping(X509CertificateInfoMapper.toDomain(certificate), null);
        } catch (RuntimeException e) {
            return new CertificateMapping(null, "TSA certificate data could not be mapped: " + e.getMessage());
        }
    }

    /**
     * The TSA certificate followed by its issuers found in the token,
     * walking issuer DN to subject DN (at most one hop per certificate in
     * the token, so a DN cycle cannot loop). Certificates in the token that
     * are not on that path are left out on purpose: the chain validator
     * checks the validity of every certificate it is given, and an unrelated
     * embedded certificate must not decide the TSA's trust. A mapping
     * failure of an issuer ends the chain there (the validator then reports
     * an incomplete chain, so the timestamp is simply not trusted).
     */
    private static List<CertificateInfo> mapTsaChain(
            X509Certificate tsaCertificate, CertificateInfo tsaCertificateInfo, TimeStampToken token,
            Provider bcProvider) {
        List<CertificateInfo> chain = new ArrayList<>();
        chain.add(tsaCertificateInfo);
        try {
            List<X509Certificate> candidates = new ArrayList<>();
            JcaX509CertificateConverter converter = new JcaX509CertificateConverter().setProvider(bcProvider);
            for (X509CertificateHolder holder : token.getCertificates().getMatches(null)) {
                candidates.add(converter.getCertificate(holder));
            }
            X509Certificate current = tsaCertificate;
            for (int hop = 0; hop < candidates.size(); hop++) {
                if (current.getIssuerX500Principal().equals(current.getSubjectX500Principal())) {
                    break; // self-signed: reached the root
                }
                X509Certificate issuer = findIssuer(candidates, current);
                if (issuer == null) {
                    break;
                }
                chain.add(X509CertificateInfoMapper.toDomain(issuer));
                current = issuer;
            }
        } catch (CertificateException | RuntimeException e) {
            // Keep whatever part of the chain was mapped; an incomplete chain is simply not trusted.
        }
        return chain;
    }

    private static X509Certificate findIssuer(List<X509Certificate> candidates, X509Certificate certificate) {
        for (X509Certificate candidate : candidates) {
            if (!candidate.equals(certificate)
                    && candidate.getSubjectX500Principal().equals(certificate.getIssuerX500Principal())) {
                return candidate;
            }
        }
        return null;
    }

    /** Result of {@link #mapTsaCertificate}: the mapped certificate, or a failure note when mapping failed. */
    record CertificateMapping(CertificateInfo certificateInfo, String failureNote) {
    }

    private static boolean imprintMatches(TimeStampTokenInfo info, byte[] signatureValue, Provider bcProvider) {
        try {
            DigestCalculatorProvider digestCalculatorProvider =
                    new JcaDigestCalculatorProviderBuilder().setProvider(bcProvider).build();
            DigestCalculator digestCalculator =
                    digestCalculatorProvider.get(new AlgorithmIdentifier(info.getMessageImprintAlgOID()));
            digestCalculator.getOutputStream().write(signatureValue);
            byte[] actualImprint = digestCalculator.getDigest();
            return Arrays.equals(actualImprint, info.getMessageImprintDigest());
        } catch (IOException | org.bouncycastle.operator.OperatorCreationException | RuntimeException e) {
            // An unsupported or malformed imprint algorithm is simply an
            // invalid imprint, not a reason to fail the whole timestamp.
            return false;
        }
    }

    private static X509Certificate findTsaCertificate(TimeStampToken token, Provider bcProvider) {
        try {
            Store<X509CertificateHolder> certificates = token.getCertificates();
            SignerId signerId = token.getSID();
            Collection<X509CertificateHolder> matches = certificates.getMatches(signerId);
            if (matches.isEmpty()) {
                return null;
            }
            X509CertificateHolder holder = matches.iterator().next();
            return new JcaX509CertificateConverter().setProvider(bcProvider).getCertificate(holder);
        } catch (CertificateException | RuntimeException e) {
            return null;
        }
    }

    /**
     * T05b decision: kept as-is rather than simplified/removed, even though
     * BC's own signingCertificate/ESSCertID binding check (RFC 5035) means a
     * substituted certificate usually fails signature validation for the
     * same reason, making "valid signature + missing EKU" hard to reach in
     * practice -- an unmodified, genuinely non-compliant TSA certificate
     * still reaches this check on its own, so the note stays independently
     * useful.
     */
    private static boolean hasTimeStampingEku(X509Certificate certificate) {
        try {
            List<String> extendedKeyUsage = certificate.getExtendedKeyUsage();
            return extendedKeyUsage != null && extendedKeyUsage.contains(KeyPurposeId.id_kp_timeStamping.getId());
        } catch (CertificateParsingException | RuntimeException e) {
            // A malformed EKU extension is treated the same as a missing one.
            return false;
        }
    }

    /** Appends {@code addition} to {@code existing} (joined by {@code "; "}); a {@code null} addition is a no-op. */
    private static String appendNote(String existing, String addition) {
        if (addition == null) {
            return existing;
        }
        return existing == null ? addition : existing + "; " + addition;
    }

    private static TimestampInfo malformed(String note) {
        return new TimestampInfo(null, "", false, false, null, Objects.requireNonNull(note), List.of(), false, false);
    }
}
