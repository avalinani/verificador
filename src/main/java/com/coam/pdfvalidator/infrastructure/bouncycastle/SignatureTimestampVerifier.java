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
 *       TimeStampToken#validate}), and that certificate should declare the
 *       {@code id-kp-timeStamping} extended key usage (a missing EKU is
 *       reported as a note rather than a failure, since it does not affect
 *       cryptographic validity by itself).</li>
 * </ol>
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
        String tsaName = "";

        if (tsaCertificate == null) {
            note = "TSA certificate not found in the timestamp token";
        } else {
            tsaCertificateInfo = X509CertificateInfoMapper.toDomain(tsaCertificate);
            tsaName = tsaCertificate.getSubjectX500Principal().getName();
            try {
                SignerInformationVerifier verifier =
                        new JcaSimpleSignerInfoVerifierBuilder().setProvider(bcProvider).build(tsaCertificate);
                token.validate(verifier);
                signatureValid = true;
            } catch (TSPException | org.bouncycastle.operator.OperatorCreationException e) {
                note = "TSA signature verification failed: " + e.getMessage();
            }
            if (!hasTimeStampingEku(tsaCertificate)) {
                note = appendNote(note, "TSA certificate is missing the id-kp-timeStamping extended key usage");
            }
        }

        return new TimestampInfo(genTime, tsaName, imprintValid, signatureValid, tsaCertificateInfo, note);
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

    private static boolean hasTimeStampingEku(X509Certificate certificate) {
        try {
            List<String> extendedKeyUsage = certificate.getExtendedKeyUsage();
            return extendedKeyUsage != null && extendedKeyUsage.contains(KeyPurposeId.id_kp_timeStamping.getId());
        } catch (CertificateParsingException | RuntimeException e) {
            // A malformed EKU extension is treated the same as a missing one.
            return false;
        }
    }

    private static String appendNote(String existing, String addition) {
        return existing == null ? addition : existing + "; " + addition;
    }

    private static TimestampInfo malformed(String note) {
        return new TimestampInfo(null, "", false, false, null, Objects.requireNonNull(note));
    }
}
