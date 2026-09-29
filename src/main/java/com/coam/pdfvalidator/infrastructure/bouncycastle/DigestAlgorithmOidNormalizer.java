package com.coam.pdfvalidator.infrastructure.bouncycastle;

import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.nist.NISTObjectIdentifiers;
import org.bouncycastle.asn1.oiw.OIWObjectIdentifiers;
import org.bouncycastle.asn1.pkcs.PKCSObjectIdentifiers;
import org.bouncycastle.asn1.x509.AlgorithmIdentifier;
import org.bouncycastle.asn1.x9.X9ObjectIdentifiers;

import java.util.Map;

/**
 * Some real-world signing tools encode a CMS {@code SignerInfo}'s {@code
 * digestAlgorithm} field using the SIGNATURE algorithm's OID (e.g. {@code
 * sha256WithRSAEncryption}, {@code 1.2.840.113549.1.1.11}) instead of the
 * plain digest OID ({@code id-sha256}, {@code 2.16.840.1.101.3.4.2.1}) RFC
 * 5652 actually requires there. Adobe accepts this non-standard encoding;
 * Bouncy Castle's own digest-calculator lookup does not (it fails with
 * {@code NoSuchAlgorithmException}, since no digest provider is registered
 * under a signature algorithm's OID). This class maps every unambiguous
 * signature algorithm OID -- one that names exactly one digest algorithm --
 * to that digest's own OID.
 *
 * <p><b>Deliberately narrow</b>: only RSA PKCS#1 v1.5, ECDSA and classic DSA
 * signature OIDs are mapped, since each of those names its digest
 * unambiguously. {@code id-RSASSA-PSS} is not mapped: its digest is carried
 * in the algorithm's own parameters, not implied by a fixed OID. A bare
 * {@code rsaEncryption} OID is not mapped either: it names no digest at all,
 * so there is nothing unambiguous to infer.
 */
final class DigestAlgorithmOidNormalizer {

    private static final Map<ASN1ObjectIdentifier, ASN1ObjectIdentifier> SIGNATURE_TO_DIGEST = Map.ofEntries(
            Map.entry(PKCSObjectIdentifiers.sha1WithRSAEncryption, OIWObjectIdentifiers.idSHA1),
            Map.entry(PKCSObjectIdentifiers.sha224WithRSAEncryption, NISTObjectIdentifiers.id_sha224),
            Map.entry(PKCSObjectIdentifiers.sha256WithRSAEncryption, NISTObjectIdentifiers.id_sha256),
            Map.entry(PKCSObjectIdentifiers.sha384WithRSAEncryption, NISTObjectIdentifiers.id_sha384),
            Map.entry(PKCSObjectIdentifiers.sha512WithRSAEncryption, NISTObjectIdentifiers.id_sha512),
            Map.entry(X9ObjectIdentifiers.ecdsa_with_SHA1, OIWObjectIdentifiers.idSHA1),
            Map.entry(X9ObjectIdentifiers.ecdsa_with_SHA224, NISTObjectIdentifiers.id_sha224),
            Map.entry(X9ObjectIdentifiers.ecdsa_with_SHA256, NISTObjectIdentifiers.id_sha256),
            Map.entry(X9ObjectIdentifiers.ecdsa_with_SHA384, NISTObjectIdentifiers.id_sha384),
            Map.entry(X9ObjectIdentifiers.ecdsa_with_SHA512, NISTObjectIdentifiers.id_sha512),
            Map.entry(X9ObjectIdentifiers.id_dsa_with_sha1, OIWObjectIdentifiers.idSHA1));

    private DigestAlgorithmOidNormalizer() {
    }

    /** Whether {@code oid} is one of the signature algorithm OIDs this class knows how to normalize. */
    static boolean isSignatureAlgorithmOid(ASN1ObjectIdentifier oid) {
        return SIGNATURE_TO_DIGEST.containsKey(oid);
    }

    /**
     * Returns an {@link AlgorithmIdentifier} for the plain digest OID
     * corresponding to {@code original}'s algorithm, when it is a known
     * signature algorithm OID; returns {@code original} unchanged otherwise
     * (including when it is already a plain digest OID).
     */
    static AlgorithmIdentifier normalize(AlgorithmIdentifier original) {
        ASN1ObjectIdentifier digestOid = SIGNATURE_TO_DIGEST.get(original.getAlgorithm());
        return digestOid == null ? original : new AlgorithmIdentifier(digestOid);
    }
}
