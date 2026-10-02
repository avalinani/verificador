package com.coam.pdfvalidator.tools.tsl;

import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.cert.CertificateEncodingException;
import java.security.cert.X509Certificate;
import java.util.HexFormat;

/** Lower-case hex SHA-256 of a certificate's DER encoding: the identity used for pins, dedup and file names. */
final class Fingerprints {

    private Fingerprints() {
    }

    static String sha256(X509Certificate certificate) {
        try {
            return HexFormat.of().formatHex(MessageDigest.getInstance("SHA-256").digest(certificate.getEncoded()));
        } catch (NoSuchAlgorithmException | CertificateEncodingException e) {
            throw new IllegalStateException("Cannot fingerprint a certificate", e);
        }
    }
}
