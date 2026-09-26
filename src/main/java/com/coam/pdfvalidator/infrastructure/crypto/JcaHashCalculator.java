package com.coam.pdfvalidator.infrastructure.crypto;

import com.coam.pdfvalidator.domain.model.DocumentHashes;
import com.coam.pdfvalidator.domain.port.HashCalculator;

import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.HexFormat;

/**
 * Computes SHA-256/SHA-512 digests with the JDK's own {@link MessageDigest}
 * (JCA), needing neither PDFBox nor Bouncy Castle. A plain class,
 * constructor-injectable; Spring wiring is added in a later task.
 */
public class JcaHashCalculator implements HashCalculator {

    private static final HexFormat HEX = HexFormat.of();

    @Override
    public DocumentHashes hash(byte[] content) {
        return new DocumentHashes(digest("SHA-256", content), digest("SHA-512", content));
    }

    private static String digest(String algorithm, byte[] content) {
        try {
            MessageDigest digest = MessageDigest.getInstance(algorithm);
            return HEX.formatHex(digest.digest(content));
        } catch (NoSuchAlgorithmException e) {
            // SHA-256 and SHA-512 are guaranteed by every JVM implementation
            // (Java Cryptography Architecture Standard Algorithm Names), so
            // this can only mean a broken JVM installation.
            throw new IllegalStateException("JVM does not support " + algorithm, e);
        }
    }
}
