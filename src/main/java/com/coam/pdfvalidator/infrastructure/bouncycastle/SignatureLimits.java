package com.coam.pdfvalidator.infrastructure.bouncycastle;

/**
 * Resource caps for signature analysis of a (possibly hostile) PDF (T20).
 *
 * @param maxSignatureFields          signature fields analysed; further ones are only counted
 *                                    ({@code SignatureExtraction#skippedFields()})
 * @param maxCertificatesPerSignature certificates taken from one CMS (the signer's first)
 * @param maxChainLength              certificates linked signer-to-root through issuer names
 */
public record SignatureLimits(int maxSignatureFields, int maxCertificatesPerSignature, int maxChainLength) {

    public static final SignatureLimits DEFAULT = new SignatureLimits(50, 50, 10);

    public SignatureLimits {
        if (maxSignatureFields < 1 || maxCertificatesPerSignature < 1 || maxChainLength < 1) {
            throw new IllegalArgumentException("signature limits must be >= 1: " + maxSignatureFields + ", "
                    + maxCertificatesPerSignature + ", " + maxChainLength);
        }
    }
}
