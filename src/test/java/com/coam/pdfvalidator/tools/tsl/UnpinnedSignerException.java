package com.coam.pdfvalidator.tools.tsl;

/** The list is signed by a certificate outside the pinned set (for the LOTL: a signer rotation not yet pinned). */
final class UnpinnedSignerException extends TrustedListException {

    private static final long serialVersionUID = 1L;

    private final String signerSha256;

    UnpinnedSignerException(String signerSha256, Throwable cause) {
        super("The list's signer certificate " + signerSha256 + " is not pinned", cause);
        this.signerSha256 = signerSha256;
    }

    String signerSha256() {
        return signerSha256;
    }
}
