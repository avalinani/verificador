package com.coam.pdfvalidator.tools.tsl;

/** Any reason a downloaded trusted list cannot be trusted; the sync aborts without touching the trust store. */
class TrustedListException extends Exception {
    private static final long serialVersionUID = 1L;

    TrustedListException(String message) {
        super(message);
    }

    TrustedListException(String message, Throwable cause) {
        super(message, cause);
    }
}
