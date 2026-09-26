package com.coam.pdfvalidator.domain.exception;

/** The PDF is encrypted and cannot be read further without (or even with) the right password. */
public class EncryptedPdfException extends RuntimeException {

    public EncryptedPdfException(String message) {
        super(message);
    }

    public EncryptedPdfException(String message, Throwable cause) {
        super(message, cause);
    }
}
