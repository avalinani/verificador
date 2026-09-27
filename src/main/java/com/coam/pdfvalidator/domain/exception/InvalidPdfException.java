package com.coam.pdfvalidator.domain.exception;

/** The given bytes are not a well-formed PDF (unparseable, truncated, or not a PDF at all). */
public class InvalidPdfException extends RuntimeException {

    public InvalidPdfException(String message) {
        super(message);
    }

    public InvalidPdfException(String message, Throwable cause) {
        super(message, cause);
    }
}
