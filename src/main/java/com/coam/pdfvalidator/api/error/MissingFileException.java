package com.coam.pdfvalidator.api.error;

/** The {@code file} multipart part is missing or empty. */
public class MissingFileException extends RuntimeException {

    public MissingFileException(String message) {
        super(message);
    }
}
