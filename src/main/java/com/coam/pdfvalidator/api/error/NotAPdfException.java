package com.coam.pdfvalidator.api.error;

/**
 * The uploaded content does not start with a recognizable {@code %PDF-}
 * header, so it is rejected before even attempting to analyze it -- even
 * when the uploaded file name ends in {@code .pdf} (the name is never
 * trusted). A file that does have the header but is otherwise broken is a
 * different case: see the domain's own {@code InvalidPdfException},
 * reported as {@code 422} instead of this one's {@code 400}.
 */
public class NotAPdfException extends RuntimeException {

    public NotAPdfException(String message) {
        super(message);
    }
}
