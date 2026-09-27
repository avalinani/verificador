package com.coam.pdfvalidator.domain.model;

/** Whether the signed bytes still match what was actually signed. */
public enum IntegrityStatus {
    INTACT,
    MODIFIED_AFTER_SIGNING,
    INVALID_SIGNATURE,
    UNSUPPORTED
}
