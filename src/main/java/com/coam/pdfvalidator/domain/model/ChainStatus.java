package com.coam.pdfvalidator.domain.model;

/** Outcome of validating a certificate chain against a configured trust store. */
public enum ChainStatus {
    TRUSTED,
    UNTRUSTED_ROOT,
    INCOMPLETE_CHAIN,
    EXPIRED,
    NOT_CHECKED
}
