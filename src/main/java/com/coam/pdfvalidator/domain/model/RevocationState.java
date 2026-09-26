package com.coam.pdfvalidator.domain.model;

/** Outcome of checking a certificate's revocation state via OCSP/CRL. */
public enum RevocationState {
    GOOD,
    REVOKED,
    UNKNOWN,
    NOT_CHECKED
}
