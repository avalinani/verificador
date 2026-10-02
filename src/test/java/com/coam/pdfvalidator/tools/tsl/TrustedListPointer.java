package com.coam.pdfvalidator.tools.tsl;

import java.security.cert.X509Certificate;
import java.util.List;

/**
 * An {@code OtherTSLPointer} of the LOTL: where a national list lives, which
 * territory and format it is, and the certificates allowed to sign it.
 * {@code territory} and {@code mimeType} are {@code null} when absent.
 */
record TrustedListPointer(String location, String territory, String mimeType, List<X509Certificate> certificates) {

    TrustedListPointer {
        certificates = List.copyOf(certificates);
    }
}
