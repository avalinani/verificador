package com.coam.pdfvalidator.tools.tsl;

import java.security.cert.X509Certificate;
import java.util.List;

/**
 * One certificate to bundle, with every selected service that lists it
 * (sorted; the first one names the file).
 */
record Anchor(String fileName, String sha256, X509Certificate certificate, List<TrustService> services) {

    Anchor {
        services = List.copyOf(services);
    }

    /** The short service type of the naming service: {@code CA/QC} or {@code TSA/QTST}. */
    String kind() {
        String type = services.getFirst().type();
        return AnchorSelector.TSA_QTST.equals(type) ? "TSA/QTST" : "CA/QC";
    }
}
