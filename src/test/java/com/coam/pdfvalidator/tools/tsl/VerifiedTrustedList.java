package com.coam.pdfvalidator.tools.tsl;

import java.net.URI;
import java.security.cert.X509Certificate;

/** A trusted list whose signature, signer pin, signer validity and NextUpdate have all been checked. */
record VerifiedTrustedList(URI source, TrustedList list, X509Certificate signer) {
}
