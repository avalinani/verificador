package com.coam.pdfvalidator.infrastructure.revocation;

import java.net.InetAddress;
import java.net.UnknownHostException;

/**
 * Resolves a hostname to its addresses. A seam over {@link
 * InetAddress#getAllByName(String)} so tests can prove {@link
 * RevocationUrlGuard#resolve} and {@link PinnedHttpClient} share a single
 * resolution instead of each independently re-resolving the same hostname
 * (which is exactly the DNS-rebinding TOCTOU this design avoids: a hostile
 * authoritative DNS server could otherwise answer a first, validating
 * lookup with a public address and a later connect-time lookup with an
 * internal one).
 */
@FunctionalInterface
interface HostResolver {

    InetAddress[] resolve(String host) throws UnknownHostException;

    static HostResolver systemDefault() {
        return InetAddress::getAllByName;
    }
}
