package com.coam.pdfvalidator.infrastructure.revocation;

import java.net.Inet6Address;
import java.net.InetAddress;
import java.net.URI;
import java.net.URISyntaxException;
import java.net.UnknownHostException;
import java.util.Arrays;

/**
 * SSRF guard for OCSP/CRL distribution point URLs extracted from a
 * certificate's AIA/CDP extensions: a hostile or misissued certificate
 * could point either at an internal service (e.g. {@code
 * http://169.254.169.254/} or {@code http://localhost:8080/actuator}), and
 * this server must never blindly follow it.
 *
 * <p><b>DNS-rebinding TOCTOU</b>: an earlier version of this guard validated
 * the hostname's resolved addresses, then let {@code java.net.http.HttpClient}
 * resolve the same hostname <em>again</em> at connect time -- a hostile
 * authoritative DNS server can legitimately answer those two lookups
 * differently (a public address for the check, a private one for the
 * actual connection), defeating the guard entirely. {@link #resolve} fixes
 * this by resolving the hostname <em>exactly once</em>, picking one
 * permitted address, and returning it bundled with the request URI as a
 * {@link ValidatedTarget}; {@link PinnedHttpClient} then connects a plain
 * socket to that exact {@link InetAddress}, never to the hostname again.
 *
 * <p>Only {@code http} URLs are accepted -- see {@link PinnedHttpClient}'s
 * Javadoc for why {@code https} is rejected outright rather than pinned.
 * Unless {@code allowPrivateAddresses} is {@code true} (test-only: a local
 * test HTTP server bound to {@code localhost}; production wiring always
 * passes {@code false}), every resolved candidate address is checked
 * against {@link #isPrivateOrReserved} and the first permitted one is used;
 * if none is permitted, the URL is rejected. Redirects are never followed
 * at all ({@link PinnedHttpClient} implements a minimal, non-redirecting
 * HTTP/1.1 client), so a redirect to a private address cannot bypass this
 * guard either.
 */
final class RevocationUrlGuard {

    private RevocationUrlGuard() {
    }

    /** A request URI together with the exact single resolved address {@link PinnedHttpClient} must connect to. */
    record ValidatedTarget(URI uri, InetAddress address) {
    }

    static ValidatedTarget resolve(String urlString, boolean allowPrivateAddresses, HostResolver resolver) {
        URI uri;
        try {
            uri = new URI(urlString);
        } catch (URISyntaxException e) {
            throw new RevocationUrlRejectedException("malformed URL");
        }

        String scheme = uri.getScheme();
        if (scheme == null || !scheme.equalsIgnoreCase("http")) {
            throw new RevocationUrlRejectedException(
                    "unsupported URL scheme (only http is supported for revocation checking)");
        }

        String host = uri.getHost();
        if (host == null) {
            throw new RevocationUrlRejectedException("URL has no host");
        }

        InetAddress[] addresses;
        try {
            addresses = resolver.resolve(host);
        } catch (UnknownHostException e) {
            throw new RevocationUrlRejectedException("host could not be resolved");
        }

        for (InetAddress candidate : addresses) {
            if (allowPrivateAddresses || !isPrivateOrReserved(candidate)) {
                return new ValidatedTarget(uri, candidate);
            }
        }
        throw new RevocationUrlRejectedException(
                "URL resolves only to private/loopback/reserved addresses, refusing to contact it");
    }

    /**
     * Covers loopback, wildcard/any-local, link-local (incl. the {@code
     * 169.254.169.254} cloud-metadata address), IPv4 RFC 1918 private
     * ranges, IPv6 unique-local ({@code fc00::/7}), IPv4 {@code 0.0.0.0/8},
     * CGNAT ({@code 100.64.0.0/10}), and multicast -- both directly and
     * through every IPv6 form that embeds an IPv4 address (see {@link
     * #embeddedIpv4}): the address is normalized to its embedded IPv4 address
     * first so it cannot slip past the IPv4-specific checks above. The NAT64
     * local-use prefix {@code 64:ff9b:1::/48} (RFC 8215) is rejected
     * wholesale. Teredo ({@code 2001::/32}) is not decoded: it does not
     * carry a routable target address for an HTTP client on this host.
     */
    private static boolean isPrivateOrReserved(InetAddress address) {
        if (address instanceof Inet6Address v6) {
            byte[] embedded = embeddedIpv4(v6.getAddress());
            if (embedded != null) {
                return isPrivateOrReserved(toIpv4(embedded));
            }
            if (isNat64LocalUse(v6.getAddress())) {
                return true;
            }
        }

        if (address.isLoopbackAddress() || address.isAnyLocalAddress()
                || address.isLinkLocalAddress() || address.isSiteLocalAddress()
                || address.isMulticastAddress()) {
            return true;
        }

        byte[] bytes = address.getAddress();
        if (bytes.length == 4) {
            int firstOctet = bytes[0] & 0xFF;
            int secondOctet = bytes[1] & 0xFF;
            if (firstOctet == 0) {
                return true; // 0.0.0.0/8
            }
            return firstOctet == 100 && secondOctet >= 64 && secondOctet <= 127; // 100.64.0.0/10 (CGNAT)
        }
        if (bytes.length == 16) {
            // Unique local addresses, fc00::/7: the top 7 bits of the first
            // byte are 1111110 (0xFC or 0xFD as the first byte).
            return (bytes[0] & 0xFE) == 0xFC;
        }
        return false;
    }

    /**
     * The IPv4 address embedded in an IPv6 address, or {@code null} when it
     * carries none: IPv4-mapped {@code ::ffff:a.b.c.d}, IPv4-compatible
     * (deprecated) {@code ::a.b.c.d}, the NAT64 well-known prefix {@code
     * 64:ff9b::/96} (RFC 6052) and 6to4 {@code 2002::/16} (RFC 3056, the
     * IPv4 address sits in bits 16-47).
     */
    private static byte[] embeddedIpv4(byte[] b) {
        boolean firstTenZero = true;
        for (int i = 0; i < 10; i++) {
            firstTenZero &= b[i] == 0;
        }
        if (firstTenZero && (b[10] & 0xFF) == 0xFF && (b[11] & 0xFF) == 0xFF) {
            return Arrays.copyOfRange(b, 12, 16); // ::ffff:0:0/96
        }
        boolean firstTwelveZero = firstTenZero && b[10] == 0 && b[11] == 0;
        if (firstTwelveZero) {
            return Arrays.copyOfRange(b, 12, 16); // ::/96 (also ::1 and ::, which map to 0.0.0.x)
        }
        if (b[0] == 0x00 && b[1] == 0x64 && (b[2] & 0xFF) == 0xFF && (b[3] & 0xFF) == 0x9B) {
            boolean restZero = true;
            for (int i = 4; i < 12; i++) {
                restZero &= b[i] == 0;
            }
            if (restZero) {
                return Arrays.copyOfRange(b, 12, 16); // 64:ff9b::/96
            }
        }
        if ((b[0] & 0xFF) == 0x20 && b[1] == 0x02) {
            return Arrays.copyOfRange(b, 2, 6); // 2002::/16
        }
        return null;
    }

    /** {@code 64:ff9b:1::/48}: NAT64 local-use translation prefix, private by definition. */
    private static boolean isNat64LocalUse(byte[] b) {
        return b[0] == 0x00 && b[1] == 0x64 && (b[2] & 0xFF) == 0xFF && (b[3] & 0xFF) == 0x9B
                && b[4] == 0x00 && b[5] == 0x01;
    }

    private static InetAddress toIpv4(byte[] octets) {
        try {
            return InetAddress.getByAddress(octets);
        } catch (UnknownHostException e) {
            // Unreachable: a 4-byte address is always a valid raw address.
            throw new IllegalStateException(e);
        }
    }
}
